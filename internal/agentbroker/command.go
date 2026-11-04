package agentbroker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Command is a fully resolved, owner-reviewable command.
type Command struct {
	Executable string   // absolute, symlinks resolved
	Args       []string // argv[1:]
	Dir        string   // absolute, symlinks resolved
	Secrets    []string // sorted, unique
	// ExecutableSHA256 binds an approval to the file's content: an edited
	// script or swapped binary needs a fresh approval.
	ExecutableSHA256 string
	// Interpreter is the shebang interpreter (resolved) and its hash, if any.
	Interpreter       string
	InterpreterSHA256 string
	// Files binds every argument that names an existing regular file (for
	// example `python3 deploy.py`) to its content hash.
	Files    []BoundFile
	Warnings []string
	// AlwaysAllowed is false when the command runs project code or lives in
	// the working directory: those are approved once at a time.
	AlwaysAllowed bool
}

// BoundFile is a file argument whose content is part of the approval.
type BoundFile struct {
	Path   string
	SHA256 string
}

// errRefused carries only a fixed reason chosen here; never caller text.
type errRefused struct{ reason string }

func (e errRefused) Error() string { return e.reason }

// RefusalReason returns the fixed reason for a refused command, if any.
func RefusalReason(err error) (string, bool) {
	var r errRefused
	if errors.As(err, &r) {
		return r.reason, true
	}
	return "", false
}

var shells = set("sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "pwsh", "powershell")

// Inline-code flags per interpreter: such a command is arbitrary code chosen by
// the agent at request time, so there is nothing meaningful to approve.
// Single letters are matched anywhere in a short-flag cluster (`-Ic`, `-we`).
var inlineFlags = map[string][]string{
	"python": {"-c"}, "python3": {"-c"}, "python2": {"-c"}, "pypy": {"-c"}, "pypy3": {"-c"},
	"node": {"-e", "--eval", "-p", "--print", "-r", "--require", "--import", "--loader"}, "deno": {"eval"}, "bun": {"-e", "--eval", "-p", "--print", "-r", "--preload"},
	"ruby": {"-e", "-r"}, "perl": {"-e", "-E", "-M", "-m"}, "php": {"-r", "-B", "-R", "-E", "-F"}, "osascript": {"-e"}, "lua": {"-e", "-l"},
	"awk": {""}, "gawk": {""}, "mawk": {""}, "nawk": {""}, "tclsh": {""}, "Rscript": {"-e"}, "R": {"-e"},
	"git": {"-c", "--config-env"}, "find": {"-exec", "-execdir", "-ok", "-okdir", "-fprintf"},
}

// Executables refused outright: they print the environment, run an arbitrary
// next command with it, or escalate privilege.
var refused = set("env", "printenv", "export", "declare", "sudo", "doas", "su", "xargs", "eval", "exec", "command", "nohup", "script", "strace", "dtruss", "lldb", "gdb",
	// Wrappers that run whatever follows them: the check would only see the wrapper.
	"timeout", "gtimeout", "nice", "time", "stdbuf", "caffeinate", "arch", "busybox", "toybox", "chroot", "unbuffer", "watch", "ionice", "taskset",
	"flock", "setsid", "sg", "runuser", "ssh", "launchctl", "open", "sandbox-exec", "parallel", "entr",
	// Editors and filters that execute or print arbitrary code/environment from arguments.
	"vim", "vi", "nvim", "ex", "view", "emacs", "nano", "jq", "yq", "gojq", "sed", "gsed")

// Executables that run code from the working directory an agent may edit.
var runsProjectCode = set("npm", "npx", "pnpm", "yarn", "bun", "deno", "node", "python", "python3", "ruby", "perl", "php", "make", "just", "cargo", "go", "gradle", "mvn", "bundle", "rake", "uv", "poetry", "pip", "pip3", "tsx", "ts-node", "git", "lua", "Rscript")

// displayBytes bounds what the owner must read: anything longer is refused
// rather than shown truncated.
const displayBytes = 8 << 10

func set(values ...string) map[string]bool {
	m := map[string]bool{}
	for _, v := range values {
		m[v] = true
	}
	return m
}

// ResolveCommand validates and resolves a run request. `path` is the broker's
// own PATH (never the agent's).
func ResolveCommand(argv []string, dir string, secrets []string, path string) (Command, error) {
	if len(argv) == 0 || len(argv) > Limits.Argv || len(secrets) == 0 || len(secrets) > Limits.Secrets {
		return Command{}, errRefused{"argv and at least one secret are required"}
	}
	total := 0
	for _, a := range argv {
		total += len(a)
		if len(a) > Limits.ArgBytes || strings.ContainsRune(a, 0) {
			return Command{}, errRefused{"argument too long or contains NUL"}
		}
	}
	if total+len(dir) > displayBytes {
		return Command{}, errRefused{"command too long to show the owner in full"}
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return Command{}, errRefused{"an absolute working directory is required"}
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return Command{}, errRefused{"working directory not found"}
	}
	if info, err := os.Stat(realDir); err != nil || !info.IsDir() {
		return Command{}, errRefused{"working directory not found"}
	}
	names := append([]string(nil), secrets...)
	sort.Strings(names)
	for i, n := range names {
		if !ValidName(n) || (i > 0 && names[i-1] == n) {
			return Command{}, errRefused{"secret names must be valid and unique"}
		}
	}
	exe := argv[0]
	switch {
	case filepath.IsAbs(exe):
	case strings.ContainsRune(exe, os.PathSeparator):
		exe = filepath.Join(realDir, exe)
	default:
		found, err := lookPath(exe, path)
		if err != nil {
			return Command{}, errRefused{"executable not found on the broker PATH"}
		}
		exe = found
	}
	realExe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return Command{}, errRefused{"executable not found"}
	}
	info, err := os.Stat(realExe)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return Command{}, errRefused{"executable is not a regular executable file"}
	}
	base := filepath.Base(realExe)
	named := filepath.Base(argv[0])
	cmd := Command{Executable: realExe, Args: append([]string(nil), argv[1:]...), Dir: realDir, Secrets: names}
	for _, b := range []string{base, named, versionless(base), versionless(named)} {
		if refused[b] {
			return Command{}, errRefused{"this executable prints or forwards the environment and cannot be approved"}
		}
		if shells[b] && hasShortFlag(cmd.Args, 'c') {
			return Command{}, errRefused{"inline shell code (-c) cannot be approved; put it in a script file"}
		}
		for _, f := range inlineFlags[b] {
			if f == "" || containsArg(cmd.Args, f) {
				return Command{}, errRefused{"inline interpreter code cannot be approved; put it in a script file"}
			}
		}
	}
	projectCode := runsProjectCode[versionless(base)] || runsProjectCode[versionless(named)] || shells[base] || shells[named]
	sum, err := fileSHA256(realExe)
	if err != nil {
		return Command{}, errRefused{"executable could not be read"}
	}
	cmd.ExecutableSHA256 = sum
	if interp, ok := shebang(realExe); ok {
		resolved, err := resolveInterpreter(interp, path)
		if err != nil {
			return Command{}, err
		}
		cmd.Interpreter = resolved
		if cmd.InterpreterSHA256, err = fileSHA256(resolved); err != nil {
			return Command{}, errRefused{"script interpreter could not be read"}
		}
		projectCode = true
	}
	// Bind every file argument (scripts, configs) to its content.
	for _, a := range cmd.Args {
		candidate := a
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(realDir, candidate)
		}
		real, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		st, err := os.Stat(real)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if len(cmd.Files) >= 32 || st.Size() > 256<<20 {
			return Command{}, errRefused{"too many or too large file arguments to bind to the approval"}
		}
		h, err := fileSHA256(real)
		if err != nil {
			return Command{}, errRefused{"a file argument could not be read"}
		}
		cmd.Files = append(cmd.Files, BoundFile{Path: real, SHA256: h})
		if under(real, realDir) {
			projectCode = true
		}
	}
	if projectCode {
		cmd.Warnings = append(cmd.Warnings, "runs scripts or project code an agent may have edited; that code receives the secret values")
	}
	inDir := under(realExe, realDir)
	if inDir {
		cmd.Warnings = append(cmd.Warnings, "the executable is inside the working directory, which an agent may modify")
	}
	cmd.AlwaysAllowed = !projectCode && !inDir
	return cmd, nil
}

// Verify re-resolves the request and requires the identical approval key, so a
// file swapped or edited after approval is refused (a residual race remains
// between this check and exec).
func Verify(approved Command, argv []string, dir string, secrets []string, path string) error {
	now, err := ResolveCommand(argv, dir, secrets, path)
	if err != nil {
		return err
	}
	if now.ApprovalKey() != approved.ApprovalKey() {
		return errRefused{"the command or a file it uses changed after approval"}
	}
	return nil
}

func shebang(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	head := make([]byte, 256)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if !strings.HasPrefix(string(head), "#!") {
		return "", false
	}
	line := string(head[2:])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line), true
}

// resolveInterpreter applies the same refusals to a shebang interpreter.
func resolveInterpreter(line, path string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", errRefused{"script has an empty interpreter line"}
	}
	interp := fields[0]
	rest := fields[1:]
	if filepath.Base(interp) == "env" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return "", errRefused{"env shebang with options cannot be approved"}
		}
		found, err := lookPath(rest[0], path)
		if err != nil {
			return "", errRefused{"script interpreter not found on the broker PATH"}
		}
		interp, rest = found, rest[1:]
	}
	real, err := filepath.EvalSymlinks(interp)
	if err != nil {
		return "", errRefused{"script interpreter not found"}
	}
	base := versionless(filepath.Base(real))
	if refused[base] || (shells[base] && hasShortFlag(rest, 'c')) {
		return "", errRefused{"script interpreter cannot be approved"}
	}
	for _, f := range inlineFlags[base] {
		if f == "" || containsArg(rest, f) {
			return "", errRefused{"script interpreter flags cannot be approved"}
		}
	}
	return real, nil
}

// ApprovalKey identifies an exact command for "always" approvals.
func (c Command) ApprovalKey() string {
	raw, _ := json.Marshal([]any{c.Executable, c.ExecutableSHA256, c.Interpreter, c.InterpreterSHA256, c.Files, c.Args, c.Dir, c.Secrets})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func lookPath(name, path string) (string, error) {
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue // never resolve through "." or relative PATH entries
		}
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func versionless(name string) string {
	return strings.TrimRight(name, "0123456789.")
}

func hasShortFlag(args []string, flag byte) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.IndexByte(a[1:], flag) >= 0 {
			return true
		}
		if a == "--command" {
			return true
		}
	}
	return false
}

// containsArg matches a long flag exactly or as `--flag=…`, a bare word
// exactly, and a single-letter flag anywhere in a short-flag cluster.
func containsArg(args []string, flag string) bool {
	single := len(flag) == 2 && flag[0] == '-' && flag[1] != '-'
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
		if single && len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.IndexByte(a[1:], flag[1]) >= 0 {
			return true
		}
		if !single && strings.HasPrefix(flag, "--") && strings.HasPrefix(a, flag) {
			return true
		}
	}
	return false
}

func under(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<30)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidName matches EnvBank's environment-variable name rule.
func ValidName(name string) bool {
	if name == "" || len(name) > 128 || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
