package agentbroker

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ReadHidden turns terminal echo OFF before printing the prompt, then reads
// one line and restores the terminal. (term.ReadPassword prints the prompt
// first and disables echo afterwards, so input typed in that window would be
// echoed.) Ctrl-C still interrupts (ISIG stays on).
func ReadHidden(in *os.File, out io.Writer, prompt string) ([]byte, error) {
	fd := int(in.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	hidden := *old
	hidden.Lflag &^= unix.ECHO | unix.ECHONL
	hidden.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &hidden); err != nil {
		return nil, err
	}
	defer unix.IoctlSetTermios(fd, ioctlSetTermios, old)
	fmt.Fprint(out, prompt)
	var line []byte
	var one [1]byte
	for len(line) <= 4096 {
		n, err := in.Read(one[:])
		if err != nil {
			wipe(line)
			return nil, err
		}
		if n == 0 {
			continue
		}
		if one[0] == '\n' || one[0] == '\r' {
			return line, nil
		}
		line = append(line, one[0])
	}
	wipe(line)
	return nil, errors.New("input too long")
}
