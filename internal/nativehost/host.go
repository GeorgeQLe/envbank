package nativehost

import (
	"errors"
	"io"
	"time"

	"github.com/GeorgeQLe/envbank/internal/browser"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/password"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

const ProtocolVersion = 1

type Request struct {
	Version          int             `json:"version"`
	ID               string          `json:"id"`
	Action           string          `json:"action"`
	Name             string          `json:"name,omitempty"`
	Origin           string          `json:"origin,omitempty"`
	Policy           password.Policy `json:"policy,omitempty"`
	ExpectedRevision int64           `json:"expected_revision,omitempty"`
}

type Response struct {
	Version int    `json:"version"`
	ID      string `json:"id,omitempty"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Result  any    `json:"result,omitempty"`
}

type ListedRecord struct {
	Name            string `json:"name"`
	Allowed         bool   `json:"allowed"`
	Revision        int64  `json:"revision"`
	RotatedAt       string `json:"rotated_at"`
	RotateEveryDays int    `json:"rotate_every_days"`
	Due             bool   `json:"due"`
}

type Keychain interface {
	Get(service, account, prompt string) ([]byte, error)
}

type Host struct {
	ConfigPath string
	Keychain   Keychain
	Idle       time.Duration
	Now        func() time.Time

	api      *client.API
	vaultKey []byte
}

func New(configPath string, store Keychain) *Host {
	return &Host{ConfigPath: configPath, Keychain: store, Idle: 10 * time.Minute, Now: time.Now}
}

func (h *Host) account(cfg *client.Config) string { return cfg.VaultID + ":" + cfg.DeviceID }

func (h *Host) unlock() error {
	if h.api != nil {
		return nil
	}
	cfg, err := client.LoadConfig(h.ConfigPath)
	if err != nil {
		return errors.New("native host configuration is unavailable")
	}
	passphrase, err := h.Keychain.Get(keychain.Service, h.account(cfg), "Unlock EnvBank for this browser session")
	if err != nil {
		return errors.New("EnvBank Keychain authentication was cancelled or failed")
	}
	defer zero(passphrase)
	secrets, err := cfg.Unlock(passphrase)
	if err != nil {
		return errors.New("stored credentials could not unlock EnvBank")
	}
	vaultKey, err := decodeVaultKey(secrets)
	if err != nil {
		return err
	}
	api := client.NewAPI(cfg.Server)
	api.Config, api.Secrets = cfg, secrets
	h.api, h.vaultKey = api, vaultKey
	return nil
}

func decodeVaultKey(secrets secure.DeviceSecrets) ([]byte, error) {
	key, err := secure.Decode(secrets.VaultKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("EnvBank device has no usable vault key")
	}
	return key, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func (h *Host) clear() {
	zero(h.vaultKey)
	h.vaultKey, h.api = nil, nil
}

func (h *Host) loadRecords() ([]protocol.SecretRecord, error) {
	if err := h.unlock(); err != nil {
		return nil, err
	}
	encrypted, err := h.api.ListRecords()
	if err != nil {
		return nil, errors.New("could not refresh EnvBank records")
	}
	records, err := client.DecryptRecords(h.api.Config.VaultID, h.vaultKey, encrypted)
	if err != nil {
		return nil, errors.New("could not decrypt EnvBank records")
	}
	return records, nil
}

func (h *Host) Handle(request Request) (Response, bool) {
	response := Response{Version: ProtocolVersion, ID: request.ID}
	if request.Version != ProtocolVersion || request.ID == "" || len(request.ID) > 128 {
		response.Error = "unsupported protocol request"
		return response, false
	}
	if request.Action == "lock" {
		h.clear()
		response.OK = true
		return response, true
	}
	origin, err := browser.NormalizeOrigin(request.Origin)
	if err != nil {
		response.Error = "origin is not eligible for browser filling"
		return response, false
	}
	switch request.Action {
	case "list_for_origin":
		records, err := h.loadRecords()
		if err != nil {
			response.Error = err.Error()
			return response, false
		}
		listed := make([]ListedRecord, 0, len(records))
		now := h.Now()
		for _, record := range records {
			due := false
			if record.RotateEveryDays > 0 {
				if rotated, parseErr := time.Parse(time.RFC3339, record.RotatedAt); parseErr == nil {
					due = !rotated.Add(time.Duration(record.RotateEveryDays) * 24 * time.Hour).After(now)
				}
			}
			listed = append(listed, ListedRecord{Name: record.Name, Allowed: browser.ContainsOrigin(record.AllowedOrigins, origin), Revision: record.Revision, RotatedAt: record.RotatedAt, RotateEveryDays: record.RotateEveryDays, Due: due})
		}
		response.OK, response.Result = true, listed
	case "allow_origin", "deny_origin":
		if request.Name == "" {
			response.Error = "variable name is required"
			break
		}
		if err := h.changePolicy(request.Name, origin, request.Action == "allow_origin"); err != nil {
			response.Error = err.Error()
			break
		}
		response.OK, response.Result = true, map[string]any{"name": request.Name, "origin": origin}
	case "generate_password":
		if !validVariableName(request.Name) {
			response.Error = "a valid variable name is required"
			break
		}
		if err := request.Policy.Validate(); err != nil {
			response.Error = err.Error()
			break
		}
		result, err := h.generatePassword(request.Name, origin, request.Policy, request.ExpectedRevision)
		if err != nil {
			response.Error = err.Error()
			break
		}
		response.OK, response.Result = true, result
	case "get_for_fill":
		if request.Name == "" {
			response.Error = "variable name is required"
			break
		}
		records, err := h.loadRecords()
		if err != nil {
			response.Error = err.Error()
			break
		}
		for _, record := range records {
			if record.Name == request.Name {
				if !browser.ContainsOrigin(record.AllowedOrigins, origin) {
					response.Error = "variable is not allowed on this origin"
					return response, false
				}
				response.OK, response.Result = true, map[string]string{"value": record.Value}
				return response, false
			}
		}
		response.Error = "variable was not found"
	default:
		response.Error = "unknown native action"
	}
	return response, false
}

func validVariableName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
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

func (h *Host) generatePassword(name, origin string, policy password.Policy, expected int64) (ListedRecord, error) {
	records, err := h.loadRecords()
	if err != nil {
		return ListedRecord{}, err
	}
	nowFunction := h.Now
	if nowFunction == nil {
		nowFunction = time.Now
	}
	now := nowFunction().UTC().Format(time.RFC3339)
	record := protocol.SecretRecord{Name: name, CreatedAt: now, RotatedAt: now, Revision: 1, AllowedOrigins: []string{origin}}
	found := false
	for _, existing := range records {
		if existing.Name != name {
			continue
		}
		found = true
		if expected == 0 || expected != existing.Revision {
			return ListedRecord{}, errors.New("record changed or replacement was not confirmed; refresh and try again")
		}
		record.CreatedAt = existing.CreatedAt
		record.RotateEveryDays = existing.RotateEveryDays
		record.AllowedOrigins, _ = browser.AddOrigin(existing.AllowedOrigins, origin)
		record.Revision = existing.Revision + 1
		break
	}
	if !found && expected != 0 {
		return ListedRecord{}, errors.New("record changed or replacement was not confirmed; refresh and try again")
	}
	record.Value, err = password.Generate(policy)
	if err != nil {
		return ListedRecord{}, errors.New("password generation failed")
	}
	id, blob, err := client.EncryptRecord(h.api.Config.VaultID, h.vaultKey, record)
	if err != nil {
		return ListedRecord{}, errors.New("could not encrypt generated password")
	}
	if _, err := h.api.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
		return ListedRecord{}, errors.New("record changed concurrently; refresh and try again")
	}
	return ListedRecord{Name: record.Name, Allowed: true, Revision: record.Revision, RotatedAt: record.RotatedAt, RotateEveryDays: record.RotateEveryDays}, nil
}

func (h *Host) changePolicy(name, origin string, allow bool) error {
	records, err := h.loadRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Name != name {
			continue
		}
		var changed bool
		if allow {
			record.AllowedOrigins, changed = browser.AddOrigin(record.AllowedOrigins, origin)
		} else {
			record.AllowedOrigins, changed = browser.RemoveOrigin(record.AllowedOrigins, origin)
		}
		if !changed {
			return nil
		}
		expected := record.Revision
		record.Revision++
		id, blob, err := client.EncryptRecord(h.api.Config.VaultID, h.vaultKey, record)
		if err != nil {
			return errors.New("could not encrypt browser policy update")
		}
		if _, err := h.api.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
			return errors.New("browser policy changed concurrently; refresh and try again")
		}
		return nil
	}
	return errors.New("variable was not found")
}

func (h *Host) Run(input io.Reader, output io.Writer) error {
	type incoming struct {
		request Request
		err     error
	}
	requests := make(chan incoming, 1)
	go func() {
		for {
			var request Request
			err := ReadMessage(input, &request)
			requests <- incoming{request, err}
			if err != nil {
				return
			}
		}
	}()
	idle := h.Idle
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	timer := time.NewTimer(idle)
	defer timer.Stop()
	defer h.clear()
	for {
		select {
		case <-timer.C:
			return nil
		case item := <-requests:
			if item.err != nil {
				if errors.Is(item.err, io.EOF) || errors.Is(item.err, io.ErrUnexpectedEOF) {
					return nil
				}
				return item.err
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idle)
			response, terminate := h.Handle(item.request)
			if err := WriteMessage(output, response); err != nil {
				return err
			}
			if terminate {
				return nil
			}
		}
	}
}
