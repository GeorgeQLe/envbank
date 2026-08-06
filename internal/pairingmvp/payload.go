package pairingmvp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	PayloadPrefix  = "envbank-pairing:v1:"
	MaxPayloadSize = 8 << 10
)

var (
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9_-]{24}$`)
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Payload is deliberately only a locator and public-key fingerprint. It is
// not an invitation credential and grants no access to a vault.
type Payload struct {
	Server      string `json:"server"`
	VaultID     string `json:"vault_id"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
}

func EncodePayload(payload Payload) (string, error) {
	if err := validatePayload(payload); err != nil {
		return "", err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encoded := PayloadPrefix + base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > MaxPayloadSize {
		return "", errors.New("pairing payload is too large")
	}
	return encoded, nil
}

func DecodePayload(input string) (Payload, error) {
	var payload Payload
	if len(input) > MaxPayloadSize {
		return payload, errors.New("pairing payload is too large")
	}
	if !strings.HasPrefix(input, PayloadPrefix) {
		if strings.HasPrefix(input, "envbank-pairing:") {
			return payload, errors.New("unsupported pairing payload version")
		}
		return payload, errors.New("invalid pairing payload prefix")
	}
	encoded := strings.TrimPrefix(input, PayloadPrefix)
	if encoded == "" || strings.Contains(encoded, "=") {
		return payload, errors.New("invalid pairing payload encoding")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return payload, errors.New("invalid pairing payload encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return Payload{}, errors.New("invalid pairing payload JSON")
	}
	if decoder.Decode(&struct{}{}) == nil {
		return Payload{}, errors.New("invalid pairing payload JSON")
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Payload{}, errors.New("pairing payload is not canonical")
	}
	if err := validatePayload(payload); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

func validatePayload(payload Payload) error {
	if err := validateServer(payload.Server); err != nil {
		return err
	}
	if !idPattern.MatchString(payload.VaultID) || !idPattern.MatchString(payload.DeviceID) {
		return errors.New("invalid vault or device ID")
	}
	if !fingerprintPattern.MatchString(payload.Fingerprint) {
		return errors.New("invalid device fingerprint")
	}
	created, err := time.Parse(time.RFC3339, payload.CreatedAt)
	if err != nil || created.Format(time.RFC3339) != payload.CreatedAt {
		return errors.New("invalid pairing timestamp")
	}
	return nil
}

func validateServer(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return errors.New("invalid pairing server URL")
	}
	if u.Path == "/" {
		return errors.New("pairing server URL must not contain a path")
	}
	hostname := u.Hostname()
	if hostname == "" || strings.ToLower(hostname) != hostname {
		return errors.New("pairing server URL is not normalized")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(hostname)
		if hostname != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("HTTP pairing servers must be loopback")
		}
	default:
		return errors.New("pairing server must use HTTPS or loopback HTTP")
	}
	if u.String() != value {
		return fmt.Errorf("pairing server URL is not normalized")
	}
	return nil
}
