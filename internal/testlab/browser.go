package testlab

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
)

// BrowserRecipe is the signed protocol-v2 capture authorization. It binds a
// capture to one exact top-frame origin, route, selector, record and expiry.
type BrowserRecipe struct {
	Version   int    `json:"version"`
	Origin    string `json:"origin"`
	Route     string `json:"route"`
	Selector  string `json:"selector"`
	Record    string `json:"record"`
	Prefix    string `json:"prefix"`
	ExpiresAt string `json:"expires_at"`
	Signature []byte `json:"signature"`
}

func (recipe BrowserRecipe) signingBytes() []byte {
	recipe.Signature = nil
	raw, _ := json.Marshal(recipe)
	return raw
}
func (recipe *BrowserRecipe) Sign(private ed25519.PrivateKey) {
	recipe.Signature = ed25519.Sign(private, recipe.signingBytes())
}

type BrowserCapture struct {
	Origin          string
	Route           string
	SelectorMatches int
	Masked          bool
	Navigated       bool
	InFrame         bool
	Cancelled       bool
	DOMStable       bool
}
type BrowserReceipt struct {
	Acknowledged bool   `json:"acknowledged"`
	Mode         string `json:"mode"`
	Record       string `json:"record"`
	Revision     int64  `json:"revision"`
}

type BrowserSimulator struct {
	PublicKey ed25519.PublicKey
	Now       func() time.Time
	mu        sync.Mutex
	used      map[string]bool
}

// Capture deterministically reveals only inside the simulator, remasks before
// returning, and hands the value to the host through SecretSink. The receipt
// contains acknowledgement metadata only.
func (browser *BrowserSimulator) Capture(ctx context.Context, recipe BrowserRecipe, page BrowserCapture, sink *lifecycle.SecretSink) (BrowserReceipt, error) {
	if browser == nil || sink == nil || recipe.Version != 2 || len(browser.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(browser.PublicKey, recipe.signingBytes(), recipe.Signature) {
		return BrowserReceipt{}, errors.New("browser capture rejected")
	}
	now := time.Now().UTC()
	if browser.Now != nil {
		now = browser.Now().UTC()
	}
	expires, err := time.Parse(time.RFC3339, recipe.ExpiresAt)
	if err != nil || !now.Before(expires) || page.Origin != recipe.Origin || page.Route != recipe.Route || page.SelectorMatches != 1 || !page.Masked || page.Navigated || page.InFrame || page.Cancelled || !page.DOMStable {
		return BrowserReceipt{}, errors.New("browser capture rejected")
	}
	browser.mu.Lock()
	if browser.used == nil {
		browser.used = map[string]bool{}
	}
	identity := recipe.Origin + "\x00" + recipe.Route + "\x00" + recipe.Record
	if browser.used[identity] {
		browser.mu.Unlock()
		return BrowserReceipt{}, errors.New("browser capture rejected")
	}
	browser.used[identity] = true
	browser.mu.Unlock()
	secret, err := synthetic("clerk")
	if err != nil {
		return BrowserReceipt{}, errors.New("browser capture rejected")
	}
	defer wipe(secret)
	if recipe.Prefix != "" && !strings.HasPrefix(string(secret), recipe.Prefix) {
		return BrowserReceipt{}, errors.New("browser capture rejected")
	}
	receipt, err := sink.StoreBytes(ctx, secret)
	if err != nil {
		return BrowserReceipt{}, errors.New("browser capture rejected")
	}
	return BrowserReceipt{Acknowledged: true, Mode: "simulated-interactive", Record: receipt.Record, Revision: receipt.Revision}, nil
}
