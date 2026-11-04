// Package ownerapprovaltest provides a deterministic SOFTWARE P-256 signer for
// tests only. It proves canonical signing/verification logic, never hardware
// residency or user presence. Production code must not import this package;
// TestNoProductionImport enforces that across the module.
package ownerapprovaltest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

type Signer struct {
	private *ecdsa.PrivateKey
	public  []byte
	Calls   int
	Reasons []string
	// HighS forces the non-canonical (s > n/2) form so callers' normalization
	// is exercised.
	HighS bool
	Fail  error
}

// New derives a fixed key from label so test fixtures are reproducible.
func New(label string) *Signer {
	seed := sha256.Sum256([]byte("envbank.ownerapprovaltest.v1\x00" + label))
	private, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
	if err != nil {
		panic("ownerapprovaltest: derived scalar invalid; choose another label")
	}
	public, err := private.PublicKey.Bytes()
	if err != nil {
		panic("ownerapprovaltest: public key encoding failed")
	}
	return &Signer{private: private, public: public}
}

func (s *Signer) PublicKey() []byte { return append([]byte(nil), s.public...) }

func (s *Signer) Sign(ctx context.Context, message []byte, reason string) ([]byte, error) {
	s.Calls++
	s.Reasons = append(s.Reasons, reason)
	if s.Fail != nil {
		return nil, s.Fail
	}
	if ctx.Err() != nil {
		return nil, errors.New("cancelled")
	}
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, s.private, digest[:])
	if err != nil || !s.HighS {
		return signature, err
	}
	var parsed struct{ R, S *big.Int }
	if _, err = asn1.Unmarshal(signature, &parsed); err != nil {
		return nil, err
	}
	if parsed.S.Cmp(new(big.Int).Rsh(elliptic.P256().Params().N, 1)) > 0 {
		return signature, nil
	}
	return FlipS(signature)
}

// FlipS returns the other valid ECDSA encoding (s -> n-s) of a signature.
func FlipS(der []byte) ([]byte, error) {
	var signature struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &signature); err != nil {
		return nil, err
	}
	signature.S = new(big.Int).Sub(elliptic.P256().Params().N, signature.S)
	return asn1.Marshal(signature)
}
