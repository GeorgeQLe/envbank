// Package password generates random-character passwords without modulo bias.
package password

import (
	"crypto/rand"
	"errors"
	"io"
)

const (
	DefaultLength = 24
	MinLength     = 8
	MaxLength     = 256
	Lowercase     = "abcdefghijklmnopqrstuvwxyz"
	Uppercase     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits        = "0123456789"
	Symbols       = "!@#$%^&*()-_=+"
)

type Policy struct {
	Length    int  `json:"length"`
	Lowercase bool `json:"lowercase"`
	Uppercase bool `json:"uppercase"`
	Digits    bool `json:"digits"`
	Symbols   bool `json:"symbols"`
}

func DefaultPolicy() Policy {
	return Policy{Length: DefaultLength, Lowercase: true, Uppercase: true, Digits: true, Symbols: true}
}

func (p Policy) Validate() error {
	if p.Length < MinLength || p.Length > MaxLength {
		return errors.New("password length must be between 8 and 256")
	}
	if !p.Lowercase && !p.Uppercase && !p.Digits && !p.Symbols {
		return errors.New("at least one password character class is required")
	}
	return nil
}

func Generate(policy Policy) (string, error) { return generate(rand.Reader, policy) }

func generate(reader io.Reader, policy Policy) (string, error) {
	if err := policy.Validate(); err != nil {
		return "", err
	}
	classes := make([]string, 0, 4)
	if policy.Lowercase {
		classes = append(classes, Lowercase)
	}
	if policy.Uppercase {
		classes = append(classes, Uppercase)
	}
	if policy.Digits {
		classes = append(classes, Digits)
	}
	if policy.Symbols {
		classes = append(classes, Symbols)
	}
	all := ""
	result := make([]byte, 0, policy.Length)
	for _, class := range classes {
		all += class
		index, err := randomIndex(reader, len(class))
		if err != nil {
			return "", err
		}
		result = append(result, class[index])
	}
	for len(result) < policy.Length {
		index, err := randomIndex(reader, len(all))
		if err != nil {
			return "", err
		}
		result = append(result, all[index])
	}
	for i := len(result) - 1; i > 0; i-- {
		index, err := randomIndex(reader, i+1)
		if err != nil {
			return "", err
		}
		result[i], result[index] = result[index], result[i]
	}
	return string(result), nil
}

func randomIndex(reader io.Reader, size int) (int, error) {
	limit := 256 - 256%size
	var sample [1]byte
	for {
		if _, err := io.ReadFull(reader, sample[:]); err != nil {
			return 0, err
		}
		if int(sample[0]) < limit {
			return int(sample[0]) % size, nil
		}
	}
}
