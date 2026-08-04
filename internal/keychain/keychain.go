package keychain

import "errors"

const Service = "com.envbank.native"

var ErrNotFound = errors.New("keychain item not found")

type Store interface {
	Put(service, account string, secret []byte) error
	Get(service, account, prompt string) ([]byte, error)
	Delete(service, account string) error
}

type SystemStore struct{}
