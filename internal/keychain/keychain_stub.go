//go:build !darwin || !cgo

package keychain

import "errors"

func (SystemStore) Put(service, account string, secret []byte) error {
	return errors.New("macOS Keychain support requires a cgo-enabled macOS build")
}

func (SystemStore) Get(service, account, prompt string) ([]byte, error) {
	return nil, errors.New("macOS Keychain support requires a cgo-enabled macOS build")
}

func (SystemStore) Delete(service, account string) error {
	return errors.New("macOS Keychain support requires a cgo-enabled macOS build")
}
