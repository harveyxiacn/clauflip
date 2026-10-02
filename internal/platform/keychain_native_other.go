//go:build !darwin || !cgo

package platform

import "errors"

func nativeKeychainWrite(string, string, string, []byte) error {
	return errors.New("native macOS Keychain writes require a Darwin build with CGO enabled")
}
