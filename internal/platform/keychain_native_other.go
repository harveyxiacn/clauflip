//go:build !darwin || !cgo

package platform

import "errors"

func nativeKeychainWrite(string, string, string, []byte) error {
	return errors.New("native macOS Keychain writes require a Darwin build with CGO enabled")
}

func nativeKeychainSnapshot(string, string, string) ([]byte, error) {
	return nil, errors.New("native Keychain metadata requires a Darwin CGO build")
}
func nativeKeychainRestore(string, string, string, []byte) error {
	return errors.New("native Keychain metadata requires a Darwin CGO build")
}
func nativeKeychainRead(string, string, string) ([]byte, error) {
	return nil, errors.New("native Keychain reads require a Darwin CGO build")
}
