package platform

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Contains access metadata and payload hashes, never OAuth or integration tokens.
type keychainACLJournal struct {
	Version    int    `json:"version"`
	Service    string `json:"service"`
	Account    string `json:"account"`
	Path       string `json:"path"`
	BeforeHash string `json:"beforeHash"`
	AfterHash  string `json:"afterHash"`
	Partitions []byte `json:"partitions"`
}

type keychainACLIO struct {
	snapshot     func() ([]byte, error)
	read         func() ([]byte, error)
	restore      func([]byte) error
	securityRead func() ([]byte, error)
	write        func([]byte) error
}

func (s *keychainStore) aclIO() keychainACLIO {
	if s.testACL != nil {
		return *s.testACL
	}
	return keychainACLIO{
		snapshot: func() ([]byte, error) {
			return nativeKeychainSnapshot(s.p.KeychainService, s.p.KeychainAccount, s.testKeychain)
		},
		read: func() ([]byte, error) {
			return nativeKeychainRead(s.p.KeychainService, s.p.KeychainAccount, s.testKeychain)
		},
		restore: func(b []byte) error {
			return nativeKeychainRestore(s.p.KeychainService, s.p.KeychainAccount, s.testKeychain, b)
		},
		securityRead: s.keychainRead,
		write: func(b []byte) error {
			return nativeKeychainWrite(s.p.KeychainService, s.p.KeychainAccount, s.testKeychain, b)
		},
	}
}

func payloadHash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func (s *keychainStore) aclPath() string {
	return filepath.Join(s.p.StateDir, "pending-keychain-acl.json")
}

func (s *keychainStore) beginACLUpdate(after []byte) error {
	if s.p.StateDir == "" {
		return errors.New("private state directory is required for Keychain ACL recovery")
	}
	if err := s.recoverPendingACL(); err != nil {
		return err
	}
	if err := EnsurePrivateDir(s.p.StateDir); err != nil {
		return err
	}
	ops := s.aclIO()
	partitions, err := ops.snapshot()
	if err != nil {
		return err
	}
	if len(partitions) == 0 {
		return errors.New("empty Keychain ACL snapshot")
	}
	before, err := ops.read()
	if err != nil {
		return err
	}
	j := keychainACLJournal{Version: 1, Service: s.p.KeychainService, Account: s.p.KeychainAccount, Path: s.testKeychain, BeforeHash: payloadHash(before), AfterHash: payloadHash(after), Partitions: partitions}
	b, err := json.Marshal(j)
	if err != nil {
		return errors.New("cannot encode Keychain ACL recovery")
	}
	if len(b)+1 > 4<<20 {
		return errors.New("Keychain ACL recovery metadata is too large; credentials were not updated")
	}
	if err := AtomicWrite(s.aclPath(), append(b, '\n'), 0600); err != nil {
		return errors.New("cannot save durable Keychain ACL recovery; credentials were not updated")
	}
	return nil
}

func (s *keychainStore) recoverPendingACL() error {
	if s.p.StateDir == "" {
		return nil
	} // Read-only stores need no state directory until a write.
	path := s.aclPath()
	if err := checkPath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot inspect Keychain ACL recovery")
	}
	invalid := errors.New("invalid Keychain ACL recovery; no access permissions changed")
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return invalid
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return errors.New("cannot read Keychain ACL recovery")
	}
	// Reject duplicate structural keys before strict typed decoding.
	keys := json.NewDecoder(bytes.NewReader(b))
	token, err := keys.Token()
	if err != nil || token != json.Delim('{') {
		return invalid
	}
	seen := map[string]bool{}
	for keys.More() {
		token, err := keys.Token()
		if err != nil {
			return invalid
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return invalid
		}
		seen[key] = true
		var raw json.RawMessage
		if keys.Decode(&raw) != nil {
			return invalid
		}
	}
	if _, err := keys.Token(); err != nil {
		return invalid
	}
	if _, err := keys.Token(); err != io.EOF {
		return invalid
	}
	for _, key := range []string{"version", "service", "account", "path", "beforeHash", "afterHash", "partitions"} {
		if !seen[key] {
			return invalid
		}
	}
	var j keychainACLJournal
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&j) != nil || j.Version != 1 || j.Service != s.p.KeychainService || j.Account != s.p.KeychainAccount || j.Path != s.testKeychain || len(j.Partitions) == 0 {
		return invalid
	}
	for _, hash := range []string{j.BeforeHash, j.AfterHash} {
		raw, err := hex.DecodeString(hash)
		if err != nil || len(raw) != sha256.Size {
			return invalid
		}
	}
	ops := s.aclIO()
	live, err := ops.read()
	if err != nil {
		return errors.New("cannot read native credentials for Keychain ACL recovery")
	}
	hash := payloadHash(live)
	if hash != j.BeforeHash && hash != j.AfterHash {
		return errors.New("credentials changed outside Keychain ACL recovery; refusing to restore stale permissions")
	}
	if err := ops.restore(j.Partitions); err != nil {
		return errors.New("Keychain ACL recovery is pending; original permissions could not be restored")
	}
	verified, err := ops.securityRead()
	if err != nil {
		return errors.New("Keychain ACL recovery is pending; security access verification failed")
	}
	if !bytes.Equal(verified, live) {
		return errors.New("Keychain ACL recovery is pending; credential verification changed")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("cannot clear Keychain ACL recovery")
	}
	if err := syncDirectory(s.p.StateDir); err != nil {
		return errors.New("cannot sync completed Keychain ACL recovery")
	}
	return nil
}
