package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func aclFixture(t *testing.T) (*keychainStore, *[]byte, *bool, *int) {
	t.Helper()
	dir := t.TempDir()
	data := []byte(`{"claudeAiOauth":{"accessToken":"old-secret"}}`)
	accessible := true
	restores := 0
	s := &keychainStore{p: Paths{StateDir: dir, CredentialFile: filepath.Join(dir, "credentials.json"), KeychainService: "fake-service", KeychainAccount: "fake-account"}}
	s.testACL = &keychainACLIO{
		snapshot: func() ([]byte, error) { return []byte("fake-original-partition-plist"), nil },
		read:     func() ([]byte, error) { return bytes.Clone(data), nil },
		restore: func(metadata []byte) error {
			restores++
			if string(metadata) != "fake-original-partition-plist" {
				return errors.New("wrong permissions")
			}
			accessible = true
			return nil
		},
		securityRead: func() ([]byte, error) {
			if !accessible {
				return nil, errors.New("security access denied")
			}
			return bytes.Clone(data), nil
		},
		write: func(b []byte) error {
			journal, err := os.ReadFile(s.aclPath())
			if err != nil {
				return errors.New("mutation before durable snapshot")
			}
			if bytes.Contains(journal, []byte("old-secret")) || bytes.Contains(journal, []byte("new-secret")) {
				return errors.New("journal exposed credentials")
			}
			data = bytes.Clone(b)
			accessible = false
			return nil
		},
	}
	return s, &data, &accessible, &restores
}

func TestKeychainACLJournalCheckedBeforeRead(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(p string, b []byte) {
		t.Helper()
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(dir, "pending-keychain-acl.json"), []byte(`{"version":1}`))
	s := &keychainStore{p: Paths{StateDir: dir, CredentialFile: filepath.Join(dir, "credentials.json"), KeychainService: "fake-service", KeychainAccount: "fake-account"}}
	_, err := s.Read()
	if err == nil || !strings.Contains(err.Error(), "ACL recovery") {
		t.Fatalf("pending ACL journal ignored: %v", err)
	}
}

func TestKeychainACLWriteRestoresPermissionsAndClearsJournal(t *testing.T) {
	s, data, accessible, restores := aclFixture(t)
	target := []byte(`{"claudeAiOauth":{"accessToken":"new-secret"}}`)
	if err := s.writeKeychain(target); err != nil {
		t.Fatal(err)
	}
	if !*accessible || *restores != 1 || !bytes.Equal(*data, target) {
		t.Fatal("native update did not preserve permissions/payload")
	}
	if _, err := os.Stat(s.aclPath()); !os.IsNotExist(err) {
		t.Fatal("completed update left ACL journal")
	}
}

func TestKeychainACLInterruptedWriteRecoveredBeforeRead(t *testing.T) {
	s, data, accessible, restores := aclFixture(t)
	mutation := s.testACL.write
	s.testACL.write = func(b []byte) error {
		if err := mutation(b); err != nil {
			return err
		}
		return errors.New("interrupted after mutation")
	}
	target := []byte(`{"claudeAiOauth":{"accessToken":"new-secret"}}`)
	if s.writeKeychain(target) == nil {
		t.Fatal("expected interrupted update")
	}
	if *accessible {
		t.Fatal("fixture must simulate lost security access")
	}
	got, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !*accessible || *restores != 1 || !bytes.Equal(got, target) || !bytes.Equal(*data, target) {
		t.Fatal("recovery changed token generation or failed permissions")
	}
	if _, err := s.Read(); err != nil {
		t.Fatal(err)
	}
	if *restores != 1 {
		t.Fatal("completed recovery was repeated")
	}
}

func TestKeychainACLRecoveryRefusesForeignPayload(t *testing.T) {
	s, data, _, restores := aclFixture(t)
	if err := s.beginACLUpdate([]byte("after")); err != nil {
		t.Fatal(err)
	}
	*data = []byte("external-newer-secret")
	if _, err := s.Read(); err == nil {
		t.Fatal("foreign generation accepted")
	}
	if *restores != 0 {
		t.Fatal("foreign generation permissions overwritten")
	}
	if _, err := os.Stat(s.aclPath()); err != nil {
		t.Fatal("refusal lost recovery journal")
	}
	for _, operation := range []func() error{
		func() error { return s.Write([]byte(`{"claudeAiOauth":{}}`)) },
		func() error { return s.RecoverAccount([]byte("{}"), []byte("{}")) },
		s.Delete, s.deleteKeychain,
	} {
		if operation() == nil {
			t.Fatal("entry point bypassed foreign ACL journal")
		}
	}
	if *restores != 0 {
		t.Fatal("entry point restored stale permissions")
	}
}

func TestKeychainACLSecurityVerificationFailureRetainsJournal(t *testing.T) {
	s, _, _, _ := aclFixture(t)
	if err := s.beginACLUpdate([]byte("after")); err != nil {
		t.Fatal(err)
	}
	securityRead := s.testACL.securityRead
	s.testACL.securityRead = func() ([]byte, error) { return nil, errors.New("permission still unavailable") }
	if s.recoverPendingACL() == nil {
		t.Fatal("security verification failure ignored")
	}
	if _, err := os.Stat(s.aclPath()); err != nil {
		t.Fatal("verification failure lost ACL journal")
	}
	s.testACL.securityRead = securityRead
	if err := s.recoverPendingACL(); err != nil {
		t.Fatal(err)
	}
}

func TestKeychainACLSnapshotFailurePreventsMutation(t *testing.T) {
	s, _, _, _ := aclFixture(t)
	mutated := false
	s.testACL.snapshot = func() ([]byte, error) { return nil, errors.New("cannot copy original ACL") }
	s.testACL.write = func([]byte) error { mutated = true; return nil }
	if s.writeKeychain([]byte("after")) == nil {
		t.Fatal("snapshot failure ignored")
	}
	if mutated {
		t.Fatal("payload mutated without snapshot")
	}
}

func TestKeychainSeedRejectsInteractiveCommandSeparators(t *testing.T) {
	for _, value := range []string{"fake\ncommand", "fake\rcommand", "fake\x00command"} {
		t.Run(value, func(t *testing.T) {
			s, _, _, _ := aclFixture(t)
			s.p.KeychainAccount = value
			s.testACL.securityRead = func() ([]byte, error) { return nil, os.ErrNotExist }
			if err := s.writeKeychain([]byte("after")); err == nil || !strings.Contains(err.Error(), "invalid Keychain seed argument") {
				t.Fatalf("unsafe seed argument accepted: %v", err)
			}
		})
	}
}

func TestKeychainACLRestoreFailureRetainsJournalForRetry(t *testing.T) {
	s, _, _, restores := aclFixture(t)
	if err := s.beginACLUpdate([]byte("after")); err != nil {
		t.Fatal(err)
	}
	restore := s.testACL.restore
	s.testACL.restore = func([]byte) error { return errors.New("ACL owner approval refused") }
	if s.recoverPendingACL() == nil {
		t.Fatal("restore failure ignored")
	}
	if _, err := os.Stat(s.aclPath()); err != nil {
		t.Fatal("restore failure cleared journal")
	}
	s.testACL.restore = restore
	if err := s.recoverPendingACL(); err != nil {
		t.Fatal(err)
	}
	if *restores != 1 {
		t.Fatal("restore not retried")
	}
}

func TestKeychainACLRecoveryRejectsUnknownSchemaAndBinding(t *testing.T) {
	for _, kind := range []string{"version", "binding", "unknown", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, restores := aclFixture(t)
			if err := s.beginACLUpdate([]byte("after")); err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(s.aclPath())
			var j map[string]any
			if err := json.Unmarshal(raw, &j); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "version":
				j["version"] = 2
			case "binding":
				j["service"] = "different-service"
			case "unknown":
				j["extra"] = true
			}
			raw, _ = json.Marshal(j)
			if kind == "duplicate" {
				raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			}
			if err := os.WriteFile(s.aclPath(), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if s.recoverPendingACL() == nil {
				t.Fatal("damaged sidecar accepted")
			}
			if *restores != 0 {
				t.Fatal("invalid sidecar changed permissions")
			}
		})
	}
}
