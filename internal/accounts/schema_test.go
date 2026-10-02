package accounts

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestVaultSchemaRejectsDamageWithoutWrites(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	live, _ := e.capture()
	account, _ := json.Marshal(live)
	for _, bad := range []string{
		`{}`, `{"version":1}`, `{"accounts":{}}`, `{"version":1,"accounts":{},"future":true}`,
		`{"version":1,"accounts":{"personal":` + string(account) + `,"personal":` + string(account) + `}}`,
		`{"version":1,"accounts":{"personal":` + strings.Replace(string(account), `"savedAt":`, `"unknown":true,"savedAt":`, 1) + `}}`,
	} {
		t.Run(bad, func(t *testing.T) {
			must(t, os.WriteFile(e.statePath(), []byte(bad), 0600))
			before := bytes.Clone(c.data)
			identity := read(t, e.Paths.IdentityFile)
			if e.Save("personal") == nil {
				t.Fatal("damaged vault accepted")
			}
			if !bytes.Equal(read(t, e.statePath()), []byte(bad)) || !bytes.Equal(c.data, before) || !bytes.Equal(identity, read(t, e.Paths.IdentityFile)) {
				t.Fatal("rejection changed stored data")
			}
		})
	}
}

func TestDuplicateNestedLiveJSONRejected(t *testing.T) {
	for _, bad := range []string{
		`{"claudeAiOauth":{"accessToken":"a","accessToken":"b","refreshToken":"r"}}`,
	} {
		e, c := fixture(t)
		c.data = []byte(bad)
		if e.Save("personal") == nil {
			t.Fatal("duplicate nested credential field accepted")
		}
		if !bytes.Equal(c.data, []byte(bad)) {
			t.Fatal("credentials changed")
		}
	}
	e, c := fixture(t)
	c.data = bytes.Replace(c.data, []byte(`"plugin-secret"`), []byte(`[{"value":1,"value":2}]`), 1)
	before := bytes.Clone(c.data)
	if e.Save("personal") == nil {
		t.Fatal("duplicate field inside array accepted")
	}
	if !bytes.Equal(before, c.data) {
		t.Fatal("credentials changed")
	}
}

func TestRecoveryJournalSchemaRejectedWithoutWrites(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	live, _ := e.capture()
	j, _ := json.Marshal(journal{Version: 1, Before: live, After: live, ActiveBefore: "personal"})
	for _, bad := range []string{
		strings.Replace(string(j), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(j), `"version":1,`, "", 1),
		strings.Replace(string(j), `"before":`, `"unknown":true,"before":`, 1),
		strings.Replace(string(j), `"before":`, `"before":{},"before":`, 1),
	} {
		t.Run(bad, func(t *testing.T) {
			must(t, os.WriteFile(e.journalPath(), []byte(bad), 0600))
			before := bytes.Clone(c.data)
			identity := read(t, e.Paths.IdentityFile)
			vault := read(t, e.statePath())
			if e.Recover() == nil {
				t.Fatal("damaged journal accepted")
			}
			if !bytes.Equal(before, c.data) || !bytes.Equal(identity, read(t, e.Paths.IdentityFile)) || !bytes.Equal(vault, read(t, e.statePath())) || !bytes.Equal([]byte(bad), read(t, e.journalPath())) {
				t.Fatal("journal rejection changed data")
			}
		})
	}
}
