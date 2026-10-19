package runtimecheck

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestInventoryManifest(t *testing.T) {
	for _, tool := range Inventory() {
		if tool.Name == "" || tool.Command == "" || len(tool.Args) == 0 {
			t.Fatal(tool)
		}
		if _, err := regexp.Compile(tool.VersionPattern); err != nil {
			t.Fatal(err)
		}
	}
}
func TestIntegrityDetectsChangeAndDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tool")
	manifest := filepath.Join(dir, "manifest.json")
	os.WriteFile(file, []byte("original"), 0600)
	raw, _ := json.Marshal([]IntegrityFile{{Path: file, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("original")))}})
	os.WriteFile(manifest, raw, 0600)
	check := func() bool {
		failed := false
		CheckIntegrity(manifest, func(status, _, _ string) { failed = failed || status == "FAIL" })
		return failed
	}
	if check() {
		t.Fatal("original file rejected")
	}
	os.WriteFile(file, []byte("changed"), 0600)
	if !check() {
		t.Fatal("modified file accepted")
	}
	os.Remove(file)
	os.Mkdir(file, 0700)
	if !check() {
		t.Fatal("directory accepted as executable")
	}
}
