package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2kims/lotor-go/bridge"
)

func TestConnectorShouldRejectUnsafeFilesAndInvalidConfigurationBeforeNetwork(t *testing.T) {
	for _, scenario := range []string{"missing", "directory", "symlink", "readable", "oversize", "unknown-field", "multiple-json", "invalid-key"} {
		t.Run(scenario, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "connector.json")
			body, mode := `{}`, os.FileMode(0o600)
			switch scenario {
			case "directory":
				if err := os.Mkdir(file, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("absent", file); err != nil {
					t.Fatal(err)
				}
			case "readable":
				mode = 0o644
			case "oversize":
				body = strings.Repeat(" ", 65537)
			case "unknown-field":
				body = `{"unexpected":"value"}`
			case "multiple-json":
				body = `{} {}`
			case "invalid-key":
				body = `{"signing_private_key":"not-a-key"}`
			}
			if scenario != "missing" && scenario != "directory" && scenario != "symlink" {
				if err := os.WriteFile(file, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(context.Background(), file); !errors.Is(err, bridge.ErrInvalid) {
				t.Fatal("unsafe config was not rejected", err)
			}
		})
	}
}
