package cliconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigKeepsSSHAuthTypeUnset(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("INCUS_GLOBAL_CONF", filepath.Join(tmpDir, "global"))

	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := `default-remote: ssh-remote
remotes:
  ssh-remote:
    addr: ssh://user@example.com
    protocol: incus
    public: false
`

	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	conf, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if conf.Remotes["ssh-remote"].AuthType != "" {
		t.Fatalf("Expected SSH remote auth_type to stay empty, got %q", conf.Remotes["ssh-remote"].AuthType)
	}
}

func TestLoadConfigDefaultsHTTPSAuthTypeToTLS(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("INCUS_GLOBAL_CONF", filepath.Join(tmpDir, "global"))

	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := `default-remote: https-remote
remotes:
  https-remote:
    addr: https://example.com
    protocol: incus
    public: false
`

	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	conf, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if conf.Remotes["https-remote"].AuthType != "tls" {
		t.Fatalf("Expected HTTPS remote auth_type to default to tls, got %q", conf.Remotes["https-remote"].AuthType)
	}
}
