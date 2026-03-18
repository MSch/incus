package incus

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSSHRemoteSocketPathsDefault(t *testing.T) {
	t.Parallel()

	remoteURL, err := url.Parse("ssh://user@example.com")
	if err != nil {
		t.Fatalf("Failed to parse SSH URL: %v", err)
	}

	paths := sshRemoteSocketPaths(remoteURL)
	if len(paths) != len(sshDefaultSocketPathCandidates) {
		t.Fatalf("Expected %d default socket paths, got %d", len(sshDefaultSocketPathCandidates), len(paths))
	}

	for i, path := range sshDefaultSocketPathCandidates {
		if paths[i] != path {
			t.Fatalf("Expected path %q at index %d, got %q", path, i, paths[i])
		}
	}
}

func TestSSHRemoteSocketPathsExplicit(t *testing.T) {
	t.Parallel()

	remoteURL, err := url.Parse("ssh://user@example.com/custom/incus.sock")
	if err != nil {
		t.Fatalf("Failed to parse SSH URL: %v", err)
	}

	paths := sshRemoteSocketPaths(remoteURL)
	if len(paths) != 1 {
		t.Fatalf("Expected a single explicit socket path, got %d", len(paths))
	}

	if paths[0] != "/custom/incus.sock" {
		t.Fatalf("Unexpected explicit socket path %q", paths[0])
	}
}

func TestSSHAuthMethodsDoesNotPromptDuringSetup(t *testing.T) {
	homeDir := t.TempDir()
	err := os.Mkdir(filepath.Join(homeDir, ".ssh"), 0o700)
	if err != nil {
		t.Fatalf("Failed creating test SSH directory: %v", err)
	}

	err = os.WriteFile(filepath.Join(homeDir, ".ssh", "id_ed25519"), encryptedTestPrivateKey(t), 0o600)
	if err != nil {
		t.Fatalf("Failed writing test SSH key: %v", err)
	}

	t.Setenv("HOME", homeDir)
	t.Setenv("SSH_AUTH_SOCK", "")

	promptCalls := 0
	authMethods, agentConn, err := sshAuthMethods(&ConnectionArgs{
		PromptPassword: func(filename string) (string, error) {
			promptCalls++
			return "secret", nil
		},
	})
	if err != nil {
		t.Fatalf("Failed building SSH auth methods: %v", err)
	}

	if agentConn != nil {
		t.Fatalf("Expected no SSH agent connection, got %v", agentConn)
	}

	if len(authMethods) != 1 {
		t.Fatalf("Expected one auth method, got %d", len(authMethods))
	}

	if promptCalls != 0 {
		t.Fatalf("Expected no prompt during auth method setup, got %d prompts", promptCalls)
	}
}

func TestSSHAuthMethodsPrefersAgentBeforeDefaultKeys(t *testing.T) {
	homeDir := t.TempDir()
	err := os.Mkdir(filepath.Join(homeDir, ".ssh"), 0o700)
	if err != nil {
		t.Fatalf("Failed creating test SSH directory: %v", err)
	}

	err = os.WriteFile(filepath.Join(homeDir, ".ssh", "id_ed25519"), encryptedTestPrivateKey(t), 0o600)
	if err != nil {
		t.Fatalf("Failed writing test SSH key: %v", err)
	}

	agentSocket := filepath.Join(homeDir, "agent.sock")
	listener, err := net.Listen("unix", agentSocket)
	if err != nil {
		t.Fatalf("Failed starting test SSH agent: %v", err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		keyring := agent.NewKeyring()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(keyring, conn)
			}()
		}
	}()

	t.Setenv("HOME", homeDir)
	t.Setenv("SSH_AUTH_SOCK", agentSocket)

	promptCalls := 0
	authMethods, agentConn, err := sshAuthMethods(&ConnectionArgs{
		PromptPassword: func(filename string) (string, error) {
			promptCalls++
			return "secret", nil
		},
	})
	if err != nil {
		t.Fatalf("Failed building SSH auth methods: %v", err)
	}

	if agentConn == nil {
		t.Fatalf("Expected an SSH agent connection")
	}

	t.Cleanup(func() {
		_ = agentConn.Close()
	})

	if len(authMethods) != 2 {
		t.Fatalf("Expected two auth methods, got %d", len(authMethods))
	}

	if promptCalls != 0 {
		t.Fatalf("Expected no prompt during auth method setup, got %d prompts", promptCalls)
	}
}

func TestSSHConnectionInfoUsesConnectionAddress(t *testing.T) {
	httpBaseURL, err := url.Parse("http://unix.socket")
	if err != nil {
		t.Fatalf("Failed to parse base URL: %v", err)
	}

	server := ProtocolIncus{
		httpBaseURL:       *httpBaseURL,
		httpUnixPath:      "/run/incus/unix.socket",
		httpProtocol:      "ssh",
		connectionAddress: "ssh://user@example.com:22",
	}

	info, err := server.GetConnectionInfo()
	if err != nil {
		t.Fatalf("Failed to get connection info: %v", err)
	}

	if info.URL != "http://unix.socket" {
		t.Fatalf("Expected HTTP base URL to remain unchanged, got %q", info.URL)
	}

	if info.ConnectionAddress != "ssh://user@example.com:22" {
		t.Fatalf("Expected SSH connection address, got %q", info.ConnectionAddress)
	}
}

func TestSSHKnownHostsCallbackPromptsAndPersistsUnknownHost(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	promptCalls := 0
	callback, err := sshKnownHostsCallback(&ConnectionArgs{
		PromptHostKey: func(host string, keyType string, fingerprint string) error {
			promptCalls++

			if host != "example.com" {
				t.Fatalf("Unexpected host %q", host)
			}

			if keyType == "" {
				t.Fatalf("Expected SSH key type to be set")
			}

			if fingerprint == "" {
				t.Fatalf("Expected SSH fingerprint to be set")
			}

			return nil
		},
	})
	if err != nil {
		t.Fatalf("Failed to build host key callback: %v", err)
	}

	signer := sshTestSigner(t)
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}

	err = callback("example.com:22", remoteAddr, signer.PublicKey())
	if err != nil {
		t.Fatalf("Failed accepting unknown SSH host key: %v", err)
	}

	if promptCalls != 1 {
		t.Fatalf("Expected one SSH host-key prompt, got %d", promptCalls)
	}

	knownHostsContent, err := os.ReadFile(filepath.Join(homeDir, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatalf("Failed reading known_hosts: %v", err)
	}

	if !strings.Contains(string(knownHostsContent), "example.com") {
		t.Fatalf("Expected known_hosts entry to include hostname, got %q", string(knownHostsContent))
	}

	if !strings.Contains(string(knownHostsContent), "203.0.113.10") {
		t.Fatalf("Expected known_hosts entry to include remote address, got %q", string(knownHostsContent))
	}

	err = callback("example.com:22", remoteAddr, signer.PublicKey())
	if err != nil {
		t.Fatalf("Failed accepting cached SSH host key: %v", err)
	}

	if promptCalls != 1 {
		t.Fatalf("Expected SSH host-key prompt to be cached, got %d prompts", promptCalls)
	}
}

func encryptedTestPrivateKey(t *testing.T) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed generating test RSA key: %v", err)
	}

	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey), []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("Failed encrypting test RSA key: %v", err)
	}

	return pem.EncodeToMemory(block)
}

func sshTestSigner(t *testing.T) ssh.Signer {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed generating test RSA key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("Failed creating SSH signer: %v", err)
	}

	return signer
}
