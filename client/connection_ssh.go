package incus

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/lxc/incus/v6/shared/logger"
	"github.com/lxc/incus/v6/shared/util"
)

const sshDefaultPort = "22"

var sshDefaultSocketPathCandidates = []string{
	"/run/incus/unix.socket",
	"/var/lib/incus/unix.socket",
	"/run/incus/unix.socket.user",
	"/var/lib/incus/unix.socket.user",
}

type sshHTTPDialer struct {
	address      string
	clientConfig *ssh.ClientConfig
	socketPaths  []string
	selectedPath string
	agentConn    net.Conn
	client       *ssh.Client
	mu           sync.Mutex
}

func (d *sshHTTPDialer) DialContext(ctx context.Context, _ string, _ string) (net.Conn, error) {
	conn, err := d.dialSocket(ctx)
	if err == nil {
		return conn, nil
	}

	// Retry once with a fresh SSH transport in case the underlying SSH session expired.
	d.closeClient()

	return d.dialSocket(ctx)
}

func (d *sshHTTPDialer) Close() {
	d.closeClient()

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.agentConn != nil {
		_ = d.agentConn.Close()
		d.agentConn = nil
	}
}

func (d *sshHTTPDialer) dialSocket(ctx context.Context) (net.Conn, error) {
	client, err := d.getClient(ctx)
	if err != nil {
		return nil, err
	}

	paths := d.socketDialOrder()
	errorsByPath := make([]string, 0, len(paths))

	for _, path := range paths {
		conn, err := client.Dial("unix", path)
		if err != nil {
			errorsByPath = append(errorsByPath, fmt.Sprintf("%s: %v", path, err))
			continue
		}

		d.mu.Lock()
		d.selectedPath = path
		d.mu.Unlock()

		return conn, nil
	}

	return nil, fmt.Errorf("Failed connecting to the remote Incus Unix socket over SSH:\n - %s", strings.Join(errorsByPath, "\n - "))
}

func (d *sshHTTPDialer) getClient(ctx context.Context) (*ssh.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.client != nil {
		return d.client, nil
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, d.address, d.clientConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	d.client = ssh.NewClient(sshConn, chans, reqs)
	return d.client, nil
}

func (d *sshHTTPDialer) closeClient() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.client != nil {
		_ = d.client.Close()
		d.client = nil
	}
}

func (d *sshHTTPDialer) socketDialOrder() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	paths := make([]string, 0, len(d.socketPaths))
	if d.selectedPath != "" {
		paths = append(paths, d.selectedPath)
	}

	for _, path := range d.socketPaths {
		if path == d.selectedPath {
			continue
		}

		paths = append(paths, path)
	}

	return paths
}

func sshHTTPClient(args *ConnectionArgs, remoteURL *url.URL) (*http.Client, *sshHTTPDialer, string, error) {
	if args == nil {
		args = &ConnectionArgs{}
	}

	sshConfig, agentConn, err := sshClientConfig(remoteURL, args)
	if err != nil {
		return nil, nil, "", err
	}

	remoteHost := remoteURL.Hostname()
	if remoteHost == "" {
		if agentConn != nil {
			_ = agentConn.Close()
		}

		return nil, nil, "", errors.New("Missing host in SSH remote")
	}

	remotePort := remoteURL.Port()
	if remotePort == "" {
		remotePort = sshDefaultPort
	}

	dialer := &sshHTTPDialer{
		address:      net.JoinHostPort(remoteHost, remotePort),
		clientConfig: sshConfig,
		socketPaths:  sshRemoteSocketPaths(remoteURL),
		agentConn:    agentConn,
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		ExpectContinueTimeout: 30 * time.Second,
		ResponseHeaderTimeout: 3600 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
	}

	client := args.HTTPClient
	if client == nil {
		client = &http.Client{}
	}

	client.Transport = transport
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		req.Header = via[len(via)-1].Header
		return nil
	}

	return client, dialer, dialer.socketPaths[0], nil
}

func sshClientConfig(remoteURL *url.URL, args *ConnectionArgs) (*ssh.ClientConfig, net.Conn, error) {
	hostKeyCallback, err := sshKnownHostsCallback()
	if err != nil {
		return nil, nil, err
	}

	authMethods, agentConn, err := sshAuthMethods(args)
	if err != nil {
		return nil, nil, err
	}

	userName, err := sshUserName(remoteURL)
	if err != nil {
		if agentConn != nil {
			_ = agentConn.Close()
		}

		return nil, nil, err
	}

	return &ssh.ClientConfig{
		User:            userName,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}, agentConn, nil
}

func sshUserName(remoteURL *url.URL) (string, error) {
	if remoteURL.User != nil {
		if _, ok := remoteURL.User.Password(); ok {
			return "", errors.New("SSH remotes do not support passwords in the URL")
		}

		userName := remoteURL.User.Username()
		if userName != "" {
			return userName, nil
		}
	}

	currentUser, err := user.Current()
	if err == nil && currentUser.Username != "" {
		return currentUser.Username, nil
	}

	if os.Getenv("USER") != "" {
		return os.Getenv("USER"), nil
	}

	if os.Getenv("USERNAME") != "" {
		return os.Getenv("USERNAME"), nil
	}

	if err == nil {
		return "", errors.New("Failed to determine the SSH user")
	}

	return "", fmt.Errorf("Failed to determine the SSH user: %w", err)
}

func sshKnownHostsCallback() (ssh.HostKeyCallback, error) {
	knownHostsFiles := make([]string, 0, 4)

	homeDir, err := os.UserHomeDir()
	if err == nil && homeDir != "" {
		knownHostsFiles = append(knownHostsFiles,
			filepath.Join(homeDir, ".ssh", "known_hosts"),
			filepath.Join(homeDir, ".ssh", "known_hosts2"))
	}

	if runtime.GOOS != "windows" {
		knownHostsFiles = append(knownHostsFiles, "/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2")
	}

	existingFiles := make([]string, 0, len(knownHostsFiles))
	for _, path := range knownHostsFiles {
		if util.PathExists(path) {
			existingFiles = append(existingFiles, path)
		}
	}

	if len(existingFiles) == 0 {
		return nil, errors.New("Couldn't find any SSH known_hosts file")
	}

	return knownhosts.New(existingFiles...)
}

func sshAuthMethods(args *ConnectionArgs) ([]ssh.AuthMethod, net.Conn, error) {
	authMethods := make([]ssh.AuthMethod, 0, 2)

	var agentConn net.Conn
	if sshAgentSock := os.Getenv("SSH_AUTH_SOCK"); sshAgentSock != "" {
		conn, err := net.Dial("unix", sshAgentSock)
		if err == nil {
			agentConn = conn
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	keyPaths, err := sshDefaultKeyPaths()
	if err != nil && len(authMethods) == 0 {
		if agentConn != nil {
			_ = agentConn.Close()
		}

		return nil, nil, err
	}

	hasDefaultKeys := false
	for _, path := range keyPaths {
		if util.PathExists(path) {
			hasDefaultKeys = true
			break
		}
	}

	if hasDefaultKeys {
		authMethods = append(authMethods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return sshDefaultSigners(keyPaths, args)
		}))
	}

	if len(authMethods) == 0 {
		return nil, nil, errors.New("Couldn't find any usable SSH authentication method")
	}

	return authMethods, agentConn, nil
}

func sshDefaultKeyPaths() ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	return []string{
		filepath.Join(homeDir, ".ssh", "id_ed25519"),
		filepath.Join(homeDir, ".ssh", "id_ecdsa"),
		filepath.Join(homeDir, ".ssh", "id_rsa"),
		filepath.Join(homeDir, ".ssh", "id_dsa"),
	}, nil
}

func sshDefaultSigners(keyPaths []string, args *ConnectionArgs) ([]ssh.Signer, error) {
	signers := make([]ssh.Signer, 0, len(keyPaths))
	errorStrings := []string{}
	for _, path := range keyPaths {
		if !util.PathExists(path) {
			continue
		}

		signer, err := sshReadPrivateKey(path, args.PromptPassword)
		if err != nil {
			errorStrings = append(errorStrings, fmt.Sprintf("%s: %v", path, err))
			continue
		}

		signers = append(signers, signer)
	}

	if len(signers) == 0 && len(errorStrings) > 0 {
		return nil, fmt.Errorf("Failed loading the default SSH private keys:\n - %s", strings.Join(errorStrings, "\n - "))
	}

	return signers, nil
}

func sshReadPrivateKey(path string, promptPassword func(string) (string, error)) (ssh.Signer, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(content)
	if err == nil {
		return signer, nil
	}

	var passphraseMissing *ssh.PassphraseMissingError
	if !errors.As(err, &passphraseMissing) {
		return nil, err
	}

	if promptPassword == nil {
		return nil, errors.New("Private key is password protected and no helper was configured")
	}

	password, err := promptPassword(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKeyWithPassphrase(content, []byte(password))
}

func sshRemoteSocketPaths(remoteURL *url.URL) []string {
	path := remoteURL.Path
	if path == "" || path == "/" {
		return append([]string(nil), sshDefaultSocketPathCandidates...)
	}

	return []string{path}
}

// ConnectIncusSSH lets you connect to a remote Incus daemon over an SSH connection to its Unix socket.
func ConnectIncusSSH(uri string, args *ConnectionArgs) (InstanceServer, error) {
	return ConnectIncusSSHWithContext(context.Background(), uri, args)
}

// ConnectIncusSSHWithContext lets you connect to a remote Incus daemon over an SSH connection to its Unix socket with context.Context.
func ConnectIncusSSHWithContext(ctx context.Context, uri string, args *ConnectionArgs) (InstanceServer, error) {
	logger.Debug("Connecting to a remote Incus over SSH", logger.Ctx{"url": uri})

	if args == nil {
		args = &ConnectionArgs{}
	}

	remoteURL, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	httpBaseURL, err := url.Parse("http://unix.socket")
	if err != nil {
		return nil, err
	}

	httpClient, dialer, socketPath, err := sshHTTPClient(args, remoteURL)
	if err != nil {
		return nil, err
	}

	ctxConnected, ctxConnectedCancel := context.WithCancel(context.Background())

	server := ProtocolIncus{
		ctx:                ctx,
		httpBaseURL:        *httpBaseURL,
		httpUnixPath:       socketPath,
		httpProtocol:       "ssh",
		httpUserAgent:      args.UserAgent,
		ctxConnected:       ctxConnected,
		ctxConnectedCancel: ctxConnectedCancel,
		eventConns:         make(map[string]*websocket.Conn),
		eventListeners:     make(map[string][]*EventListener),
		skipEvents:         args.SkipGetEvents,
		tempPath:           args.TempPath,
		disconnectHook:     dialer.Close,
	}

	server.http = httpClient

	if !args.SkipGetServer {
		serverStatus, _, err := server.GetServer()
		if err != nil {
			dialer.Close()
			return nil, err
		}

		server.httpCertificate = serverStatus.Environment.Certificate
		server.httpUnixPath = dialer.selectedPath
	}

	return &server, nil
}
