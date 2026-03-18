package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	config "github.com/lxc/incus/v6/shared/cliconfig"
)

func TestRemoteConfigWithURLSwitchesToSSH(t *testing.T) {
	remote := config.Remote{
		Addr:     "https://images.example.com",
		Public:   true,
		Protocol: "simplestreams",
	}

	remote, remoteURL, err := remoteConfigWithURL(remote, "ssh://user@example.com")
	assert.NoError(t, err)
	assert.Equal(t, "ssh://user@example.com:22", remoteURL)
	assert.Equal(t, "ssh://user@example.com:22", remote.Addr)
	assert.Equal(t, "ssh", remote.AuthType)
	assert.False(t, remote.Public)
	assert.Equal(t, "incus", remote.Protocol)
}

func TestRemoteConfigWithURLSwitchesAwayFromSSH(t *testing.T) {
	remote := config.Remote{
		Addr:     "ssh://user@example.com:22",
		Protocol: "incus",
		AuthType: "ssh",
	}

	remote, remoteURL, err := remoteConfigWithURL(remote, "https://example.com:8443")
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com:8443", remoteURL)
	assert.Equal(t, "https://example.com:8443", remote.Addr)
	assert.Equal(t, "tls", remote.AuthType)
	assert.False(t, remote.Public)
	assert.Equal(t, "incus", remote.Protocol)
}
