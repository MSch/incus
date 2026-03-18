package cliconfig

import "strings"

func isUnixRemoteAddr(addr string) bool {
	return strings.HasPrefix(addr, "unix:")
}

func isSSHRemoteAddr(addr string) bool {
	return strings.HasPrefix(addr, "ssh:")
}

func isSocketRemoteAddr(addr string) bool {
	return isUnixRemoteAddr(addr) || isSSHRemoteAddr(addr)
}
