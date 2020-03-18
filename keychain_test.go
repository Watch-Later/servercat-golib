package main

import (
	"servercat.app/golib/keychain"
	"strings"
	"testing"
)


func TestSSHPublicKey(t *testing.T) {
	//ad := assert.New(t)
	ed25519_pk := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBX3YLBYr
LpZhxInHcAT2sAAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPmlfMvmcIiCV93d
89YMAqhMUc5VLYsfo+WR4n6h9cAuAAAAoOhnV1U5qnkk2tkEEirRxG+KyZTRx0JHFRCFEb
2P1JYru6n9JrtQq76dE++fTAXrVyBc53dolMn9g6+g6Ru1b0dad7zpgdJ1IdaOw/NXBPdV
h//Uafie4x9xKmI5iMJpr5K5+evVQan0xwShHigc/S0WUmPWFtQCRvZYmyUzajVqHEz1eu
cvV8fHxUzpJ7dPKhezgIYuzaatOJmoGeUMTVY=
-----END OPENSSH PRIVATE KEY-----`

	sshPubKey, err := keychain.GenerateSSHAuthorizedKey(ed25519_pk, "test")

	if err != nil {
		t.Error(err)
	}

	println(sshPubKey)

	if !strings.HasPrefix(sshPubKey, "ssh-ed25519 ") {
		t.Errorf("SSH Authorized Key must startswith ssh: %s", sshPubKey)
	}
}
