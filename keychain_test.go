package main

import (
	"servercat.app/golib/golib"
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
)

const ed25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBX3YLBYr
LpZhxInHcAT2sAAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPmlfMvmcIiCV93d
89YMAqhMUc5VLYsfo+WR4n6h9cAuAAAAoOhnV1U5qnkk2tkEEirRxG+KyZTRx0JHFRCFEb
2P1JYru6n9JrtQq76dE++fTAXrVyBc53dolMn9g6+g6Ru1b0dad7zpgdJ1IdaOw/NXBPdV
h//Uafie4x9xKmI5iMJpr5K5+evVQan0xwShHigc/S0WUmPWFtQCRvZYmyUzajVqHEz1eu
cvV8fHxUzpJ7dPKhezgIYuzaatOJmoGeUMTVY=
-----END OPENSSH PRIVATE KEY-----`


func TestSSHPublicKey(t *testing.T) {
	sshPubKey, err := golib.GenerateSSHAuthorizedKey(ed25519PrivateKey, "test")

	if err != nil {
		t.Error(err)
	}

	if !strings.HasPrefix(sshPubKey, "ssh-ed25519 ") {
		t.Errorf("SSH Authorized Key must startswith ssh: %s", sshPubKey)
	}
}


func TestKeyDetect(t *testing.T) {
	info := golib.DetectKey(ed25519PrivateKey, "test")

	assert.Equal(t, "", info.Error, "they should be equal")
	assert.Equal(t, true, info.Valid, "they should be equal")
	assert.Equal(t, "ed25519", info.CipherName, "they should be equal")
}
