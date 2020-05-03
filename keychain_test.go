package main

import (
	"log"
	"servercat.app/golib/golib"
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"time"
)

const ed25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBX3YLBYr
LpZhxInHcAT2sAAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPmlfMvmcIiCV93d
89YMAqhMUc5VLYsfo+WR4n6h9cAuAAAAoOhnV1U5qnkk2tkEEirRxG+KyZTRx0JHFRCFEb
2P1JYru6n9JrtQq76dE++fTAXrVyBc53dolMn9g6+g6Ru1b0dad7zpgdJ1IdaOw/NXBPdV
h//Uafie4x9xKmI5iMJpr5K5+evVQan0xwShHigc/S0WUmPWFtQCRvZYmyUzajVqHEz1eu
cvV8fHxUzpJ7dPKhezgIYuzaatOJmoGeUMTVY=
-----END OPENSSH PRIVATE KEY-----`


func TestGenerateRSAKey(t *testing.T) {
	keyPair, err := golib.GenerateRsaPrivateKey()
	if err != nil  {
		assert.Error(t, err)
	}

	assert.NotNil(t, keyPair, "should not fail")
	assert.True(t, strings.HasPrefix(keyPair.PublicKey, "ssh-rsa "))
	assert.True(t, strings.HasPrefix(keyPair.PrivateKey, "-----BEGIN RSA PRIVATE KEY-----"))
}

func TestGenerateEd25519Key(t *testing.T) {
	keyPair, err := golib.GenerateEd25519PrivateKey()
	if err != nil  {
		assert.Error(t, err)
	}

	assert.NotNil(t, keyPair, "should not fail")
	assert.True(t, strings.HasPrefix(keyPair.PublicKey, "ssh-ed25519 "))
	assert.True(t, strings.HasPrefix(keyPair.PrivateKey, "-----BEGIN OPENSSH PRIVATE KEY-----"))
}

func TestDetectRsaKey(t *testing.T) {
	keyPair, err := golib.GenerateRsaPrivateKey()
	if err != nil  {
		assert.Error(t, err)
	}

	info := golib.DetectKey(keyPair.PrivateKey, "")
	assert.Equal(t, "", info.Error)
	assert.Equal(t, true, info.Valid)
	assert.Equal(t, "rsa", info.CipherName)
}

func TestDetectEdKey(t *testing.T) {
	keyPair, err := golib.GenerateEd25519PrivateKey()
	if err != nil  {
		assert.Error(t, err)
	}

	info := golib.DetectKey(keyPair.PrivateKey, "")
	assert.Equal(t, "", info.Error)
	assert.Equal(t, true, info.Valid)
	assert.Equal(t, "ed25519", info.CipherName)
}


func TestSSHPublicKey(t *testing.T) {
	sshPubKey, err := golib.GenerateSSHAuthorizedKey(ed25519PrivateKey, "test")

	if err != nil {
		t.Error(err)
	}

	if !strings.HasPrefix(sshPubKey, "ssh-ed25519 ") {
		t.Errorf("SSH Authorized Key must startswith ssh: %s", sshPubKey)
	}

	assert.False(t, strings.HasSuffix(sshPubKey, "\n"), "has trailing blank")
}


func TestKeyDetect(t *testing.T) {
	info := golib.DetectKey(ed25519PrivateKey, "invalid_pass")
	assert.Equal(t, false, info.Valid)

	start := time.Now()
	info = golib.DetectKey(ed25519PrivateKey, "test")
	log.Printf("Binomial took %s", time.Since(start))

	assert.Equal(t, "", info.Error, "they should be equal")
	assert.Equal(t, true, info.Valid, "they should be equal")
	assert.Equal(t, "ed25519", info.CipherName, "they should be equal")
}
