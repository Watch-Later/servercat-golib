package golib

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

type PrivateKey struct {
	Valid           bool
	PassphraseValid bool
	KeyType         string
	CipherName      string
	Bytes           int
	Encrypted       bool
	Error           string
}

func DetectKey(privateKeyPem string, passphrase string) *PrivateKey {
	var err error

	info := &PrivateKey{
		Valid: true,
	}
	pemBytes := []byte(privateKeyPem)

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		info.Valid = false
		info.Error = "No pem found"
		return info
	}

	var data []byte

	if x509.IsEncryptedPEMBlock(block) {
		info.Encrypted = true

		data, err = x509.DecryptPEMBlock(block, []byte(passphrase))

		if err == x509.IncorrectPasswordError {
			info.PassphraseValid = false
			return info
		}

		if err != nil {
			info.PassphraseValid = false
			return info
		}

	} else {
		info.Encrypted = false
		info.Bytes = len(block.Bytes)

		data = block.Bytes
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		info.CipherName = "rsa"
		_, err := x509.ParsePKCS1PrivateKey(data)
		if err != nil {
			info.PassphraseValid = false
			return info
		}
		return info
	case "EC PRIVATE KEY":
		info.CipherName = "ecdsa"
		return info
	case "DSA PRIVATE KEY":
		info.CipherName = "dsa"
		return info
	case "OPENSSH PRIVATE KEY":
		pk, err := sshkeys.ParseEncryptedRawPrivateKey(pemBytes, []byte(passphrase))

		if err != nil {
			info.Valid = false
			info.Error = err.Error()
			return info
		}

		switch pk.(type) {
		case rsa.PrivateKey:
			info.CipherName = "rsa"
			return info
		case ed25519.PrivateKey:
			info.CipherName = "ed25519"
			return info
		default:
			info.Valid = false
			info.CipherName = "unknown"
			info.Error = "Unknown key type"
			return info
		}

	default:
		info.Valid = false
		info.CipherName = "unknown"
		info.Error = "Unknown key type"
		return info
	}
}

func GenerateSSHAuthorizedKey(privateKeyPem string, passphrase string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPem))

	if block == nil {
		return "", errors.New("golib: no key found")
	}

	println(block.Type)
	pemBytes := []byte(privateKeyPem)

	pk, err := sshkeys.ParseEncryptedRawPrivateKey(pemBytes, []byte(passphrase))

	if err != nil {
		return "", err
	}

	if privateKey, ok := pk.(HasPublicKey); ok {
		pubK := privateKey.Public()
		publicRsaKey, err := ssh.NewPublicKey(pubK)
		if err != nil {
			return "", nil
		}
		pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
		return strings.TrimSpace(string(pubKeyBytes)), nil
	}

	return "", nil
}

type HasPublicKey interface {
	Public() crypto.PublicKey
}

func GenerateEd25519PrivateKey() (*KeyPair, error) {
	pubKey, priKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pk, err := sshkeys.Marshal(priKey, &sshkeys.MarshalOptions{
		Passphrase: nil,
		Format:     sshkeys.FormatOpenSSHv1,
	})

	publicRsaKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated", string(pubKeyBytes))
	return &KeyPair{
		PublicKey:  strings.TrimSpace(string(pubKeyBytes)),
		PrivateKey: strings.TrimSpace(string(pk)),
	}, nil
}

func ParsePrivateKey(pemString string, passPhrase string) {
}

func Parse() {
	file, err := os.Open("../../.golib/id_ed25519")
	//file, err := os.Open("../../.golib/id_ed25519_2")
	//file, err := os.Open("../../.golib/id_rsa")
	if err != nil {
		panic(err)
	}

	defer file.Close()

	pemBytes, _ := ioutil.ReadAll(file)
	passPhrase := []byte("wulibaye")

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		panic(errors.New("golib: no key found"))
	}

	println(block.Type)

	buf := block.Bytes

	ik, err := sshkeys.ParseEncryptedRawPrivateKey(pemBytes, passPhrase)

	_ = buf

	//ik, err := golib.ParseRawPrivateKey(pemBytes, )
	//ik, err := golib.ParseRawPrivateKeyWithPassphrase(pemBytes, passPhrase)

	if err != nil {
		panic(err)
	}

	//pk := ik.(crypto.PrivateKey)
	pk := ik.(ed25519.PrivateKey)

	println(pk)

	println(pk.Public())

	//if !pk.(crypto.PrivateKey) {
	//    panic(errors.New("Unknown"))
	//}

	if err != nil {
		panic(err)
	}

	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		println("* Encrypted")
		if x509.IsEncryptedPEMBlock(block) {
			var err error
			buf, err = x509.DecryptPEMBlock(block, passPhrase)
			if err != nil {
				if err == x509.IncorrectPasswordError {
					panic(err)
				}
				panic(fmt.Errorf("golib: cannot decode encrypted private keys: %v", err))
			}
		}
	}

}

func Hello() string {
	print("hello")
	return "Hello"
}
