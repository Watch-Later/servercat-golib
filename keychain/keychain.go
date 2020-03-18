package keychain

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"log"

	//"crypto/rsa"
	"crypto/x509"
	//"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ScaleFT/sshkeys"
	"io/ioutil"
	"os"
	"strings"
)

//func savePEMKey(key *rsa.PrivateKey) {
//    var privateKey = &pem.Block{
//        Type:  "PRIVATE KEY",
//        Bytes: x509.MarshalPKCS1PrivateKey(key),
//    }
//}
//
//func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
//    asn1Bytes, err := asn1.Marshal(pubkey)
//    checkError(err)
//
//    var pemkey = &pem.Block{
//        Type:  "PUBLIC KEY",
//        Bytes: asn1Bytes,
//    }
//    err = pem.Encode(pemfile, pemkey)
//}

func GenerateSSHAuthorizedKey(privateKeyPem string, passphrase string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPem))

	if block == nil {
		return "", errors.New("keychain: no key found")
	}

	println(block.Type)
	pemBytes := []byte(privateKeyPem)

	//buf := block.Bytes

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
		return string(pubKeyBytes), nil
	}

	return "", nil
}

type KeyPair struct {
	PublicKey  string
	PrivateKey string
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

	println("marshaled pk", string(pk))

	publicRsaKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated", string(pubKeyBytes))
	return &KeyPair{
		PublicKey:  string(pubKeyBytes),
		PrivateKey: string(pk),
	}, nil
}

func GenerateEcKey() {
}

func ParsePrivateKey(pemString string, passPhrase string) {
}

func Parse() {
	file, err := os.Open("../../.keychain/id_ed25519")
	//file, err := os.Open("../../.keychain/id_ed25519_2")
	//file, err := os.Open("../../.keychain/id_rsa")
	if err != nil {
		panic(err)
	}

	defer file.Close()

	pemBytes, _ := ioutil.ReadAll(file)
	passPhrase := []byte("wulibaye")

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		panic(errors.New("keychain: no key found"))
	}

	println(block.Type)

	buf := block.Bytes

	ik, err := sshkeys.ParseEncryptedRawPrivateKey(pemBytes, passPhrase)

	_ = buf

	//ik, err := keychain.ParseRawPrivateKey(pemBytes, )
	//ik, err := keychain.ParseRawPrivateKeyWithPassphrase(pemBytes, passPhrase)

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
				panic(fmt.Errorf("keychain: cannot decode encrypted private keys: %v", err))
			}
		}
	}

}

func Hello() string {
	print("hello")
	return "Hello"
}
