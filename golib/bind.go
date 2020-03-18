package golib

import (
    "crypto/ed25519"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    //"golang.org/x/crypto/ssh"
    "io/ioutil"
    "os"
    "strings"
    "github.com/ScaleFT/sshkeys"
)


func Parse() {
    file, err := os.Open("../../.ssh/id_ed25519")
    //file, err := os.Open("../../.ssh/id_ed25519_2")
    //file, err := os.Open("../../.ssh/id_rsa")
    if err != nil {
        panic(err)
    }

    defer file.Close()


    pemBytes, _ := ioutil.ReadAll(file)
    passPhrase := []byte("wulibaye")

    block, _ := pem.Decode(pemBytes)
    if block == nil {
        panic(errors.New("ssh: no key found"))
    }

    println(block.Type)

    buf := block.Bytes


    ik, err := sshkeys.ParseEncryptedRawPrivateKey(pemBytes, passPhrase)

    _ = buf

    //ik, err := ssh.ParseRawPrivateKey(pemBytes, )
    //ik, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte("wulibaye"))
    //ik, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passPhrase)

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
                panic(fmt.Errorf("ssh: cannot decode encrypted private keys: %v", err))
            }
        }
    }

}

func Hello() string {
    print("hello")
    return "Hello"
}
