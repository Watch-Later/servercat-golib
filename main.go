package main

import "servercat.app/golib/keychain"

func main() {
    //keychain.Parse()
    pk, pubKey := keychain.GenerateEd25519PrivateKey()
    println(pk)
    println(pubKey)

    println("Hello")
}
