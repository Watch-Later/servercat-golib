package main

import "servercat.app/golib/golib"

func main() {
    //golib.Parse()
    pk, pubKey := golib.GenerateEd25519PrivateKey()
    println(pk)
    println(pubKey)

    println("Hello")
}
