package main

import "servercat.app/golib/golib"

func main() {
    //golib.Parse()
    key, err := golib.GenerateEd25519PrivateKey()
    if err != nil {
        panic(err)
    }
    println("----")
    println(key.PublicKey)
    println("----")
    println(key.PrivateKey)
    println("----")

    println("Hello")
}
