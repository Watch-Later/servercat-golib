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


    rsa, err := golib.GenerateRsaPrivateKey()
    if err != nil {
        panic(err)
    }
    println("----")
    println(rsa.PublicKey)
    println("----")
    println(rsa.PrivateKey)
    println("----")

    println("Hello")
}
