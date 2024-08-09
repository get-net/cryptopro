package cryptopro

import (
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func TestHash(t *testing.T) {
	prov, err := CryptAcquireContext("", "", PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := CreateCryptHash(prov, CALG_GR3411_2012_256)
	if err != nil {
		t.Fatal(err)
	}

	hashBytes, err := ioutil.ReadFile("hash.go")
	if err != nil {
		t.Fatal(err)
	}

	err = hash.CryptHashData(hashBytes)
	if err != nil {
		t.Fatal(err)
	}

	val, err := hash.CryptGetHashParam()
	if err != nil {
		t.Fatal(err)
	}
	hashVal := hex.EncodeToString(val)
	if hashVal != "ea9785e97782eaccdf99806954ba366f3aad6e934e45e6084a9276a3149f53d2" {
		t.Fatal("got hash ", hashVal)
	}

	err = hash.DestoryHash()
	if err != nil {
		t.Fatal(err)
	}

	err = prov.Release()
	if err != nil {
		t.Fatal(err)
	}

}
