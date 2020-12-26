package cryptopro

import (
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func TestHash(t *testing.T) {
	prov, err := CryptAcquireContext("", CRYPT_VERIFYCONTEXT)
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
	if hashVal != "daa851262492b08b92642a9152707b30bdb084f3b1670a96fb3bada9e6ecc759" {
		t.Fatal("got hash ", hashVal)
	}

	err = hash.DestoryHash()
	if err != nil {
		t.Fatal(err)
	}

}
