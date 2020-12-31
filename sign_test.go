package cryptopro

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCryptSignHash(t *testing.T) {

	capBytes := []byte("Hello world")

	store, err := CertOpenSystemStore("MY")
	defer CertCloseStore(store, 0)
	if err != nil {
		t.Fatal("Can't open MY store")
	}

	//client, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e",
	//	CERT_FIND_SHA1_HASH)

	client, err := CertFindCertificateInStore(store, "365050de109cbe26a1f1a09b5a10c6485d6bbe56",
		CERT_FIND_SHA1_HASH)

	if err != nil {
		t.Fatal(err)
	}

	context, err := CryptAquireCertificatePrivateKey(client)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := CreateCryptHash(context, CALG_GR3411)
	if err != nil {
		t.Fatal(err)
	}

	err = hash.CryptHashData(capBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = hash.CryptGetHashParam()
	if err != nil {
		t.Fatal(err)
	}

	sigBytes, err := CryptSignHash(hash, AT_KEYEXCHANGE, 0)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("signature: %s\n", hex.EncodeToString(sigBytes))

}
