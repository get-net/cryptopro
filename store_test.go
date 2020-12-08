package cryptopro

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestCertOpenSystemStore(t *testing.T) {


	_, err := CryptAcquireContext("dcaa1808-81c7-4fa0-b4fb-0cf44797cb3d")
	if err != nil {
		t.Fatal(err)
	}

	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
//	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("got cert: %+v\n", cert)


	pkey, err := CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CryptGenKey(pkey, CALG_G28147, CRYPT_EXPORTABLE)
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := ioutil.ReadFile("avsh.cer")
	if err != nil {
		t.Fatal(err)
	}

	pubCert, err := CertCreateCertificateContext(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := CryptImportPublicKeyInfoEx(pkey, pubCert)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("got pubKey %+v\n", pubKey)
	blob, err := CryptExportKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("got blob %+v\n", blob)

	_, err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}