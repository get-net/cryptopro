package cryptopro

import (
	"testing"
)

func TestCryptExportPublicKey(t *testing.T) {
	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}

	prov, err := CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		t.Fatal(err)
	}

	key, err := CryptGetUserKey(prov, AT_KEYEXCHANGE)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := CryptExportKey(key, PUBLICKEYBLOB)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CryptImportKey(prov, blob)
	if err != nil {
		t.Fatal(err)
	}

	err = CertFreeCertificateContext(cert)
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(store, 0)
	if err != nil {
		t.Fatal(err)
	}
}
