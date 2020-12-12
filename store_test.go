package cryptopro

import (
	"testing"
)

func TestCertOpenSystemStore(t *testing.T) {

	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}
