package cryptopro

import (
	"fmt"
	"testing"
)

func TestCadesBes(t *testing.T) {
	thumbprint := "4c880bda646323cad15a8708ba947aa8043e03a4"
	detached := true
	file := []byte("test msg")

	// открываем хранилище
	store, err := CertOpenSystemStore("MY")
	defer func() {
		if err = CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG); err != nil {
			fmt.Printf("close store failed: %s\n", err.Error())
		}
	}()
	if err != nil {
		t.Fatal(fmt.Errorf("open MY store failed: %w", err))
	}

	// поиск сертификата
	cert, err := CertFindCertificateInStore(store, thumbprint, CERT_FIND_SHA1_HASH)
	defer func() {
		if err = CertFreeCertificateContext(cert); err != nil {
			fmt.Printf("free certificate context failed: %s\n", err.Error())
		}
	}()
	if err != nil {
		t.Fatal(fmt.Errorf("find certificate in store failed: %w", err))
	}

	// проверка наличия закрытого ключа
	prov, err := CryptAquireCertificatePrivateKey(cert)
	defer func() {
		if err = prov.Release(); err != nil {
			fmt.Printf("release context failed: %s \n", err.Error())
		}
	}()
	if err != nil {
		t.Fatal(fmt.Errorf("get private key failed: %w", err))
	}

	_, err = SignMessageCadesBes(cert, detached, file)
	if err != nil {
		t.Fatal(fmt.Errorf("sign message failed: %w", err))
	}

}
