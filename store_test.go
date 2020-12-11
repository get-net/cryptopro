package cryptopro

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
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
	fmt.Printf("got cert\n issuer: %s\n subject: %s\n", cert.Issuer, cert.Subject)

	_, err = CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		t.Fatal(err)
	}

	//params, err := InitParams(hProv)

	//msgInfo, err := InitEncodeInfo(cert)
	//if err != nil {
	//	t.Fatal(err)
	//}

	//	fileName := "store_test.go"

	//fi, err := os.Stat(fileName)
	//if err != nil {
	//	t.Fatal(err)
	//}

	//fiSize := fi.Size()
	//streamInfo, err := InitStreamInfo(nil, int(fiSize), "test_func")
	//if err != nil {
	//	t.Fatal(err)
	//}

	//msg, err := CryptMsgOpenToEncode(msgInfo, CMSG_ENVELOPED, streamInfo)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//chunkSize := 10 * 1024 * 1024
	//buff := make([]byte, chunkSize)
	//
	//file, err := os.Open(fileName)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//reader := bufio.NewReader(file)
	//final := 0
	//for {
	//	n, err := reader.Read(buff)
	//	if err != nil && err != io.EOF {
	//			t.Fatal(err)
	//	}
	//
	//	if n < chunkSize || err == io.EOF {
	//		final = 1
	//	}
	//	buff = buff[:n]
	//
	//	errUpd := CryptMsgUpdate(msg, buff, final)
	//	if errUpd != nil {
	//		t.Fatal(errUpd)
	//	}
	//	if final == 1 {
	//		break
	//	}
	//}
	//err = file.Close()
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//err = CryptMsgClose(msg)
	//if err != nil {
	//	t.Fatal(err)
	//}

	signInfo, err := InitSignedInfo(cert)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := CryptMsgOpenToEncode(signInfo, CMSG_SIGNED, CMSG_DETACHED_FLAG, nil)
	if err != nil {
		t.Fatal(err)
	}

	fileName := "Win10_2004_Russian_x32.iso"

	//fi, err := os.Stat(fileName)
	//if err != nil {
	//	t.Fatal(err)
	//}

	//fiSize := fi.Size()
	//streamInfo, err := InitStreamInfo(nil, int(fiSize), "test_func")
	//if err != nil {
	//	t.Fatal(err)
	//}

	//msg, err := CryptMsgOpenToEncode(msgInfo, CMSG_ENVELOPED, streamInfo)
	//if err != nil {
	//	t.Fatal(err)
	//}

	chunkSize := 10 * 1024 * 1024
	buff := make([]byte, chunkSize)

	file, err := os.Open(fileName)
	if err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(file)
	final := 0
	for {
		n, err := reader.Read(buff)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}

		if n < chunkSize || err == io.EOF {
			final = 1
		}
		buff = buff[:n]

		errUpd := CryptMsgUpdate(msg, buff, final)
		if errUpd != nil {
			t.Fatal(errUpd)
		}
		if final == 1 {
			break
		}
	}
	err = file.Close()
	if err != nil {
		t.Fatal(err)
	}

	encBytes, err := CryptMsgGetParam(msg)
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile("test.sgn", encBytes, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = CryptMsgClose(msg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}
