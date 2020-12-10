package cryptopro

import (
	"fmt"
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
	fmt.Printf("got cert: %+v\n", cert)


	_, err = CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		t.Fatal(err)
	}

//	params, err := InitParams(hProv)

	fileName := "10.enc.mp3"
	chunkSize := 1024*1024
	fi, err := os.Stat(fileName)
	if err != nil {
		t.Fatal(err)
	}

	for

	//bytes, err := ioutil.ReadFile("store_test.go")

	file, err := os.Open("store_test.go")
	if err != nil {
		t.Fatal(err)
	}

	msgInfo, err := InitEncodeInfo(cert)
	if err != nil {
		t.Fatal(err)
	}

	fiSize := fi.Size()
	streamInfo, err := InitStreamInfo(nil, int(fiSize), "test_func")
	if err  != nil {
		t.Fatal(err)
	}


	msg, err := CryptMsgOpenToEncode(msgInfo, CMSG_ENVELOPED, streamInfo)
	if err != nil {
		t.Fatal(err)
	}

	part := make([]byte, fiSize/2)

	_, err = file.Read(part)
	if err != nil {
		t.Fatal(err)
	}

	err = CryptMsgUpdate(msg, part, 0)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("got %+v\n", part)

	//file.Seek(fiSize/2, 0)

	part2 := make([]byte, fiSize - fiSize/2)
	_, err = file.Read(part2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("got2 %+v\n", part2)
	encBytes, err := CryptMsgUpdate(msg, part2, 1)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%+v\n", encBytes)


	//err = ioutil.WriteFile("test.enc", encBytes, 0644)

	_, err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}