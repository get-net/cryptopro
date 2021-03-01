package cryptopro

import (
	"bufio"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestCryptEncryptMessage(t *testing.T) {
	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}

	msgInfo, err := InitEncodeInfo(cert)
	if err != nil {
		t.Fatal(err)
	}

	fileName := "store_test.go"

	fi, err := os.Stat(fileName)
	if err != nil {
		t.Fatal(err)
	}

	fiSize := fi.Size()
	streamInfo, err := InitStreamInfo(nil, int(fiSize))
	if err != nil {
		t.Fatal(err)
	}

	msg, err := CryptMsgOpenToEncode(msgInfo, CMSG_ENVELOPED, 0, streamInfo)
	if err != nil {
		t.Fatal(err)
	}

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

	err = CryptMsgClose(msg)
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCryptSignMessage(t *testing.T) {
	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got cert\n issuer: %s\n subject: %s\n", cert.Issuer, cert.Subject)

	_, err = CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		t.Fatal(err)
	}

	signInfo, err := InitSignedInfo(cert)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := CryptMsgOpenToEncode(signInfo, CMSG_SIGNED, CMSG_DETACHED_FLAG, nil)
	if err != nil {
		t.Fatal(err)
	}

	fileName := "store_test.go"

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

	encBytes, err := CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0)
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile("store_test.go.sgn", encBytes, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = CryptMsgClose(msg)
	if err != nil {
		t.Fatal(err)
	}

	decBytes, err := ioutil.ReadFile("store_test.go.sgn")
	if err != nil {
		t.Fatal(err)
	}

	prov, err := CryptAcquireContext("", CRYPT_VERIFYCONTEXT)
	if err != nil {
		t.Fatal(err)
	}

	decMsg, err := CryptMsgOpenToDecode(prov, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = CryptMsgUpdate(decMsg, decBytes, 1)
	if err != nil {
		t.Fatal(err)
	}

	//_, err = CryptMsgGetParam(decMsg, CMSG_CONTENT_PARAM, 0)
	//if err != nil {
	//	t.Fatal(err)
	//}

	data, err := CryptMsgGetParam(decMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0)
	if err != nil {
		t.Fatal(err)
	}

	checkStore, err := CertMsgOpenStore(decMsg, prov)
	if err != nil {
		t.Fatal(err)
	}

	checkCert, err := CertGetSubjectCertificateFromStore(checkStore, data)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(checkCert.getCertName())

	status, err := CryptMsgControl(decMsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, checkCert)
	if err != nil {
		t.Fatal(err)
	}

	if status {
		t.Log("Signature verified")
	}

	err = ioutil.WriteFile("signer.crt", data, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = CryptMsgClose(decMsg)
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCryptVerifyMessage(t *testing.T) {
	decBytes, err := ioutil.ReadFile("message_test.go.der.sgn")
	if err != nil {
		t.Fatal(err)
	}

	prov, err := CryptAcquireContext("", CRYPT_VERIFYCONTEXT)
	if err != nil {
		t.Fatal(err)
	}

	decMsg, err := CryptMsgOpenToDecode(prov, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = CryptMsgUpdate(decMsg, decBytes, 1)
	if err != nil {
		t.Fatal(err)
	}

	data, err := CryptMsgGetParam(decMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0)
	if err != nil {
		t.Fatal(err)
	}

	checkStore, err := CertMsgOpenStore(decMsg, prov)
	if err != nil {
		t.Fatal(err)
	}

	checkCert, err := CertGetSubjectCertificateFromStore(checkStore, data)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(checkCert.getCertName())

	status, err := CryptMsgControl(decMsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, checkCert)
	if err != nil {
		t.Fatal(err)
	}

	if status {
		t.Log("Signature verified")
	}

	err = ioutil.WriteFile("signer.crt", data, 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = CryptMsgClose(decMsg)
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(checkStore, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}
