package cryptopro

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestCertGetIssuer(t *testing.T) {
	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}

	issuerStr := cert.GetIssuer()

	accessInfo, err := cert.GetExtensionByOid(SzOID_AUTHORITY_INFO_ACCESS)
	if err != nil {
		t.Fatal(err)
	}

	authInfoAccess, err := accessInfo.GetAuthorityInfoAccess()
	if err != nil {
		t.Fatal(err)
	}

	var certUrl string

	for _, info := range authInfoAccess {
		t.Log("Got Info Access", info.Oid, info.Info)
		if info.Oid == "1.3.6.1.5.5.7.48.2" {
			certUrl = info.Info
		}
	}

	if certUrl != "" {
		resp, err := http.Get(certUrl)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		issuerCert, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		context, err := CertAddEncodedCertificateToStore(store, issuerCert, CERT_STORE_ADD_NEW)
		defer CertFreeCertificateContext(context)
		if err != nil {
			t.Fatal(err)
		}

	}

	t.Logf("Search issuer %s", issuerStr)
	issuerCert, err := CertFindCertificateInStore(store, issuerStr, CERT_FIND_SUBJECT_STR)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Got issuer cert %s", issuerCert.GetCertName())

	err = CertFreeCertificateContext(cert)
	if err != nil {
		t.Fatal(err)
	}

	err = CertFreeCertificateContext(issuerCert)
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertGetInfo(t *testing.T) {

	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}

	notBefore := cert.GetNotBefore()
	notAfter := cert.GetNotAfter()
	t.Logf("NotBefore %s - NotAfter %s", notBefore, notAfter)

	sha1Hash := cert.GetThumbprint()
	t.Logf("SHA1 Hash %s", sha1Hash)
	name := cert.GetCertName()
	t.Logf(name)
	issuer := cert.GetIssuer()
	t.Logf(issuer)

	serialNumber := cert.GetSerialNumber()
	t.Logf("Serial Number 0x%s", hex.EncodeToString(serialNumber))

	blob := cert.GetEncodedCert()
	if blob != nil {
		err := ioutil.WriteFile(fmt.Sprintf("%s.crt", sha1Hash), blob, 0644)
		if err != nil {
			t.Fatal(err)
		}
	}

	extLen := cert.GetExtensionLen()

	for i := 0; i < extLen; i++ {
		test, err := cert.GetExtension(i)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(test.GetOID())
	}

	distPoint, err := cert.GetExtensionByOid(SzOID_CRL_DIST_POINTS)
	if err != nil {
		t.Fatal(err)
	}
	crls, err := distPoint.GetCrlDistPoints()
	if err != nil {
		t.Fatal(err)
	}

	for _, crl := range crls {
		t.Log(crl)
	}

	accessInfo, err := cert.GetExtensionByOid(SzOID_AUTHORITY_INFO_ACCESS)
	if err != nil {
		t.Fatal(err)
	}

	authInfoAccess, err := accessInfo.GetAuthorityInfoAccess()
	if err != nil {
		t.Fatal(err)
	}

	for _, info := range authInfoAccess {
		t.Log("Got Info Access", info.Oid, info.Info)
	}

	err = CertFreeCertificateContext(cert)
	if err != nil {
		t.Fatal(err)
	}

	var prevCtx *CertContext
	for {
		ctx, err := CertEnumCertificatesInStore(store, prevCtx)
		if err == CRYPT_E_NOT_FOUND {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		//log.Print(ctx.GetCertName())
		prevCtx = ctx
	}

	err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCryptImportPublicKeyInfo(t *testing.T) {
	prov, err := CryptAcquireContext("", "", PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)
	if err != nil {
		t.Fatal(err)
	}

	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cert.CryptImportPublicKeyInfo(prov)
	if err != nil {
		t.Fatal(err)
	}

	err = CertFreeCertificateContext(cert)
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}

	err = prov.Release()
	if err != nil {
		t.Fatal(err)
	}
}
