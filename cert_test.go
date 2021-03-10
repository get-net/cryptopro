package cryptopro

import (
	"testing"
)

func TestCertGetInfo(t *testing.T) {

	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "39da49123dbe70e953f394074d586eb692f3328e", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}

	notBefore := cert.getNotBefore()
	notAfter := cert.getNotAfter()
	t.Logf("NotBefore %s - NotAfter %s", notBefore, notAfter)

	sha1Hash := cert.getThumbprint()
	t.Logf("SHA1 Hash %s", sha1Hash)
	name := cert.getCertName()
	t.Logf(name)

	extLen := cert.getExtensionLen()

	for i := 0; i < extLen; i++ {
		test, err := cert.getExtension(i)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(test.getOID())
	}

	distPoint, err := cert.getExtensionByOid(X509_CRL_DIST_POINTS)
	if err != nil {
		t.Fatal(err)
	}
	crls, err := distPoint.getCrlDistPoints()
	if err != nil {
		t.Fatal(err)
	}

	for _, crl := range crls {
		t.Log(crl)
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
		//log.Print(ctx.getCertName())
		prevCtx = ctx
	}

	err = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG)
	if err != nil {
		t.Fatal(err)
	}
}
