package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10 -lcades -lxades -lrdrsup
#include <stdlib.h>
#include <stdarg.h>
#include <cades.h>
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"unsafe"
)

const (
	CERT_SIMPLE_NAME_STR = C.CERT_SIMPLE_NAME_STR
	CERT_OID_NAME_STR = C.CERT_OID_NAME_STR
	CERT_X500_NAME_STR = C.CERT_X500_NAME_STR
)

const (
	X509_ASN_ENCODING = C.X509_ASN_ENCODING
	PKCS_7_ASN_ENCODING = C.PKCS_7_ASN_ENCODING
)

const (
	CERT_KEY_PROV_INFO_PROP_ID = C.CERT_KEY_PROV_INFO_PROP_ID
)

type CertStore struct {
	HCertStore C.HCERTSTORE
}

type CertContext struct {
	Issuer string
	Subject string
	SHA1Hash string
	pCertContext *C.PCCERT_CONTEXT
}

func CertNameToStr(nameBlob C.PCERT_NAME_BLOB, flag int) (*string, error) {
	size := C.CertNameToStr(X509_ASN_ENCODING, nameBlob, C.uint(flag), nil, 0)

	n := C.CString(string(make([]byte, size)))
	defer C.free(unsafe.Pointer(n))
	count := C.CertNameToStr(X509_ASN_ENCODING, nameBlob, C.uint(flag), n, size)
	if count == 0 {
		return nil, errors.New("can't convert name_blob to string")
	}

	name := C.GoString(n)
	return &name, nil
}

func CertCreateCertificateContext(data []byte) (*CertContext, error) {
	size := len(data)
	p := C.CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,(*C.uchar)(C.CBytes(data)),C.uint(size))
	if p == nil {
		return nil, errors.New("can't create cert context")
	}

	return &CertContext{pCertContext: &p}, nil
}

func CertFindCertificateInStore(store *CertStore, searchParam string, findType uint) (*CertContext, error) {

	if store == nil {
		return nil, errors.New("store is nil")
	}

	var hash C.CRYPT_INTEGER_BLOB

	hashBytes, err := hex.DecodeString(searchParam)
	if err != nil {
		return nil, err
	}

	hash.cbData = C.uint(len(hashBytes))
	hash.pbData = (*C.uchar)(C.CBytes(hashBytes))

	if err != nil {
		return nil, err
	}

	p := C.CertFindCertificateInStore(store.HCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
		C.uint(findType), unsafe.Pointer(&hash), nil)
	if p == nil {
		return nil, errors.New("certificate not found")
	}

	issuer, err := CertNameToStr(&p.pCertInfo.Issuer, CERT_X500_NAME_STR)
	if err != nil {
		return nil, err
	}
	subject, err := CertNameToStr(&p.pCertInfo.Subject, CERT_X500_NAME_STR)
	if err != nil {
		return nil, err
	}

	return &CertContext{
		Issuer: *issuer,
		Subject: *subject,
		SHA1Hash: searchParam,
		pCertContext: &p,
	}, nil
}
