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
	"errors"
)


const (
	CALG_G28147 = C.CALG_G28147
)

const (
	CRYPT_EXPORTABLE = C.CRYPT_EXPORTABLE
)

const PUBLICKEYBLOB = C.PUBLICKEYBLOB

type PubKey struct {
	hCryptKey *C.HCRYPTKEY
}

type CryptoProv struct {
	hCryptoProv *C.HCRYPTPROV
}


func CryptImportPublicKeyInfoEx(prov *CryptoProv, context *CertContext) (*PubKey, error) {
	var pubKey C.HCRYPTKEY

	status := C.CryptImportPublicKeyInfoEx(*prov.hCryptoProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		&(*context.pCertContext).pCertInfo.SubjectPublicKeyInfo, 0, 0, nil, &pubKey)
	if status == 0 {
		return nil, errors.New("can't get public key from cert")
	}
	return &PubKey{hCryptKey: &pubKey}, nil
}

func CryptExportKey(pubKey *PubKey) (*[]byte, error) {
	var size C.uint
	status := C.CryptExportKey(*pubKey.hCryptKey, 0, PUBLICKEYBLOB, 0, nil, &size)
	print(status)
	if status == 0 {
		return nil, errors.New("can't export pubKey")
	}

	blob := make([]byte, size)
	status = C.CryptExportKey(*pubKey.hCryptKey, 0, PUBLICKEYBLOB, 0, (*C.uchar)(C.CBytes(blob)), &size)
	if status == 0 {
		return nil, errors.New("can't export pubKey")
	}

	return &blob, nil
}

func CryptGenKey(cryptoProv *CryptoProv, algo uint, flags uint) (*C.HCRYPTKEY, error) {
	var hKey C.HCRYPTKEY

	status := C.CryptGenKey(*cryptoProv.hCryptoProv, C.uint(algo), C.uint(flags), &hKey)
	if status == 0 {
		return nil, errors.New("can't generate key for encrypt")
	}

	return &hKey, nil
}


func CryptAcquireContext(container string) (*C.HCRYPTPROV, error) {
	var hProv C.HCRYPTPROV

	status := C.CryptAcquireContext(&hProv, C.CString(container), nil, PROV_GOST_2012_256, 0)
	if status == 0 {
		return nil, errors.New("can't acquire context")
	}

	return &hProv, nil
}

func CryptAquireCertificatePrivateKey(context *CertContext) (*CryptoProv, error) {

	var hProv C.HCRYPTPROV
	var dwKeySpec C.uint = 0
	var mustFree C.int = 0

	if context == nil {
		return nil, errors.New("content is null")
	}

	status := C.CryptAcquireCertificatePrivateKey(*context.pCertContext, 0, nil, &hProv, &dwKeySpec, &mustFree)
	if status == 0 {
		return nil, errors.New("can't acquire private key")
	}

	return &CryptoProv{&hProv}, nil
}
