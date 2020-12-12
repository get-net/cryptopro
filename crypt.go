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

type CryptoProv struct {
	hCryptoProv *C.HCRYPTPROV
}

func GetLastError() int {
	return int(C.GetLastError())
}

func CryptImportPublicKeyInfoEx(prov *CryptoProv, context *CertContext) (*Key, error) {
	var pubKey C.HCRYPTKEY

	status := C.CryptImportPublicKeyInfoEx(*prov.hCryptoProv, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
		&(*context.pCertContext).pCertInfo.SubjectPublicKeyInfo, 0, 0, nil, &pubKey)
	if status == 0 {
		return nil, errors.New("can't get public key from cert")
	}
	return &Key{hCryptKey: &pubKey}, nil
}

func CryptAcquireContext(container string) (*C.HCRYPTPROV, error) {
	var hProv C.HCRYPTPROV

	status := C.CryptAcquireContext(&hProv, C.CString(container), nil, PROV_GOST_2012_256, 0)
	if status == 0 {
		return nil, errors.New("can't acquire context")
	}

	return &hProv, nil
}
