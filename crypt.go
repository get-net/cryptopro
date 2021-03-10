package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10
#include <stdlib.h>
#include <stdarg.h>
#include <CSP_WinCrypt.h>
#include <WinCryptEx.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"strconv"
)

const (
	CALG_G28147 = C.CALG_G28147
)

const (
	CRYPT_EXPORTABLE    = C.CRYPT_EXPORTABLE
	CRYPT_VERIFYCONTEXT = C.CRYPT_VERIFYCONTEXT
)

var CRYPT_E_STREAM_MSG_NOT_READY = errors.New("CRYPT_E_STREAM_MSG_NOT_READY")
var CRYPT_E_NOT_FOUND = errors.New("CRYPT_E_NOT_FOUND")

var winAPIErrors = map[int]error{
	0x80091010: CRYPT_E_STREAM_MSG_NOT_READY,
	0x80092004: CRYPT_E_NOT_FOUND,
}

type CryptoProv struct {
	hCryptoProv *C.HCRYPTPROV
	KeySpec     C.uint
}

func GetLastError() error {
	codeError := int(C.GetLastError())
	err := winAPIErrors[codeError]
	if err == nil {
		err = errors.New(strconv.Itoa(codeError))
	}
	return err
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

func CryptAcquireContext(container string, provName string, provType uint, flags uint) (*CryptoProv, error) {
	var hProv C.HCRYPTPROV

	var cont *C.char = nil
	if container != "" {
		cont = C.CString(container)
	}

	var prov *C.char = nil
	if provName != "" {
		prov = C.CString(provName)
	}

	status := C.CryptAcquireContext(&hProv, cont, prov, C.uint(provType), C.uint(flags))
	if status == 0 {
		return nil, fmt.Errorf("can't acquire context got error 0x%x", GetLastError())
	}

	return &CryptoProv{hCryptoProv: &hProv}, nil
}
