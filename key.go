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
	"fmt"
)

const (
	PUBLICKEYBLOB  = C.PUBLICKEYBLOB
	PRIVATEKEYBLOB = C.PRIVATEKEYBLOB
)

type Key struct {
	hCryptKey *C.HCRYPTKEY
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
		lastError := GetLastError()
		return nil, fmt.Errorf("can't acquire private key got error 0x%x", lastError)
	}

	return &CryptoProv{&hProv}, nil
}

func CryptGenKey(cryptoProv *CryptoProv, algo uint, flags uint) (*C.HCRYPTKEY, error) {
	var hKey C.HCRYPTKEY

	status := C.CryptGenKey(*cryptoProv.hCryptoProv, C.uint(algo), C.uint(flags), &hKey)
	if status == 0 {
		return nil, fmt.Errorf("can't generate key get error 0x%x", GetLastError())
	}

	return &hKey, nil
}

func CryptGetUserKey(prov *CryptoProv, keySpec uint) (*Key, error) {
	var phUserKey C.HCRYPTKEY
	status := C.CryptGetUserKey(*prov.hCryptoProv, C.uint(keySpec), &phUserKey)
	if status == 0 {
		return nil, fmt.Errorf("can't get key got error 0x%x", GetLastError())
	}
	return &Key{hCryptKey: &phUserKey}, nil
}

func CryptExportKey(key *Key, blobType uint) (*[]byte, error) {
	var size C.uint
	status := C.CryptExportKey(*key.hCryptKey, 0, C.uint(blobType), 0, nil, &size)
	print(status)
	if status == 0 {
		return nil, errors.New("can't export keypubKey")
	}

	blob := make([]byte, size)
	status = C.CryptExportKey(*key.hCryptKey, 0, C.uint(blobType), 0, (*C.uchar)(&blob[0]), &size)
	if status == 0 {
		return nil, fmt.Errorf("can't export keypubKey got error 0x%x", GetLastError())
	}

	return &blob, nil
}
