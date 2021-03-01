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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	PUBLICKEYBLOB  = C.PUBLICKEYBLOB
	PRIVATEKEYBLOB = C.PRIVATEKEYBLOB
)

const (
	KP_ALGID  = C.KP_ALGID
	KP_KEYLEN = C.KP_KEYLEN
)

type Key struct {
	hCryptKey *C.HCRYPTKEY
	KeySpec   C.uint
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
		return nil, fmt.Errorf("can't acquire private key got error 0x%x", GetLastError())
	}

	return &CryptoProv{&hProv, dwKeySpec}, nil
}

func (k *Key) CryptGetKeyParam(paramType uint) (uint, error) {
	var size C.uint
	var val uint
	status := C.CryptGetKeyParam(*k.hCryptKey, C.uint(paramType), nil, &size, 0)
	if status == 0 {
		return 0, fmt.Errorf("can't acquire param from key got error 0x%x", GetLastError())
	}

	res := make([]byte, size)
	status = C.CryptGetKeyParam(*k.hCryptKey, C.uint(paramType), (*C.uchar)(&res[0]), &size, 0)
	if status == 0 {
		return 0, fmt.Errorf("can't acquire param from key got error 0x%x", GetLastError())
	}
	err := binary.Read(bytes.NewBuffer(res), binary.LittleEndian, &val)
	if err != nil {
		return 0, err
	}

	return val, nil
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

func CryptExportKey(key *Key, blobType uint) ([]byte, error) {
	var size C.uint
	status := C.CryptExportKey(*key.hCryptKey, 0, C.uint(blobType), 0, nil, &size)
	if status == 0 {
		return nil, fmt.Errorf("can't export keypubKey gpt error 0x%x", GetLastError())
	}

	blob := make([]byte, size)
	status = C.CryptExportKey(*key.hCryptKey, 0, C.uint(blobType), 0, (*C.uchar)(&blob[0]), &size)
	if status == 0 {
		return nil, fmt.Errorf("can't export keypubKey got error 0x%x", GetLastError())
	}

	return blob, nil
}

func CryptImportKey(prov *CryptoProv, keyBlob []byte) (*Key, error) {
	if prov == nil {
		return nil, errors.New("provider not found")
	}
	if len(keyBlob) == 0 {
		return nil, errors.New("blob should be greater than zero")
	}
	var hKey C.HCRYPTKEY

	status := C.CryptImportKey(*prov.hCryptoProv, (*C.uchar)(&keyBlob[0]), C.uint(len(keyBlob)), 0, 0, &hKey)
	if status == 0 {
		return nil, fmt.Errorf("can't import key got error 0x%x", GetLastError())
	}
	return &Key{hCryptKey: &hKey}, nil
}
