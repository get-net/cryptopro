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
	"unsafe"
)

const (
	CALG_GR3411_2012_256 = C.CALG_GR3411_2012_256
	CALG_GR3411_2012_512 = C.CALG_GR3411_2012_512
	CALG_GR3411          = C.CALG_GR3411
)

const (
	HP_HASHVAL  = C.HP_HASHVAL
	HP_HASHSIZE = C.HP_HASHSIZE
)

type CryptoHash struct {
	hHash *C.HCRYPTHASH
}

func CreateCryptHash(hProv *CryptoProv, algo uint) (*CryptoHash, error) {
	var hHash C.HCRYPTHASH

	status := C.CryptCreateHash(*hProv.hCryptoProv, C.uint(algo), 0, 0, &hHash)
	if status == 0 {
		lastError := GetLastError()
		return nil, fmt.Errorf("can't get hash got error 0x%x", lastError)
	}

	return &CryptoHash{hHash: &hHash}, nil
}

func (hHash CryptoHash) CryptHashData(data []byte) error {
	size := len(data)
	if size == 0 {
		return errors.New("data can't be empty")
	}
	status := C.CryptHashData(*hHash.hHash, (*C.uchar)(C.CBytes(data)), C.uint(size), 0)
	if status == 0 {
		return fmt.Errorf("can't hash data got error 0x%x", GetLastError())
	}
	return nil
}

func (hHash CryptoHash) CryptGetHashParam() ([]byte, error) {
	var size C.uint
	var hashSize C.uint = C.sizeof_uint

	status := C.CryptGetHashParam(*hHash.hHash, HP_HASHSIZE, (*C.uchar)(unsafe.Pointer(&size)), &hashSize, 0)
	if status == 0 {
		return nil, fmt.Errorf("can't get hash size got error 0x%x", GetLastError())
	}

	value := make([]byte, size)
	status = C.CryptGetHashParam(*hHash.hHash, HP_HASHVAL, (*C.uchar)(&value[0]), &size, 0)
	if status == 0 {
		return nil, fmt.Errorf("can't get hash value got error 0x%x", GetLastError())
	}

	return value, nil
}

func (hHash CryptoHash) DestoryHash() error {
	status := C.CryptDestroyHash(*hHash.hHash)
	if status == 0 {
		return fmt.Errorf("can't destroy hash got error 0x%x", GetLastError())
	}
	return nil
}
