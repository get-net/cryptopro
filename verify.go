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

func CryptVerifySignature(hHash *CryptoHash, signature []byte, pubKey *Key, flags uint) (bool, error) {
	if hHash == nil {
		return false, errors.New("hHash can't be nil")
	}

	if len(signature) == 0 {
		return false, errors.New("signature length should be greater zero")
	}

	status := C.CryptVerifySignature(*hHash.hHash, (*C.uchar)(&signature[0]), C.uint(len(signature)), *pubKey.hCryptKey, nil, C.uint(flags))
	if status == 0 {
		return false, fmt.Errorf("can't verify hash got error 0x%x", GetLastError())
	}

	return true, nil
}
