package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10 -lcades -lxades -lrdrsup
#include <stdlib.h>
#include <stdarg.h>
#include <cades.h>
*/
import "C"
import "errors"

type CryptEncryptParams struct {
	cmsPara *C.CRYPT_ENCRYPT_MESSAGE_PARA
}

func CryptEncryptMessage(data []byte, params *CryptEncryptParams, certs []CertContext) ([]byte, error) {

	certLen := len(certs)
	dataLen := len(data)
	var bufLen C.uint = 0

	status := C.CryptEncryptMessage(params.cmsPara, certLen, &certs, (*C.uchar)(C.Cbytes(data)), dataLen, nil, &bufLen)
	if status == 0 {
		return nil, errors.New("Failed send")
	}

	return nil, nil
}
