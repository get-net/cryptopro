package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki -I/opt/cprocsp/include/reader
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10
#include "sgnmsg.h"
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

func SignMessageCadesBes(certContext *CertContext, detached bool, data []byte) ([]byte, error) {
	dwFlag := C.uint(0)
	if detached {
		dwFlag = C.CMSG_DETACHED_FLAG
	}

	cMsg := (*C.uchar)(C.CBytes(data))
	defer C.free(unsafe.Pointer(cMsg))

	cOut := C.malloc(C.sizeof_char * 102400)
	defer C.free(unsafe.Pointer(cOut))

	size := C.int(0)

	p := *certContext.pCertContext

	errorCode := C.sign_message_cades_bes(p, dwFlag, cMsg, (*C.char)(cOut), &size)
	out := C.GoBytes(cOut, size)
	if errorCode != 0 {
		return nil, errors.New(string(out))
	}

	return out, nil
}

func SignMessageCadesBesCOnly(thumbprint string, detached bool, data []byte) ([]byte, error) {
	dwFlag := C.uint(0)
	if detached {
		dwFlag = C.CMSG_DETACHED_FLAG
	}

	hashBytes, err := hex.DecodeString(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("decode hex string: %w", err)
	}

	cThumbprint := (*C.uchar)(C.CBytes(hashBytes))
	defer C.free(unsafe.Pointer(cThumbprint))

	cMsg := (*C.uchar)(C.CBytes(data))
	defer C.free(unsafe.Pointer(cMsg))

	cOut := C.malloc(C.sizeof_char * 102400)
	defer C.free(unsafe.Pointer(cOut))

	size := C.int(0)

	errorCode := C.sign_message_cades_bes_c_only(cThumbprint, dwFlag, cMsg, (*C.char)(cOut), &size)
	out := C.GoBytes(cOut, size)
	if errorCode != 0 {
		return nil, errors.New(string(out))
	}

	return out, nil
}
