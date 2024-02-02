package cryptopro

/*
#cgo CFLAGS: -Wdeprecated-declarations -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I. -I/opt/cprocsp/include/cpcsp -I/usr/lib/ -I/opt/cprocsp/include/ -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -L/usr/lib/ -lxades -lcapi20 -lcapi10
#include "sign_xml.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

type XMLSigningResult struct {
	Document  []byte
	ErrorCode int
}

const (
	XML_SIGNING_NO_ERROR                          = 0
	XML_SIGNING_FAILED_TO_OPEN_SYSTEM_STORE_ERROR = 1001
	XML_SIGNING_CERT_NOT_FOUND_ERROR              = 1002
	XML_SIGNING_FAILED_TO_SIGN_ERROR              = 1003
	XML_SIGNING_FAILED_TO_ALLOCATE_OUTPUT         = 1004
)

func ParseXMLSigningResult(cResult C.struct_XMLSigningResult) (result XMLSigningResult) {
	result.ErrorCode = int(cResult.error_code)
	if result.ErrorCode == XML_SIGNING_NO_ERROR {
		result.Document = C.GoBytes(unsafe.Pointer(cResult.document), C.int(cResult.document_size))
	}

	return
}

func freeSignedDocument(cResult C.struct_XMLSigningResult) {
	C.free(unsafe.Pointer(cResult.document))
}

func SignXML(document []byte, thumbprint string) ([]byte, error) {
	// converting data to C-compatible structures
	// TODO: use a pointer to the first byte of the document in order to avoid double copying
	cDocument := C.CString(string(document))
	defer C.free(unsafe.Pointer(cDocument))

	cThumbprint := C.CString(thumbprint)
	defer C.free(unsafe.Pointer(cThumbprint))

	// signing the document
	cResult := C.sign_xml(cDocument, cThumbprint)

	result := ParseXMLSigningResult(cResult)

	switch result.ErrorCode {
	case XML_SIGNING_NO_ERROR:
		defer freeSignedDocument(cResult)

		return result.Document, nil
	case XML_SIGNING_FAILED_TO_OPEN_SYSTEM_STORE_ERROR:
		return nil, errors.New("failed to open system store")
	case XML_SIGNING_CERT_NOT_FOUND_ERROR:
		return nil, errors.New("cert not found")
	case XML_SIGNING_FAILED_TO_SIGN_ERROR:
		return nil, errors.New("failed to sign")
	case XML_SIGNING_FAILED_TO_ALLOCATE_OUTPUT:
		return nil, errors.New("failed to allocate output")
	default:
		return nil, fmt.Errorf("unknwon error code: %d", result.ErrorCode)
	}
}
