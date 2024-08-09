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
	Document       []byte
	ErrorCode      int
	CryptoProError int
}

const (
	XML_SIGNING_NO_ERROR                          = 0
	XML_SIGNING_FAILED_TO_OPEN_SYSTEM_STORE_ERROR = 1001
	XML_SIGNING_CERT_NOT_FOUND_ERROR              = 1002
	XML_SIGNING_FAILED_TO_SIGN_ERROR              = 1003
	XML_SIGNING_FAILED_TO_ALLOCATE_OUTPUT         = 1004

	XML_XADES_SIGNATURE_TYPE_ENVELOPED  uint32 = 0x00
	XML_XADES_SIGNATURE_TYPE_ENVELOPING uint32 = 0x01
	XML_XADES_SIGNATURE_TYPE_TEMPLATE   uint32 = 0x02
	XADES_DEFAULT                       uint32 = 0x00000010
	XADES_BES                           uint32 = 0x00000020
	XADES_T                             uint32 = 0x00000050
	XADES_X_LONG_TYPE_1                 uint32 = 0x000005d0
	XADES_A                             uint32 = 0x000007d0
	XADES_XMLDSIG                       uint32 = 0x00000000
	XADES_NONE                          uint32 = 0xf0000000
)

func ParseXMLSigningResult(cResult C.struct_XMLSigningResult) (result XMLSigningResult) {
	result.ErrorCode = int(cResult.error_code)
	result.CryptoProError = int(cResult.crypto_pro_error)
	if result.ErrorCode == XML_SIGNING_NO_ERROR {
		result.Document = C.GoBytes(unsafe.Pointer(cResult.document), C.int(cResult.document_size))
	}

	return
}

func freeSignedDocument(cResult C.struct_XMLSigningResult) {
	C.free(unsafe.Pointer(cResult.document))
}

type SignatureInfo struct {
	Document      []byte
	XPath         string
	Thumbprint    string
	SignatureType uint32
}

func SignXML(info SignatureInfo) ([]byte, error) {
	cDocument := C.CString(string(info.Document))
	defer C.free(unsafe.Pointer(cDocument))

	cThumbprint := C.CString(info.Thumbprint)
	defer C.free(unsafe.Pointer(cThumbprint))

	cXpath := (*C.char)(C.NULL)
	if len(info.XPath) > 0 {
		cXpath = C.CString(info.XPath)
		defer C.free(unsafe.Pointer(cXpath))
	}

	cSignatureType := (C.DWORD)(info.SignatureType)

	// signing the document
	cResult := C.sign_xml(cDocument, cXpath, cSignatureType, cThumbprint)

	result := ParseXMLSigningResult(cResult)

	switch result.ErrorCode {
	case XML_SIGNING_NO_ERROR:
		defer freeSignedDocument(cResult)

		return result.Document, nil
	case XML_SIGNING_FAILED_TO_OPEN_SYSTEM_STORE_ERROR:
		return nil, fmt.Errorf("failed to open system store: 0x%08x", result.CryptoProError)
	case XML_SIGNING_CERT_NOT_FOUND_ERROR:
		return nil, errors.New("cert not found")
	case XML_SIGNING_FAILED_TO_SIGN_ERROR:
		return nil, fmt.Errorf("failed to sign: 0x%08x", result.CryptoProError)
	case XML_SIGNING_FAILED_TO_ALLOCATE_OUTPUT:
		return nil, errors.New("failed to allocate output")
	default:
		return nil, fmt.Errorf("unknwon error code: %d", result.ErrorCode)
	}
}
