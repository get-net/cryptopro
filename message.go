package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10 -lcades -lxades -lrdrsup
#include <stdlib.h>
#include <stdarg.h>
#include <cades.h>

extern int getBytes(void*,char*,uint,int);
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"unsafe"
)

const szOID_CP_GOST_28147 = C.szOID_CP_GOST_28147

const (
	CMSG_BARE_CONTENT_FLAG = C.CMSG_BARE_CONTENT_FLAG
	CMSG_DETACHED_FLAG     = C.CMSG_DETACHED_FLAG
	CMSG_CONTENT_PARAM     = C.CMSG_CONTENT_PARAM
)

const (
	CMSG_DATA      = C.CMSG_CAPILITE_DATA
	CMSG_SIGNED    = C.CMSG_SIGNED
	CMSG_ENVELOPED = C.CMSG_ENVELOPED
	CMSG_HASHED    = C.CMSG_HASHED
)

type CryptEncryptParams struct {
	cmsPara *C.CRYPT_ENCRYPT_MESSAGE_PARA
}

type CryptMsg struct {
	hCryptMsg *C.HCRYPTMSG
}

type msgEncodeInfo struct {
	envpEncodeInfo *C.CMSG_ENVELOPED_ENCODE_INFO
}

type StreamInfo struct {
	streamInfo *C.CMSG_STREAM_INFO
}

func InitParams(hProv *CryptoProv) (*CryptEncryptParams, error) {
	var encryptParams C.CRYPT_ENCRYPT_MESSAGE_PARA
	var encryptAlgorithm C.CRYPT_ALGORITHM_IDENTIFIER

	if hProv == nil {
		return nil, errors.New("crypto prov is nil")
	}
	encryptAlgorithm.pszObjId = C.CString(szOID_CP_GOST_28147)

	encryptParams.cbSize = C.sizeof_CRYPT_ENCRYPT_MESSAGE_PARA
	encryptParams.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING
	encryptParams.hCryptProv = *hProv.hCryptoProv
	encryptParams.ContentEncryptionAlgorithm = encryptAlgorithm

	return &CryptEncryptParams{cmsPara: &encryptParams}, nil
}

func InitEncodeInfo(cert *CertContext) (*msgEncodeInfo, error) {
	var envpEncodeInfo C.CMSG_ENVELOPED_ENCODE_INFO
	var encryptAlgorithm C.CRYPT_ALGORITHM_IDENTIFIER

	if cert == nil {
		return nil, errors.New("cert context is nil")
	}
	encryptAlgorithm.pszObjId = C.CString(szOID_CP_GOST_28147)

	p := *cert.pCertContext
	envpEncodeInfo.cbSize = C.sizeof_CMSG_ENVELOPED_ENCODE_INFO
	envpEncodeInfo.hCryptProv = 0
	envpEncodeInfo.ContentEncryptionAlgorithm = encryptAlgorithm
	envpEncodeInfo.pvEncryptionAuxInfo = nil
	envpEncodeInfo.cRecipients = 1
	envpEncodeInfo.rgpRecipients = &p.pCertInfo

	return &msgEncodeInfo{envpEncodeInfo: &envpEncodeInfo}, nil
}

var handle *os.File

//export getBytes
func getBytes(pvArg unsafe.Pointer, pbData *C.char, cbData C.uint, final C.int) C.int {

	//	file := C.GoString((*C.char)(pvArg))
	test := C.GoBytes(unsafe.Pointer(pbData), C.int(cbData))
	handle.Write(test)
	if final != 1 {
		fmt.Println("New run ===")
		//		fmt.Printf("got file %s\n", file)
		//		fmt.Printf("got len %d\n", cbData)
		//		fmt.Printf("got bytes %+v\n", test)
	} else {
		fmt.Println("End file ===")
		handle.Close()
	}
	fmt.Printf("got final %d\n", final)
	return 1
}

func InitStreamInfo(streamFunc unsafe.Pointer, contentSize int, fileName string) (*StreamInfo, error) {
	var streamInfo C.CMSG_STREAM_INFO
	var err error

	if streamFunc == nil {
		fmt.Println("use internal mock function")
	}

	fmt.Printf("size %d\n", contentSize)
	handle, err = os.Create("test_stream.enc")
	if err != nil {
		fmt.Println("can't create file")
	}
	streamInfo.cbContent = C.uint(contentSize)
	streamInfo.pfnStreamOutput = (C.PFN_CMSG_STREAM_OUTPUT)(C.getBytes)
	streamInfo.pvArg = unsafe.Pointer(C.CString(fileName))
	return &StreamInfo{streamInfo: &streamInfo}, nil
}

func CryptMsgOpenToEncode(msgEncodeInfo *msgEncodeInfo, msgType uint, streamInfo *StreamInfo) (*CryptMsg, error) {
	hMsg := C.CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING, 0, C.uint(msgType),
		unsafe.Pointer(msgEncodeInfo.envpEncodeInfo), nil, streamInfo.streamInfo)
	if hMsg == nil {
		codeError := GetLastError()
		return nil, fmt.Errorf("open message to encode failed, got error  0x%x\n", codeError)
	}
	return &CryptMsg{hCryptMsg: &hMsg}, nil
}

func CryptMsgUpdate(msg *CryptMsg, data []byte, final int) error {

	if msg == nil {
		return errors.New("message not found")
	}
	if len(data) == 0 {
		return errors.New("data is empty")
	}

	size := len(data)
	status := C.CryptMsgUpdate(*msg.hCryptMsg, (*C.uchar)(&data[0]), C.uint(size), C.int(final))
	if status == 0 {
		numErr := GetLastError()
		return fmt.Errorf("message update failed, got error 0x%x\n", numErr)
	}

	return nil
}

func CryptMsgGetParam(msg *CryptMsg) ([]byte, error) {
	var encLen C.uint

	status := C.CryptMsgGetParam(*msg.hCryptMsg, CMSG_CONTENT_PARAM, 0, nil, &encLen)
	if status == 0 {
		numErr := GetLastError()
		return nil, fmt.Errorf("message length get failed, got error 0x%x\n", numErr)
	}

	enc := make([]byte, int(encLen))

	status = C.CryptMsgGetParam(*msg.hCryptMsg, CMSG_CONTENT_PARAM, 0, unsafe.Pointer(&enc[0]), &encLen)
	if status == 0 {
		numErr := GetLastError()
		return nil, fmt.Errorf("message get failed, got error 0x%x\n", numErr)
	}
	return enc, nil
}

func CryptMsgClose(msg *CryptMsg) error {
	status := C.CryptMsgClose(*msg.hCryptMsg)
	if status == 0 {
		return errors.New("can't close message")
	}
	return nil
}

func CryptEncryptMessage(params *CryptEncryptParams, cert *CertContext, data []byte) ([]byte, error) {
	dataLen := len(data)
	var bufLen C.uint = 0

	status := C.CryptEncryptMessage(params.cmsPara, 1, cert.pCertContext, (*C.uchar)(&data[0]), C.uint(dataLen), nil, &bufLen)
	if status == 0 {
		return nil, errors.New("failed encrypt message")
	}

	message := make([]byte, bufLen)
	status = C.CryptEncryptMessage(params.cmsPara, 1, cert.pCertContext, (*C.uchar)(&data[0]), C.uint(dataLen),
		(*C.uchar)(&message[0]), &bufLen)
	if status == 0 {
		return nil, errors.New("failed encrypt message")
	}

	return message, nil
}
