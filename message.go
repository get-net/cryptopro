package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10 -lcades -lxades -lrdrsup
#include <stdlib.h>
#include <stdarg.h>
#include <cades.h>
#include <string.h>
#include "shim.h"

extern int getBytes(void* pvArg, char* pbdata, uint cbData, int final);
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"unsafe"
)

const (
	AT_KEYEXCHANGE = C.AT_KEYEXCHANGE
	AT_SIGNATURE   = C.AT_SIGNATURE
)

const (
	szOID_CP_GOST_28147        = C.szOID_CP_GOST_28147        // symmetric cipher
	szOID_CP_GOST_R3411        = C.szOID_CP_GOST_R3411        // cryptography hash
	szOID_CP_GOST_R3411_12_256 = C.szOID_CP_GOST_R3411_12_256 // digital sign for key length 256 bit
	szOID_CP_GOST_R3411_12_512 = C.szOID_CP_GOST_R3411_12_512 // digital sign for key length 512 bit
)

const (
	CMSG_DATA                 = C.CMSG_CAPILITE_DATA
	CMSG_ENVELOPED            = C.CMSG_ENVELOPED
	CMSG_HASHED               = C.CMSG_HASHED
	CMSG_SIGNED               = C.CMSG_SIGNED
	CMSG_SIGNED_AND_ENVELOPED = C.CMSG_SIGNED_AND_ENVELOPED
)

const (
	CMSG_BARE_CONTENT_FLAG = C.CMSG_BARE_CONTENT_FLAG
	CMSG_DETACHED_FLAG     = C.CMSG_DETACHED_FLAG
)
const (
	CMSG_CONTENT_PARAM          = C.CMSG_CONTENT_PARAM
	CMSG_CERT_PARAM             = C.CMSG_CERT_PARAM
	CMSG_SIGNER_CERT_INFO_PARAM = C.CMSG_SIGNER_CERT_INFO_PARAM
	CMSG_SIGNER_CERT_ID_PARAM   = C.CMSG_SIGNER_CERT_ID_PARAM
	CMSG_SIGNER_COUNT_PARAM     = C.CMSG_SIGNER_COUNT_PARAM
	CMSG_SIGNER_INFO_PARAM      = C.CMSG_SIGNER_INFO_PARAM
)

const (
	CMSG_TRUSTED_SIGNER_FLAG   = C.CMSG_TRUSTED_SIGNER_FLAG
	CMSG_SIGNER_ONLY_FLAG      = C.CMSG_SIGNER_ONLY_FLAG
	CMSG_USE_SIGNER_INDEX_FLAG = C.CMSG_USE_SIGNER_INDEX_FLAG
)

const (
	CMSG_CTRL_DECRYPT          = C.CMSG_CTRL_DECRYPT
	CMSG_CTRL_VERIFY_SIGNATURE = C.CMSG_CTRL_VERIFY_SIGNATURE
	CMSG_CTRL_VERIFY_HASH      = C.CMSG_CTRL_VERIFY_HASH
)

type CryptEncryptParams struct {
	cmsPara *C.CRYPT_ENCRYPT_MESSAGE_PARA
}

type CryptMsg struct {
	hCryptMsg *C.HCRYPTMSG
}

type SignerInfo struct {
	signer *C.CMSG_SIGNER_ENCODE_INFO
}

type msgEncodeInfo struct {
	envpEncodeInfo *C.CMSG_ENVELOPED_ENCODE_INFO
	signEncodeInfo *C.CMSG_SIGNED_ENCODE_INFO
}

type StreamInfo struct {
	streamInfo *C.CMSG_STREAM_INFO
}

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

func InitSignedInfo(cert *CertContext) (*msgEncodeInfo, error) {
	var signedEncodeInfo C.CMSG_SIGNED_ENCODE_INFO
	var signerEncodeInfo *C.CMSG_SIGNER_ENCODE_INFO

	if cert == nil {
		return nil, errors.New("cert context is nil")
	}

	prov, err := CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		return nil, err
	}

	p := *cert.pCertContext

	signerEncodeInfo = C.init_signer(p.pCertInfo, *prov.hCryptoProv, C.CString(szOID_CP_GOST_R3411_12_256))
	signedEncodeInfo.cbSize = C.sizeof_CMSG_SIGNED_ENCODE_INFO
	signedEncodeInfo.cSigners = 1
	signedEncodeInfo.rgSigners = signerEncodeInfo
	signedEncodeInfo.cCertEncoded = 1
	signedEncodeInfo.rgCertEncoded = cert.getCertBlob()
	signedEncodeInfo.rgCrlEncoded = nil

	return &msgEncodeInfo{signEncodeInfo: &signedEncodeInfo}, nil
}

var handle *os.File

func InitStreamInfo(streamFunc unsafe.Pointer, contentSize int) (*StreamInfo, error) {
	var streamInfo C.CMSG_STREAM_INFO
	var err error

	if streamFunc == nil {
		fmt.Println("use internal mock function")
		streamFunc = C.getBytes
		fmt.Printf("size %d\n", contentSize)
		handle, err = os.Create("test_stream.enc")
		if err != nil {
			fmt.Println("can't create file")
		}
	}

	streamInfo.cbContent = C.uint(contentSize)
	streamInfo.pfnStreamOutput = (C.PFN_CMSG_STREAM_OUTPUT)(streamFunc)
	streamInfo.pvArg = nil
	return &StreamInfo{streamInfo: &streamInfo}, nil
}

func CryptMsgOpenToEncode(msgEncodeInfo *msgEncodeInfo, msgType uint, flags uint, streamInfo *StreamInfo) (*CryptMsg, error) {
	var encodeInfo unsafe.Pointer
	var CstreamInfo *C.CMSG_STREAM_INFO = nil

	if msgType == CMSG_ENVELOPED {
		encodeInfo = unsafe.Pointer(msgEncodeInfo.envpEncodeInfo)
	}
	if msgType == CMSG_SIGNED {
		encodeInfo = unsafe.Pointer(msgEncodeInfo.signEncodeInfo)
	}

	if streamInfo != nil {
		if streamInfo.streamInfo != nil {
			CstreamInfo = streamInfo.streamInfo
		}
	}

	hMsg := C.CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING, C.uint(flags), C.uint(msgType),
		encodeInfo, nil, CstreamInfo)
	if hMsg == nil {
		return nil, fmt.Errorf("open message to encode failed, got error  0x%x\n", GetLastError())
	}
	return &CryptMsg{hCryptMsg: &hMsg}, nil
}

func CryptMsgOpenToDecode(prov *CryptoProv, msgType uint, flags uint, streamInfo *StreamInfo) (*CryptMsg, error) {
	var CstreamInfo *C.CMSG_STREAM_INFO = nil
	if streamInfo != nil && msgType != CMSG_HASHED {
		if streamInfo.streamInfo != nil {
			CstreamInfo = streamInfo.streamInfo
		}
	}

	hMsg := C.CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING, C.uint(flags), C.uint(msgType),
		*prov.hCryptoProv, nil, CstreamInfo)
	if hMsg == nil {
		return nil, fmt.Errorf("open message for decode failed, got error 0x%x\n", GetLastError())
	}
	return &CryptMsg{hCryptMsg: &hMsg}, nil
}

func CryptMsgUpdate(msg *CryptMsg, data []byte, final int) error {
	var status C.int
	if msg == nil {
		return errors.New("message not found")
	}
	if len(data) == 0 {
		status = C.CryptMsgUpdate(*msg.hCryptMsg, nil, 0, C.int(final))
	} else {
		size := len(data)
		status = C.CryptMsgUpdate(*msg.hCryptMsg, (*C.uchar)(&data[0]), C.uint(size), C.int(final))
	}
	if status == 0 {
		numErr := GetLastError()
		return fmt.Errorf("message update failed, got error 0x%x\n", numErr)
	}

	return nil
}

func CryptMsgGetParam(msg *CryptMsg, paramType uint, index uint) ([]byte, error) {
	var encLen C.uint

	status := C.CryptMsgGetParam(*msg.hCryptMsg, C.uint(paramType), C.uint(index), nil, &encLen)
	if status == 0 {
		numErr := GetLastError()
		return nil, fmt.Errorf("message length get failed, got error 0x%x\n", numErr)
	}

	enc := make([]byte, int(encLen))

	status = C.CryptMsgGetParam(*msg.hCryptMsg, C.uint(paramType), C.uint(index), unsafe.Pointer(&enc[0]), &encLen)
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

func CryptMsgControl(msg *CryptMsg, flags uint, ctrlType uint, cert *CertContext) (bool, error) {
	certContext := *cert.pCertContext

	status := C.CryptMsgControl(*msg.hCryptMsg, C.uint(flags), C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(certContext.pCertInfo))
	if status == 0 {
		return false, fmt.Errorf("can't msg control got error 0x%x", GetLastError())
	}

	return true, nil
}
