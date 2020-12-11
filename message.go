package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10 -lcades -lxades -lrdrsup
#include <stdlib.h>
#include <stdarg.h>
#include <cades.h>
#include <string.h>

CERT_BLOB* get_blob(PCCERT_CONTEXT cert) {
	CERT_BLOB* blob = malloc(sizeof(CERT_BLOB));

	blob->cbData = cert->cbCertEncoded;
	blob->pbData = cert->pbCertEncoded;

	return blob;
}


CMSG_SIGNER_ENCODE_INFO* init_signer(PCERT_INFO cert_info, HCRYPTPROV h_crypt_prov, char* hash_algo) {
	CMSG_SIGNER_ENCODE_INFO* signer;
	CRYPT_ALGORITHM_IDENTIFIER *hash_ident;

	hash_ident = malloc(sizeof(CRYPT_ALGORITHM_IDENTIFIER));
	memset(hash_ident, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
	hash_ident->pszObjId = hash_algo;

	signer = malloc(sizeof(CMSG_SIGNER_ENCODE_INFO));
	memset(signer, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
	signer->cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
	signer->pCertInfo = cert_info;
	signer->hCryptProv = h_crypt_prov;
	signer->HashAlgorithm = *hash_ident;
	signer->dwKeySpec = AT_KEYEXCHANGE;
	signer->pvHashAuxInfo = NULL;

	return signer;
}
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
	var certBlob *C.CERT_BLOB
	//var hKey C.HCRYPTKEY
	//var keyLen C.uint

	if cert == nil {
		return nil, errors.New("cert context is nil")
	}

	prov, err := CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		return nil, err
	}

	p := *cert.pCertContext
	//status := C.CryptUserKey(prov, AT_SIGNATURE, hKey)
	//if status == 0 {
	//	lastError := GetLastError()
	//	return nil, fmt.Errorf("Can't get public key. Got error 0x%x\n", lastError)
	//}
	//
	//status = C.CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, nil, &keyLen)
	//if status == 0 {
	//	lastError := GetLastError()
	//	return nil, fmt.Errorf("Can't get public key. Got error 0x%x\n", lastError)
	//}
	//
	//blob := make([]byte, int(keyLen))
	//status = C.CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, &blob[0], &keyLen)
	//if status == 0 {
	//	lastError := GetLastError()
	//	return nil, fmt.Errorf("Can't get public key. Got error 0x%x\n", lastError)
	//}

	certBlob = C.get_blob(p)
	signerEncodeInfo = C.init_signer(p.pCertInfo, *prov.hCryptoProv, C.CString(szOID_CP_GOST_R3411_12_256))
	signedEncodeInfo.cbSize = C.sizeof_CMSG_SIGNED_ENCODE_INFO
	signedEncodeInfo.cSigners = 1
	signedEncodeInfo.rgSigners = signerEncodeInfo
	signedEncodeInfo.cCertEncoded = 1
	signedEncodeInfo.rgCertEncoded = certBlob
	signedEncodeInfo.rgCrlEncoded = nil

	return &msgEncodeInfo{signEncodeInfo: &signedEncodeInfo}, nil
}

var handle *os.File

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
	//streamInfo.pfnStreamOutput = (C.PFN_CMSG_STREAM_OUTPUT)(C.getBytes)
	streamInfo.pvArg = unsafe.Pointer(C.CString(fileName))
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
