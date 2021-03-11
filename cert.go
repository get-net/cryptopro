package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10
#include <stdlib.h>
#include <stdarg.h>
#include <CSP_WinCrypt.h>
#include "shim.h"
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

const (
	CERT_SIMPLE_NAME_STR = C.CERT_SIMPLE_NAME_STR
	CERT_OID_NAME_STR    = C.CERT_OID_NAME_STR
	CERT_X500_NAME_STR   = C.CERT_X500_NAME_STR
)

const (
	X509_ASN_ENCODING   = C.X509_ASN_ENCODING
	PKCS_7_ASN_ENCODING = C.PKCS_7_ASN_ENCODING
)

const (
	CERT_KEY_PROV_INFO_PROP_ID = C.CERT_KEY_PROV_INFO_PROP_ID
	CERT_HASH_PROP_ID          = C.CERT_HASH_PROP_ID
)

const (
	szOID_CRL_DIST_POINTS       = C.szOID_CRL_DIST_POINTS
	szOID_AUTHORITY_INFO_ACCESS = C.szOID_AUTHORITY_INFO_ACCESS
)

const (
	CERT_STORE_ADD_ALWAYS = C.CERT_STORE_ADD_ALWAYS
	CERT_STORE_ADD_NEW    = C.CERT_STORE_ADD_NEW
)

type CertContext struct {
	Issuer       string
	Subject      string
	SHA1Hash     string
	pCertContext *C.PCCERT_CONTEXT
}

type KeyProvInfo struct {
	cryptKeyProvInfo C.CRYPT_KEY_PROV_INFO
}

type CertExtension struct {
	pCertExtension C.PCERT_EXTENSION
}

type AuthorityInfoAccess struct {
	Oid  string
	Info string
}

func (cert CertContext) getCertBlob() *C.CERT_BLOB {
	return C.get_blob(*cert.pCertContext)
}

func (cert CertContext) getCertInfo() C.PCERT_INFO {
	var pCertContext C.PCCERT_CONTEXT = *cert.pCertContext
	return pCertContext.pCertInfo
}

func (cert CertContext) getCertName() string {
	context := *cert.pCertContext
	name, err := CertNameToStr(&context.pCertInfo.Subject, CERT_SIMPLE_NAME_STR)
	if err != nil {
		return ""
	}
	return *name
}

func (cert CertContext) getExtension(index int) (*CertExtension, error) {
	pcertInfo := cert.getCertInfo()

	extLen := int(pcertInfo.cExtension)
	if index >= extLen {
		return nil, errors.New("out of index")
	}

	ext := C.get_extension(pcertInfo, C.int(index))

	return &CertExtension{pCertExtension: ext}, nil
}

func (cert CertContext) getExtensionLen() int {
	pcertInfo := cert.getCertInfo()
	return int(pcertInfo.cExtension)
}

func (ce CertExtension) getOID() string {
	return C.GoString((*C.char)(unsafe.Pointer(ce.pCertExtension.pszObjId)))
}

func (ce CertExtension) getCrlDistPoints() ([]string, error) {
	var distInfos C.PCRL_DIST_POINTS_INFO
	var lenInfo C.uint

	var crls []string

	value := ce.pCertExtension.Value
	status := C.CryptDecodeObject(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, C.X509_CRL_DIST_POINTS,
		value.pbData, value.cbData, 0, nil, &lenInfo)
	if status == 0 {
		return nil, GetLastError()
	}
	info := make([]byte, int(lenInfo))
	status = C.CryptDecodeObject(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, C.X509_CRL_DIST_POINTS,
		value.pbData, value.cbData, 0, unsafe.Pointer(&info[0]), &lenInfo)
	if status == 0 {
		return nil, GetLastError()
	}
	distInfos = (C.PCRL_DIST_POINTS_INFO)(unsafe.Pointer(&info[0]))
	for i := 0; i < int(distInfos.cDistPoint); i++ {
		certAltInfo := C.get_dist_point(distInfos, C.int(i))
		for j := 0; j < int(certAltInfo.cAltEntry); j++ {
			crl := C.get_dist_point_url(certAltInfo, C.int(j))
			crlInfo, err := Decode(unsafe.Pointer(crl))
			if err != nil {
				return nil, err
			}
			crls = append(crls, crlInfo)
		}
	}

	return crls, nil
}

func (ce CertExtension) getAuthorityInfoAccess() ([]AuthorityInfoAccess, error) {
	var infoAccess C.PCERT_AUTHORITY_INFO_ACCESS
	var lenInfo C.uint

	var res []AuthorityInfoAccess
	value := ce.pCertExtension.Value
	status := C.CryptDecodeObject(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, C.X509_AUTHORITY_INFO_ACCESS,
		value.pbData, value.cbData, 0, nil, &lenInfo)
	if status == 0 {
		return nil, GetLastError()
	}
	info := make([]byte, int(lenInfo))
	status = C.CryptDecodeObject(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, C.X509_AUTHORITY_INFO_ACCESS,
		value.pbData, value.cbData, 0, unsafe.Pointer(&info[0]), &lenInfo)
	if status == 0 {
		return nil, GetLastError()
	}
	infoAccess = (C.PCERT_AUTHORITY_INFO_ACCESS)(unsafe.Pointer(&info[0]))
	for i := 0; i < int(infoAccess.cAccDescr); i++ {
		accessDescription := C.get_access_method(infoAccess, C.int(i))
		oid := C.GoString((*C.char)(unsafe.Pointer(accessDescription)))
		value := C.get_access_location(infoAccess, C.int(i))
		info, err := Decode(unsafe.Pointer(value))
		if err != nil {
			return nil, GetLastError()
		}
		res = append(res, AuthorityInfoAccess{
			Oid:  oid,
			Info: info,
		})
	}

	return res, nil
}

func (cert CertContext) getExtensionByOid(oid string) (*CertExtension, error) {
	extLen := cert.getExtensionLen()
	var retIdx *CertExtension
	for i := 0; i < extLen; i++ {
		ext, err := cert.getExtension(i)
		if err != nil {
			return nil, err
		}
		if ext.getOID() == oid {
			retIdx = ext
		}
	}
	if retIdx == nil {
		return nil, errors.New("oid not found")
	}
	return retIdx, nil
}

func (cert CertContext) getNotBefore() time.Time {
	info := cert.getCertInfo()
	lowdatetime := uint64(info.NotBefore.dwLowDateTime)
	highdatetime := uint64(info.NotBefore.dwHighDateTime)

	notBefore := highdatetime << 32
	notBefore = notBefore + lowdatetime
	timestamp := notBefore/(10000000) - 11644473600
	return time.Unix(int64(timestamp), 0)
}

func (cert CertContext) getNotAfter() time.Time {
	info := cert.getCertInfo()
	lowdatetime := uint64(info.NotAfter.dwLowDateTime)
	highdatetime := uint64(info.NotAfter.dwHighDateTime)

	notBefore := highdatetime << 32
	notBefore = notBefore + lowdatetime
	timestamp := notBefore/(10000000) - 11644473600
	return time.Unix(int64(timestamp), 0)
}

func (cert CertContext) getThumbprint() string {
	test, err := CertGetCertificateContextProperty(&cert, CERT_HASH_PROP_ID)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(test)
}

func CertNameToStr(nameBlob C.PCERT_NAME_BLOB, flag int) (*string, error) {
	size := C.CertNameToStr(X509_ASN_ENCODING, nameBlob, C.uint(flag), nil, 0)

	n := C.CString(string(make([]byte, size)))
	defer C.free(unsafe.Pointer(n))
	count := C.CertNameToStr(X509_ASN_ENCODING, nameBlob, C.uint(flag), n, size)
	if count == 0 {
		return nil, errors.New("can't convert name_blob to string")
	}

	name := C.GoString(n)
	return &name, nil
}

func CertCreateCertificateContext(data []byte) (*CertContext, error) {
	size := len(data)
	p := C.CertCreateCertificateContext(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, (*C.uchar)(&data[0]), C.uint(size))
	if p == nil {
		return nil, errors.New("can't create cert context")
	}

	return &CertContext{pCertContext: &p}, nil
}

func CertFindCertificateInStore(store *CertStore, searchParam string, findType uint) (*CertContext, error) {

	if store == nil {
		return nil, errors.New("store is nil")
	}

	var pointer unsafe.Pointer

	switch findType {
	case CERT_FIND_SHA1_HASH:
		var hash C.CRYPT_INTEGER_BLOB
		hashBytes, err := hex.DecodeString(searchParam)
		if err != nil {
			return nil, err
		}

		hash.cbData = C.uint(len(hashBytes))
		hash.pbData = (*C.uchar)(C.CBytes(hashBytes))
		pointer = unsafe.Pointer(&hash)
	case CERT_FIND_SUBJECT_STR_A:
		bytes := []byte(searchParam)
		pointer = unsafe.Pointer(&bytes[0])
	default:
		return nil, errors.New("not supported find type")
	}

	p := C.CertFindCertificateInStore(*store.HCertStore, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 0,
		C.uint(findType), pointer, nil)
	if p == nil {
		return nil, GetLastError()
	}

	issuer, err := CertNameToStr(&p.pCertInfo.Issuer, CERT_SIMPLE_NAME_STR)
	if err != nil {
		return nil, err
	}
	subject, err := CertNameToStr(&p.pCertInfo.Subject, CERT_SIMPLE_NAME_STR)
	if err != nil {
		return nil, err
	}

	return &CertContext{
		Issuer:       *issuer,
		Subject:      *subject,
		SHA1Hash:     searchParam,
		pCertContext: &p,
	}, nil
}

func CertGetSubjectCertificateFromStore(store *CertStore, data []byte) (*CertContext, error) {
	var pCertInfo C.PCERT_INFO = (C.PCERT_INFO)(unsafe.Pointer(&data[0]))
	pCert := C.CertGetSubjectCertificateFromStore(*store.HCertStore, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, pCertInfo)
	if pCert == nil {
		return nil, fmt.Errorf("can't get subject certificate from store got error 0x%x", GetLastError())
	}
	return &CertContext{pCertContext: &pCert}, nil
}

func CertAddCertificateContextToStore(store *CertStore, cert *CertContext, addDisp uint) error {
	status := C.CertAddCertificateContextToStore(*store.HCertStore, *cert.pCertContext, C.uint(addDisp), nil)
	if status == 0 {
		return GetLastError()
	}
	return nil
}

func CertAddEncodedCertificateToStore(store *CertStore, encCert []byte, addDisp uint) error {
	lenCert := len(encCert)
	if lenCert == 0 {
		return errors.New("encCert empty")
	}

	status := C.CertAddEncodedCertificateToStore(*store.HCertStore, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
		(*C.uchar)(&encCert[0]), C.uint(lenCert), C.uint(addDisp), nil)
	if status == 0 {
		return GetLastError()
	}
	return nil
}

func CertGetCertificateContextProperty(ctx *CertContext, propId uint) ([]byte, error) {
	var size C.uint
	status := C.CertGetCertificateContextProperty(*ctx.pCertContext, C.uint(propId), nil, &size)
	if status == 0 {
		return nil, GetLastError()
	}

	data := make([]byte, size)
	status = C.CertGetCertificateContextProperty(*ctx.pCertContext, C.uint(propId), unsafe.Pointer(&data[0]), &size)
	if status == 0 {
		return nil, GetLastError()
	}
	return data, nil
}

func CertFreeCertificateContext(cert *CertContext) error {
	if cert == nil {
		return errors.New("cert context is nil")
	}
	status := C.CertFreeCertificateContext(*cert.pCertContext)
	if status == 0 {
		return fmt.Errorf("can't free cert context got error 0x%x", GetLastError())
	}
	return nil
}

func CertEnumCertificatesInStore(store *CertStore, ctx *CertContext) (*CertContext, error) {
	if store == nil {
		return nil, errors.New("store is nil")
	}

	var context C.PCCERT_CONTEXT
	if ctx != nil {
		context = *ctx.pCertContext
	}

	cert := C.CertEnumCertificatesInStore(*store.HCertStore, context)
	if cert == nil {
		return nil, GetLastError()
	}

	return &CertContext{pCertContext: &cert}, nil
}
