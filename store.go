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
	//"github.com/GeertJohan/cgo.wchar"
)

const (
	CERT_CLOSE_STORE_FORCE_FLAG = C.CERT_CLOSE_STORE_FORCE_FLAG
	CERT_CLOSE_STORE_CHECK_FLAG = C.CERT_CLOSE_STORE_CHECK_FLAG
)

const (
	CERT_FIND_ANY                    = C.CERT_FIND_ANY
	CERT_FIND_SHA1_HASH              = C.CERT_FIND_SHA1_HASH
	CERT_FIND_MD5_HASH               = C.CERT_FIND_MD5_HASH
	CERT_FIND_SIGNATURE_HASH         = C.CERT_FIND_SIGNATURE_HASH
	CERT_FIND_KEY_IDENTIFIER         = C.CERT_FIND_KEY_IDENTIFIER
	CERT_FIND_HASH                   = C.CERT_FIND_HASH
	CERT_FIND_PROPERTY               = C.CERT_FIND_PROPERTY
	CERT_FIND_PUBLIC_KEY             = C.CERT_FIND_PUBLIC_KEY
	CERT_FIND_SUBJECT_NAME           = C.CERT_FIND_SUBJECT_NAME
	CERT_FIND_SUBJECT_ATTR           = C.CERT_FIND_SUBJECT_ATTR
	CERT_FIND_ISSUER_NAME            = C.CERT_FIND_ISSUER_NAME
	CERT_FIND_ISSUER_ATTR            = C.CERT_FIND_ISSUER_ATTR
	CERT_FIND_SUBJECT_STR_A          = C.CERT_FIND_SUBJECT_STR_A
	CERT_FIND_SUBJECT_STR_W          = C.CERT_FIND_SUBJECT_STR_W
	CERT_FIND_SUBJECT_STR            = C.CERT_FIND_SUBJECT_STR
	CERT_FIND_ISSUER_STR_A           = C.CERT_FIND_ISSUER_STR_A
	CERT_FIND_ISSUER_STR_W           = C.CERT_FIND_ISSUER_STR_W
	CERT_FIND_ISSUER_STR             = C.CERT_FIND_ISSUER_STR
	CERT_FIND_KEY_SPEC               = C.CERT_FIND_KEY_SPEC
	CERT_FIND_ENHKEY_USAGE           = C.CERT_FIND_ENHKEY_USAGE
	CERT_FIND_CTL_USAGE              = C.CERT_FIND_CTL_USAGE
	CERT_FIND_SUBJECT_CERT           = C.CERT_FIND_SUBJECT_CERT
	CERT_FIND_ISSUER_OF              = C.CERT_FIND_ISSUER_OF
	CERT_FIND_EXISTING               = C.CERT_FIND_EXISTING
	CERT_FIND_CERT_ID                = C.CERT_FIND_CERT_ID
	CERT_FIND_CROSS_CERT_DIST_POINTS = C.CERT_FIND_CROSS_CERT_DIST_POINTS
	CERT_FIND_PUBKEY_MD5_HASH        = C.CERT_FIND_PUBKEY_MD5_HASH
)

const (
	PROV_GOST_2012_256 = C.PROV_GOST_2012_256
	PROV_GOST_2012_512 = C.PROV_GOST_2012_512
)

type CertStore struct {
	HCertStore *C.HCERTSTORE
}

func CertOpenSystemStore(storeName string) (*CertStore, error) {
	store := C.CertOpenSystemStore(0, C.CString(storeName))
	if store == nil {
		lastError := GetLastError()
		return nil, fmt.Errorf("can`t open store %s got error 0x%x", storeName, lastError)
	}
	return &CertStore{HCertStore: &store}, nil
}

func CertCloseStore(store *CertStore, flags uint32) error {
	if store == nil {
		return errors.New("store not exist")
	}

	status := C.CertCloseStore(*store.HCertStore, C.uint(flags))
	if status == 0 {
		lastError := GetLastError()
		return fmt.Errorf("can't close store got error 0x%x", lastError)
	}
	return nil
}
