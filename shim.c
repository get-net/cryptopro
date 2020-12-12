#include <stdlib.h>
#include <stdarg.h>
#include <cades.h>
#include <string.h>

#include "shim.h"
#include "_cgo_export.h"

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
