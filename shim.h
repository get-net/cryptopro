#include <stdlib.h>
#include <stdarg.h>
#include <cades.h>
#include <string.h>

extern CERT_BLOB* get_blob(PCCERT_CONTEXT cert);
extern CMSG_SIGNER_ENCODE_INFO* init_signer(PCERT_INFO cert_info, HCRYPTPROV h_crypt_prov, char* hash_algo);