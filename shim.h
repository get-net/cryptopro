#include <stdlib.h>
#include <stdarg.h>
#include <CSP_WinCrypt.h>
#include <string.h>

extern CERT_BLOB* get_blob(PCCERT_CONTEXT cert);
extern CMSG_SIGNER_ENCODE_INFO* init_signer(PCERT_INFO cert_info, HCRYPTPROV h_crypt_prov, char* hash_algo);
extern CERT_EXTENSION* get_extension(PCERT_INFO cert_info, int index);
extern PCERT_ALT_NAME_INFO get_dist_point(PCRL_DIST_POINTS_INFO dist_info, int index);
extern LPWSTR get_dist_point_url(PCERT_ALT_NAME_INFO nameInfo, int index);