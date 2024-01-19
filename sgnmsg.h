#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <tchar.h>
#include <CSP_WinCrypt.h>
#include <cades.h>

const char* GetHashOid(PCCERT_CONTEXT pCert);
int sign_message_cades_bes(PCCERT_CONTEXT pCertContext , unsigned int dwFlag, BYTE* message, char* out, int *size);
