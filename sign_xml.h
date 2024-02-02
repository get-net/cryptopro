#ifndef XML_SIGNER_H
#define XML_SIGNER_H

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include "reader/tchar.h"
#include "xades.h"

#define _NO_ERROR 0
#define FAILED_TO_OPEN_SYSTEM_STORE_ERROR 1001
#define CERT_NOT_FOUND_ERROR 1002
#define FAILED_TO_SIGN_ERROR 1003
#define FAILED_TO_ALLOCATE_OUTPUT 1004

struct XMLSigningResult {
    char *document;
    int document_size;
    int error_code;
};

struct XMLSigningResult sign_xml(const char *xml_document, const char *thumbprint);

#endif



