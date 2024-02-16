#include "sign_xml.h"


static const CHAR* XML_DATA = "<data></data>";


// Taken from /cprocsp/include/cpcsp/CPCA20Request.h
BOOL HexToBin( const char * src, DWORD sLen, BYTE * dst, DWORD *pdLen ) {
    int i, j, k;
    for ( i = sLen, j = *pdLen; i > 0 && j > 0; i -= 2, j-- )
    {
        BYTE b = 0;
        for ( k = 0; k < 2; k++ )
        {
            BYTE c = ( BYTE )tolower( *src++ );
            b <<= 4;
            if ( c >= 'a' && c <= 'f' )
            { b |= c - 'a' + 10; }
            else if ( isdigit( c ) )
            { b |= c - '0'; }
            else
            { return FALSE; }
        }
        *dst++ = b;
    }
    *pdLen -= j;
    return TRUE;
}

PCCERT_CONTEXT get_recipient_cert(HCERTSTORE hCertStore, const char *thumbprint) {
    CRYPT_HASH_BLOB thumbprint_hash;

    // SHA1 thumbprint is expected to be 40 bytes long
    if (strlen(thumbprint) != 40) {
        return NULL;
    }

    BYTE bSHA1Digest[20];
    thumbprint_hash.cbData = 20;
    thumbprint_hash.pbData = bSHA1Digest;
    if (!HexToBin(thumbprint, 40, thumbprint_hash.pbData, &thumbprint_hash.cbData)){
        return NULL;
    }

    return CertFindCertificateInStore(
        hCertStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &thumbprint_hash,
        NULL
    );
}

// Signs an xml document using a certificate with the given thumbprint.
// If result's error_code is zero manual document deallocation is required
struct XMLSigningResult sign_xml(const char *xml_document, const char *xpath, DWORD signature_type, const char *thumbprint) {
    struct XMLSigningResult result = {
        .document = NULL,
        .document_size = 0,
        .error_code = _NO_ERROR,
        .crypto_pro_error = 0
    };

    // Certificate look up
    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, _TEXT("MY"));
    if (!hStoreHandle) {
        result.error_code = FAILED_TO_OPEN_SYSTEM_STORE_ERROR;
        result.crypto_pro_error = GetLastError();
        return result;
    }

	PCCERT_CONTEXT context = get_recipient_cert(hStoreHandle, thumbprint);
    if (!context) {
        CertCloseStore(hStoreHandle, 0);
        result.error_code = CERT_NOT_FOUND_ERROR;
        result.crypto_pro_error = GetLastError();
        return result;
    }

    XADES_SIGN_PARA xadesSignPara = { sizeof(xadesSignPara) };
    xadesSignPara.dwSignatureType = signature_type;
    xadesSignPara.pSignerCert = context;
    XADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pXadesSignPara = &xadesSignPara;

    DWORD cbToBeSigned = (DWORD)strlen(xml_document);
    BYTE *pbToBeSigned = (BYTE*)xml_document;
    PCRYPT_DATA_BLOB pSignedMessage = 0;

    if (!XadesSign(&para, xpath, FALSE, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        CertCloseStore(hStoreHandle, 0);
        if (context) CertFreeCertificateContext(context);

        result.error_code = FAILED_TO_SIGN_ERROR;
        result.crypto_pro_error = GetLastError();
        return result;
    }

    result.document_size = pSignedMessage->cbData * sizeof(unsigned char);
    result.document = (unsigned char*)malloc(result.document_size);
    if (result.document == NULL) {
        CertCloseStore(hStoreHandle, 0);
        if (context) CertFreeCertificateContext(context);

        result.error_code = FAILED_TO_ALLOCATE_OUTPUT;
        return result;
    };

    memcpy(result.document, pSignedMessage->pbData, result.document_size);

    XadesFreeBlob(pSignedMessage);
    CertCloseStore(hStoreHandle, 0);
    if (context) CertFreeCertificateContext(context);

    return result;
}
