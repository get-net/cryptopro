#include "sign_xml.h"


static const CHAR* XML_DATA = "<data></data>";

PCCERT_CONTEXT get_recipient_cert(HCERTSTORE hCertStore, const char *subject) {
    PCCERT_CONTEXT pCertContext = 0;
    return CertFindCertificateInStore(
        hCertStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        // CAPICOM_CERTIFICATE_FIND_SHA1_HASH
        0,
        subject,
        pCertContext
    );
}

// Signs an xml document using a certificate with the given thumbprint.
// If result's error_code is zero manual document deallocation is required
struct XMLSigningResult sign_xml(const char *xml_document, const char *thumbprint) {
    struct XMLSigningResult result = {
        .document = NULL,
        .document_size = 0,
        .error_code = _NO_ERROR
    };

    // Certificate look up
    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, _TEXT("MY"));
    if (!hStoreHandle) {
        result.error_code = FAILED_TO_OPEN_SYSTEM_STORE_ERROR;
        return result;
    }

	PCCERT_CONTEXT context = get_recipient_cert(hStoreHandle, thumbprint);
    if (!context) {
        CertCloseStore(hStoreHandle, 0);
        result.error_code = CERT_NOT_FOUND_ERROR;
        return result;
    }

    XADES_SIGN_PARA xadesSignPara = { sizeof(xadesSignPara) };
    xadesSignPara.dwSignatureType = XML_XADES_SIGNATURE_TYPE_ENVELOPED;
    xadesSignPara.pSignerCert = context;
    XADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pXadesSignPara = &xadesSignPara;

    DWORD cbToBeSigned = (DWORD)strlen(xml_document);
    BYTE *pbToBeSigned = (BYTE*)xml_document;
    PCRYPT_DATA_BLOB pSignedMessage = 0;

    if (!XadesSign(&para, NULL, FALSE, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        CertCloseStore(hStoreHandle, 0);
        if (context) CertFreeCertificateContext(context);

        result.error_code = FAILED_TO_SIGN_ERROR;
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
