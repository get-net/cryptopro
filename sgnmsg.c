#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <tchar.h>
#include <CSP_WinCrypt.h>

#include "sgnmsg.h"
#include "_cgo_export.h"

const char* GetHashOid(PCCERT_CONTEXT pCert) {
    const char *pKeyAlg = pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (strcmp(pKeyAlg, szOID_CP_GOST_R3410EL) == 0)
    {
        return szOID_CP_GOST_R3411;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_256) == 0)
    {
        return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_512) == 0)
    {
        return szOID_CP_GOST_R3411_12_512;
    }
    return NULL;
}

int sign_message_cades_bes(PCCERT_CONTEXT pCertContext , unsigned int dwFlag, BYTE* message, char* out, int *size) {
    CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = pCertContext; // 0 for window
    signPara.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(pCertContext);

    // получаем цепочку сертификатов
    CERT_CHAIN_PARA             ChainPara = { sizeof(ChainPara) };
    PCCERT_CHAIN_CONTEXT        pChainContext = NULL;
    CertGetCertificateChain(NULL, pCertContext, NULL, NULL, &ChainPara, 0, NULL, &pChainContext);

    PCCERT_CONTEXT certs[pChainContext->rgpChain[0]->cElement];
    for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement-1; ++i) {
        certs[i]=pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;
    }

    if (sizeof(certs) > 0) {
       signPara.cMsgCert = pChainContext->rgpChain[0]->cElement-1;
       signPara.rgpMsgCert = &certs[0];
    }

    const BYTE *pbToBeSigned[] = { message };
    DWORD cbToBeSigned[] = { (DWORD)strlen(message) };

    DWORD pcbSignedBlob;
    if(!CryptSignMessage(&signPara,dwFlag,1,pbToBeSigned,cbToBeSigned,NULL, &pcbSignedBlob)) {
        *size = sprintf(out,"CadesSignMessage() failed: %d", GetLastError());

        return -1;
    }

    if(!CryptSignMessage(&signPara,dwFlag,1,pbToBeSigned,cbToBeSigned,out, &pcbSignedBlob)) {
        *size = sprintf(out,"CryptSignMessage() failed: %d", GetLastError());

        return -1;
    }

    if (pChainContext)
        CertFreeCertificateChain(pChainContext);

    *size=pcbSignedBlob;

    return 0;
}
