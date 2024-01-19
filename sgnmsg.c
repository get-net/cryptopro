#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <tchar.h>
#include <CSP_WinCrypt.h>
#include <cades.h>

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

    CADES_SIGN_PARA cadesSignPara = { sizeof(cadesSignPara) };
    cadesSignPara.dwCadesType = CADES_BES;

    CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    // получаем цепочку сертификатов
    CERT_CHAIN_PARA             ChainPara = { sizeof(ChainPara) };
    PCCERT_CHAIN_CONTEXT        pChainContext = NULL;
    if (CertGetCertificateChain(NULL, pCertContext, NULL, NULL, &ChainPara, 0, NULL, &pChainContext)) {
        PCCERT_CONTEXT certs[pChainContext->rgpChain[0]->cElement];
        for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement-1; ++i) {
            certs[i]=pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;
        }

        if (sizeof(certs) > 0) {
            signPara.cMsgCert = pChainContext->rgpChain[0]->cElement-1;
            signPara.rgpMsgCert = &certs[0];
        }
    }

    const BYTE *pbToBeSigned[] = { message };
    DWORD cbToBeSigned[] = { (DWORD)strlen(message) };

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    if(!CadesSignMessage(&para,dwFlag,1,pbToBeSigned,cbToBeSigned,&pSignedMessage)) {
        *size = sprintf(out,"CadesSignMessage() failed: %d", GetLastError());

        return -1;
    }

    if (pChainContext)
        CertFreeCertificateChain(pChainContext);

    out = pSignedMessage->pbData;
    *size=pSignedMessage->cbData;

    if(!CadesFreeBlob(pSignedMessage)) {
        *size = sprintf(out,"CadesFreeBlob() failed: %d", GetLastError());

        return -1;
    }

    return 0;
}
