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
    unsigned int dwKeySpec = 0;
    int mustFree;

    HCRYPTPROV hCryptProv;
    if ( !CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_CACHE_FLAG,NULL, &hCryptProv, &dwKeySpec, &mustFree) ) {
        *size = sprintf(out,"Private key not acquired: %d", GetLastError());
        CertFreeCertificateContext( pCertContext );

        return -1;
    }

    // Задаем параметры
    CMSG_SIGNER_ENCODE_INFO signer = {sizeof(CMSG_SIGNER_ENCODE_INFO)};
    signer.pCertInfo = pCertContext->pCertInfo; // Сертификат подписчика
    signer.hCryptProv = hCryptProv; // Дескриптор криптопровайдера
    signer.dwKeySpec = dwKeySpec;
    signer.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(pCertContext);

    CERT_BLOB blob = {sizeof(CERT_BLOB)};
    blob.cbData = pCertContext->cbCertEncoded;
    blob.pbData = pCertContext->pbCertEncoded;

    CMSG_SIGNED_ENCODE_INFO info = {sizeof(CMSG_SIGNED_ENCODE_INFO)};
    info.cSigners = 1; // Количество подписчиков
    info.rgSigners = &signer; // Массив подписчиков
    info.cCertEncoded = 1;
    info.rgCertEncoded = &blob;

    // Открываем дескриптор сообщения для создания усовершенствованной подписи
    HCRYPTMSG hMsg = CryptMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, dwFlag, CMSG_SIGNED, &info, 0, 0);
    if (!hMsg) {
        *size = sprintf(out,"Can`t open cades msg to encode: %d", GetLastError());
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        return -1;
    }

    // Формируем подпись в сообщении
    if (!CryptMsgUpdate(hMsg, message, strlen(message), 1)) {
        *size = sprintf(out,"Failed to update crypt msg: %d", GetLastError());
        CryptMsgClose( hMsg );
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        return -1;
    }

    DWORD msgSize = 0;
    // Получаем размер подписи
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, 0, &msgSize)) {
        *size = sprintf(out,"Failed to get crypt msg param size: %d", GetLastError());
        CryptMsgClose( hMsg );
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        return -1;
    }

    // Получаем подпись
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, &out[0], &msgSize)) {
        *size = sprintf(out,"Failed to get crypt msg param: %d", GetLastError());
        CryptMsgClose( hMsg );
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        return -1;
    }

    CryptMsgClose( hMsg );
    if ( mustFree )
        CryptReleaseContext( hCryptProv, 0 );

    *size = msgSize;
    return 0;
}

int sign_message_cades_bes_c_only(unsigned char* hexStrThumbprint, unsigned int dwFlag, BYTE* message, char* out, int *size) {
    // Открываем хранилище сертификатов
    HCERTSTORE hCertStore = CertOpenSystemStore(0, "MY");
    if (!hCertStore) {
        *size = sprintf(out,"Error open system store: %d", GetLastError());
        return -1;
    }

    CRYPT_HASH_BLOB CryptHashBlob;
    CryptHashBlob.pbData = hexStrThumbprint;
    CryptHashBlob.cbData = strlen(hexStrThumbprint);

    PCCERT_CONTEXT pCertContext = NULL;
    pCertContext = CertFindCertificateInStore(
        hCertStore, // Дескриптор хранилища, в котором будет осуществлен поиск.
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SHA1_HASH,
        &CryptHashBlob,
        NULL);
    if ( !pCertContext ) {
        *size = sprintf(out,"Certificate not found: %d", GetLastError());
        CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );

        return -1;
    }

    // Проверка закрытого ключа
    int mustFree;
    HCRYPTPROV hCryptProv;
	unsigned int dwKeySpec = 0;
    if ( !CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_CACHE_FLAG,NULL, &hCryptProv, &dwKeySpec, &mustFree) ) {
        *size = sprintf(out,"Private key not acquired: %d", GetLastError());
        CertFreeCertificateContext( pCertContext );
        CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );

        return -1;
    }

    // Задаем параметры
    CMSG_SIGNER_ENCODE_INFO signer = {sizeof(CMSG_SIGNER_ENCODE_INFO)};
    signer.pCertInfo = pCertContext->pCertInfo; // Сертификат подписчика
    signer.hCryptProv = hCryptProv; // Дескриптор криптопровайдера
    signer.dwKeySpec = dwKeySpec;
    signer.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(pCertContext);

    CERT_BLOB blob = {sizeof(CERT_BLOB)};
    blob.cbData = pCertContext->cbCertEncoded;
    blob.pbData = pCertContext->pbCertEncoded;

    CMSG_SIGNED_ENCODE_INFO info = {sizeof(CMSG_SIGNED_ENCODE_INFO)};
    info.cSigners = 1; // Количество подписчиков
    info.rgSigners = &signer; // Массив подписчиков
    info.cCertEncoded = 1;
    info.rgCertEncoded = &blob;

    // Открываем дескриптор сообщения для создания усовершенствованной подписи
    HCRYPTMSG hMsg = CryptMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, dwFlag, CMSG_SIGNED, &info, 0, 0);
    if (!hMsg) {
        *size = sprintf(out,"Can`t open cades msg to encode: %d", GetLastError());
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        CertFreeCertificateContext( pCertContext );
        CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );

        return -1;
    }

    // Формируем подпись в сообщении
    if (!CryptMsgUpdate(hMsg, message, strlen(message), 1)) {
        *size = sprintf(out,"Failed to update crypt msg: %d", GetLastError());
        CryptMsgClose( hMsg );
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        CertFreeCertificateContext( pCertContext );
        CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );

        return -1;
    }

    DWORD msgSize = 0;
    // Получаем размер подписи
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, 0, &msgSize)) {
        *size = sprintf(out,"Failed to get crypt msg param size: %d", GetLastError());
        CryptMsgClose( hMsg );
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        CertFreeCertificateContext( pCertContext );
        CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );

        return -1;
    }

    // Получаем подпись
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, &out[0], &msgSize)) {
        *size = sprintf(out,"Failed to get crypt msg param: %d", GetLastError());
        CryptMsgClose( hMsg );
        if ( mustFree )
            CryptReleaseContext( hCryptProv, 0 );

        CertFreeCertificateContext( pCertContext );
        CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );

        return -1;
    }

    CryptMsgClose( hMsg );
    if ( mustFree )
        CryptReleaseContext( hCryptProv, 0 );

    CertFreeCertificateContext( pCertContext );
    CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );

    *size = msgSize;
    return 0;
}
