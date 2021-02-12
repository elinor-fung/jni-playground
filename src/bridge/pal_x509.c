// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_x509.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

// Handles both DER and PEM formats
jobject /*X509Certificate*/ CryptoNative_DecodeX509(const uint8_t *buf, int32_t len)
{
    if (buf == NULL || len == 0)
        return NULL;

    JNIEnv* env = GetJNIEnv();

    // byte[] bytes = new byte[] { ... }
    // InputStream stream = new ByteArrayInputStream(bytes);
    jbyteArray bytes = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte*)buf);
    jobject stream = (*env)->NewObject(env, g_ByteArrayInputStreamClass, g_ByteArrayInputStreamCtor, bytes);

    // CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    // return (X509Certificate)certFactory.generateCertificate(stream);
    jstring certType = JSTRING("X.509");
    jobject certFactory = (*env)->CallStaticObjectMethod(env, g_CertFactoryClass, g_CertFactoryGetInstance, certType);
    (*env)->DeleteLocalRef(env, certType);
    return (*env)->CallObjectMethod(env, certFactory, g_CertFactoryGenerateCertificate, stream);
}

jobject /*X509CRL*/ CryptoNative_DecodeX509Crl(const uint8_t *buf, int32_t len)
{
    if (buf == NULL || len == 0)
        return NULL;

    JNIEnv *env = GetJNIEnv();

    // byte[] bytes = new byte[] { ... }
    // InputStream stream = new ByteArrayInputStream(bytes);
    jbyteArray bytes = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte*)buf);
    jobject stream = (*env)->NewObject(env, g_ByteArrayInputStreamClass, g_ByteArrayInputStreamCtor, bytes);

    // CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    // return (X509CRL)certFactory.generateCRL(stream);
    jstring certType = JSTRING("X.509");
    jobject certFactory = (*env)->CallStaticObjectMethod(env, g_CertFactoryClass, g_CertFactoryGetInstance, certType);
    (*env)->DeleteLocalRef(env, certType);
    return (*env)->CallObjectMethod(env, certFactory, g_CertFactoryGenerateCRL, stream);
}

int32_t CryptoNative_GetX509DerSize(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return 0;

    return 0;
    //return i2d_X509(x, NULL);
}

// Encodes as DER format
int32_t CryptoNative_EncodeX509(jobject /*X509Certificate*/ cert, uint8_t* buf)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // byte[] encoded = x509.getEncoded();
    // return encoded.length
    jbyteArray encoded =  (*env)->CallObjectMethod(env, cert, g_X509CertGetEncoded);
    jsize bytesLen = (*env)->GetArrayLength(env, encoded);
    (*env)->GetByteArrayRegion(env, encoded, 0, bytesLen, (jbyte *)buf);
    (*env)->DeleteLocalRef(env, encoded);
    return (int32_t)bytesLen;
}

void CryptoNative_X509Destroy(jobject /*X509Certificate*/ cert)
{
    ReleaseGRef(GetJNIEnv(), cert);
}

jobject /*BigInteger*/ CryptoNative_X509GetSerialNumber(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return NULL;

    return NULL;
    //return X509_get_serialNumber(x509);
}

jobject /*X500Principal*/ CryptoNative_X509GetIssuerName(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return NULL;

    return NULL;
    //return X509_get_issuer_name(x509);
}

jobject /*X500Principal*/ CryptoNative_X509GetSubjectName(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return NULL;

    return NULL;
    //return X509_get_subject_name(x509);
}

uint64_t CryptoNative_X509IssuerNameHash(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // X500Principal issuer = cert.getIssuerX500Principal()
    // return issuer.hashCode();
    jobject issuer = (*env)->CallObjectMethod(env, cert, g_X509CertGetIssuerX500Principal);
    return (uint64_t)(*env)->CallObjectMethod(env, issuer, g_X500PrincipalHashCode);
}

int32_t CryptoNative_X509GetExtCount(jobject /*X509Certificate*/ cert)
{
    return 0;
    //return X509_get_ext_count(x);
}

int32_t AndroidCryptoNative_X509GetExtensions(jobject /*X509Certificate*/ cert, char **oids, char **extData)
{
    return 0;
    //return X509_get_ext(x, loc);
}

char* AndroidCryptoNative_X509FindExtensionData(jobject /*X509Certificate*/ cert, const char *oid, int32_t *len)
{
    return NULL;
    //if (x == NULL || nid == NID_undef)
    //{
    //    return NULL;
    //}

    //int idx = X509_get_ext_by_NID(x, nid, -1);

    //if (idx < 0)
    //{
    //    return NULL;
    //}

    //X509_EXTENSION* ext = X509_get_ext(x, idx);

    //if (ext == NULL)
    //{
    //    return NULL;
    //}

    //return X509_EXTENSION_get_data(ext);
}

void CryptoNative_X509CrlDestroy(jobject /*X509_CRL*/ crl)
{
    if (crl == NULL)
        return;

    ReleaseGRef(GetJNIEnv(), crl);
}

int32_t CryptoNative_GetX509SubjectPublicKeyInfoDerSize(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return 0;

    return 0;

    // X509_get_X509_PUBKEY returns an interior pointer, so should not be freed
    //return i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), NULL);
}

int32_t CryptoNative_EncodeX509SubjectPublicKeyInfo(jobject /*X509Certificate*/ cert, uint8_t* buf)
{
    if (cert == NULL)
        return 0;

    return 0;

    // X509_get_X509_PUBKEY returns an interior pointer, so should not be freed
    //return i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x509), &buf);
}

jobject /*X509Certificate*/ CryptoNative_X509UpRef(jobject /*X509Certificate*/ cert)
{
    return AddGRef(GetJNIEnv(), cert);
}
