// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_jni.h"
#include "macros.h"

// MessageDigest md = MessageDigest.getInstance("SHA-1");
// md.update(cert.getEncoded());
// byte[] thumbprint = md.digest();
PALEXPORT int32_t CryptoNative_GetX509Thumbprint(jobject /*X509Certificate*/ cert, uint8_t *pBuf, int32_t cBuf);

// java/util/Date getNotBefore()
// date.getTime()
PALEXPORT long CryptoNative_GetX509NotBefore(jobject /*X509Certificate*/ cert);

// java/util/Date getNotAfter()
// date.getTime()
PALEXPORT long CryptoNative_GetX509NotAfter(jobject /*X509Certificate*/ cert);

// java/util/Date getNextUpdate()
// date.getTime()
PALEXPORT long *CryptoNative_GetX509CrlNextUpdate(jobject /*X509CRL*/ crl);

// int getVersion()
PALEXPORT int32_t CryptoNative_GetX509Version(jobject /*X509Certificate*/ cert);

// java/lang/String getPublicKey().getAlgorithm()
PALEXPORT uint8_t* CryptoNative_GetX509PublicKeyAlgorithm(jobject /*X509Certificate*/ cert);

// java/lang/String getSigAlgOID()
PALEXPORT uint8_t* CryptoNative_GetX509SignatureAlgorithm(jobject /*X509Certificate*/ cert);

// getAlgorithm()
// if ... else if ...
// getParams()
PALEXPORT int32_t CryptoNative_GetX509PublicKeyParameterBytes(jobject /*X509Certificate*/ cert, uint8_t *pBuf, int32_t cBuf);

// java/lang/String getPublicKey().getEncoded()
PALEXPORT int32_t CryptoNative_GetX509PublicKeyBytes(jobject /*X509Certificate*/ cert, uint8_t *pBuf, int32_t cBuf);

// byte[] getEncoded()
PALEXPORT int32_t CryptoNative_GetX509NameRawBytes(jobject /*X500Principal*/ name, uint8_t *pBuf, int32_t cBuf);

PALEXPORT jobject /*X509Certificate*/ CryptoNative_DecodeX509(const uint8_t* buf, int32_t len);

PALEXPORT jobject /*X509CRL*/ CryptoNative_DecodeX509Crl(const uint8_t* buf, int32_t len);

PALEXPORT int32_t CryptoNative_GetX509DerSize(jobject /*X509Certificate*/ cert);

PALEXPORT int32_t CryptoNative_EncodeX509(jobject /*X509Certificate*/ cert, uint8_t* buf);

PALEXPORT void CryptoNative_X509Destroy(jobject /*X509Certificate*/ cert);

PALEXPORT jobject /*BigInteger*/ CryptoNative_X509GetSerialNumber(jobject /*X509Certificate*/ cert);

PALEXPORT jobject /*X500Principal*/ CryptoNative_X509GetIssuerName(jobject /*X509Certificate*/ cert);

PALEXPORT jobject /*X500Principal*/ CryptoNative_X509GetSubjectName(jobject /*X509Certificate*/ cert);

PALEXPORT uint64_t CryptoNative_X509IssuerNameHash(jobject /*X509Certificate*/ cert);

PALEXPORT void CryptoNative_X509CrlDestroy(jobject /*X509CRL*/ a);

PALEXPORT int32_t CryptoNative_GetX509SubjectPublicKeyInfoDerSize(jobject /*X509Certificate*/ cert);

PALEXPORT int32_t CryptoNative_EncodeX509SubjectPublicKeyInfo(jobject /*X509Certificate*/ cert, uint8_t* buf);

PALEXPORT jobject /*X509Certificate*/ CryptoNative_X509UpRef(jobject /*X509Certificate*/ cert);

PALEXPORT int32_t CryptoNative_X509GetExtCount(jobject /*X509Certificate*/ cert);

PALEXPORT char* AndroidCryptoNative_GetX509NameInfo(jobject /*X509Certificate*/ cert, int32_t nameType, int32_t forIssuer);

PALEXPORT int32_t AndroidCryptoNative_X509GetExtensions(jobject /*X509Certificate*/ cert, char **oids, char **extData);

PALEXPORT char* AndroidCryptoNative_X509FindExtensionData(jobject /*X509Certificate*/ cert, const char *oid, int32_t* len);

