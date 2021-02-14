// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

#include <jni.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define FAIL 0
#define SUCCESS 1

extern JavaVM* gJvm;

// java/io/ByteArrayInputStream
extern jclass    g_ByteArrayInputStreamClass;
extern jmethodID g_ByteArrayInputStreamCtor;

// java/security/Key
extern jclass    g_KeyClass;
extern jmethodID g_KeyGetAlgorithm;
extern jmethodID g_KeyGetEncoded;

// java/security/SecureRandom
extern jclass    g_randClass;
extern jmethodID g_randCtor;
extern jmethodID g_randNextBytesMethod;

// java/security/MessageDigest
extern jclass    g_mdClass;
extern jmethodID g_mdGetInstanceMethod;
extern jmethodID g_mdDigestMethod;
extern jmethodID g_mdDigestCurrentMethodId;
extern jmethodID g_mdResetMethod;
extern jmethodID g_mdUpdateMethod;

// javax/crypto/Mac
extern jclass    g_macClass;
extern jmethodID g_macGetInstanceMethod;
extern jmethodID g_macDoFinalMethod;
extern jmethodID g_macUpdateMethod;
extern jmethodID g_macInitMethod;
extern jmethodID g_macResetMethod;

// javax/crypto/spec/SecretKeySpec
extern jclass    g_sksClass;
extern jmethodID g_sksCtor;

// javax/crypto/Cipher
extern jclass    g_cipherClass;
extern jmethodID g_cipherGetInstanceMethod;
extern jmethodID g_cipherDoFinalMethod;
extern jmethodID g_cipherDoFinal2Method;
extern jmethodID g_cipherUpdateMethod;
extern jmethodID g_cipherUpdateAADMethod;
extern jmethodID g_cipherInitMethod;
extern jmethodID g_cipherInit2Method;
extern jmethodID g_getBlockSizeMethod;

// javax/crypto/spec/IvParameterSpec
extern jclass    g_ivPsClass;
extern jmethodID g_ivPsCtor;

// java/math/BigInteger
extern jclass    g_bigNumClass;
extern jmethodID g_bigNumCtor;
extern jmethodID g_toByteArrayMethod;

// javax/net/ssl/SSLParameters
extern jclass    g_sslParamsClass;
extern jmethodID g_sslParamsGetProtocolsMethod;

// javax/net/ssl/SSLContext
extern jclass    g_sslCtxClass;
extern jmethodID g_sslCtxGetDefaultMethod;
extern jmethodID g_sslCtxGetDefaultSslParamsMethod;

// javax/crypto/spec/GCMParameterSpec
extern jclass    g_GCMParameterSpecClass;
extern jmethodID g_GCMParameterSpecCtor;

// java/security/cert/CertificateFactory
extern jclass    g_CertFactoryClass;
extern jmethodID g_CertFactoryGetInstance;
extern jmethodID g_CertFactoryGenerateCertificate;
extern jmethodID g_CertFactoryGenerateCRL;

// java/security/cert/X509Certificate
extern jclass    g_X509CertClass;
extern jmethodID g_X509CertGetEncoded;
extern jmethodID g_X509CertGetIssuerX500Principal;
extern jmethodID g_X509CertGetNotAfter;
extern jmethodID g_X509CertGetNotBefore;
extern jmethodID g_X509CertGetPublicKey;
extern jmethodID g_X509CertGetSerialNumber;
extern jmethodID g_X509CertGetSigAlgOID;
extern jmethodID g_X509CertGetSubjectX500Principal;
extern jmethodID g_X509CertGetVersion;

// java/security/cert/X509Certificate implements java/security/cert/X509Extension
extern jmethodID g_X509CertGetCriticalExtensionOIDs;
extern jmethodID g_X509CertGetExtensionValue;
extern jmethodID g_X509CertGetNonCriticalExtensionOIDs;

// java/security/cert/X509CRL
extern jclass    g_X509CRLClass;
extern jmethodID g_X509CRLGetNextUpdate;

// java/security/interfaces/RSAKey
extern jclass    g_RSAKeyClass;
extern jmethodID g_RSAKeyGetModulus;

// java/security/interfaces/RSAPublicKey
extern jclass    g_RSAPublicKeyClass;
extern jmethodID g_RSAPublicKeyGetPubExpMethod;

// java/security/KeyPair
extern jclass    g_keyPairClass;
extern jmethodID g_keyPairGetPrivateMethod;
extern jmethodID g_keyPairGetPublicMethod;

// java/security/KeyPairGenerator
extern jclass    g_keyPairGenClass;
extern jmethodID g_keyPairGenGetInstanceMethod;
extern jmethodID g_keyPairGenInitializeMethod;
extern jmethodID g_keyPairGenGenKeyPairMethod;

// com/android/org/conscrypt/RSAPrivateCrtKey
extern jclass    g_RSAPrivateCrtKeyClass;
extern jmethodID g_RSAPrivateCrtKeyPubExpField;
extern jmethodID g_RSAPrivateCrtKeyPrimePField;
extern jmethodID g_RSAPrivateCrtKeyPrimeQField;
extern jmethodID g_RSAPrivateCrtKeyPrimeExpPField;
extern jmethodID g_RSAPrivateCrtKeyPrimeExpQField;
extern jmethodID g_RSAPrivateCrtKeyCrtCoefField;
extern jmethodID g_RSAPrivateCrtKeyModulusField;
extern jmethodID g_RSAPrivateCrtKeyPrivExpField;

// java/security/spec/RSAPrivateCrtKeySpec
extern jclass    g_RSAPrivateCrtKeySpecClass;
extern jmethodID g_RSAPrivateCrtKeySpecCtor;

// java/security/spec/RSAPublicKeySpec
extern jclass    g_RSAPublicCrtKeySpecClass;
extern jmethodID g_RSAPublicCrtKeySpecCtor;

// java/security/KeyFactory
extern jclass    g_KeyFactoryClass;
extern jmethodID g_KeyFactoryGetInstanceMethod;
extern jmethodID g_KeyFactoryGenPrivateMethod;
extern jmethodID g_KeyFactoryGenPublicMethod;

// java/security/spec/X509EncodedKeySpec
extern jclass    g_X509EncodedKeySpecClass;
extern jmethodID g_X509EncodedKeySpecCtor;

// java/util/Date
extern jclass    g_DateClass;
extern jmethodID g_DateGetTime;

// javax/security/auth/x500/X500Principal
extern jclass    g_X500PrincipalClass;
extern jmethodID g_X500PrincipalGetEncoded;
extern jmethodID g_X500PrincipalHashCode;

// com/android/org/conscrypt/NativeCrypto
extern jclass    g_NativeCryptoClass;

// JNI helpers
#define JSTRING(str) ((jstring)(*env)->NewStringUTF(env, str))

#define LOG_DEBUG(fmt, ...) printf("DEBUG: " fmt "\n", __VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("INFO: " fmt "\n", __VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("ERRROR: " fmt "\n -- in %s : %s@%d\n", __VA_ARGS__, __FUNCTION__, __FILE__, __LINE__)

void SaveTo(uint8_t* src, uint8_t** dst, size_t len);
jobject ToGRef(JNIEnv *env, jobject lref);
jobject AddGRef(JNIEnv *env, jobject gref);
void ReleaseGRef(JNIEnv *env, jobject gref);
jclass GetClassGRef(JNIEnv *env, const char* name);
bool CheckJNIExceptions(JNIEnv *env);
jmethodID GetMethod(JNIEnv *env, bool isStatic, jclass klass, const char* name, const char* sig);
jfieldID GetField(JNIEnv *env, bool isStatic, jclass klass, const char* name, const char* sig);
JNIEnv* GetJNIEnv(void);
