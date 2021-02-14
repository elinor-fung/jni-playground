// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_jni.h"
#include <string.h>

JavaVM* gJvm;

// java/io/ByteArrayInputStream
jclass    g_ByteArrayInputStreamClass;
jmethodID g_ByteArrayInputStreamCtor;

// java/security/Key
jclass    g_KeyClass;
jmethodID g_KeyGetAlgorithm;
jmethodID g_KeyGetEncoded;

// java/security/SecureRandom
jclass    g_randClass;
jmethodID g_randCtor;
jmethodID g_randNextBytesMethod;

// java/security/MessageDigest
jclass    g_mdClass;
jmethodID g_mdGetInstanceMethod;
jmethodID g_mdDigestMethod;
jmethodID g_mdDigestCurrentMethodId;
jmethodID g_mdResetMethod;
jmethodID g_mdUpdateMethod;

// javax/crypto/Mac
jclass    g_macClass;
jmethodID g_macGetInstanceMethod;
jmethodID g_macDoFinalMethod;
jmethodID g_macUpdateMethod;
jmethodID g_macInitMethod;
jmethodID g_macResetMethod;

// javax/crypto/spec/SecretKeySpec
jclass    g_sksClass;
jmethodID g_sksCtor;

// javax/crypto/Cipher
jclass    g_cipherClass;
jmethodID g_cipherGetInstanceMethod;
jmethodID g_cipherDoFinalMethod;
jmethodID g_cipherDoFinal2Method;
jmethodID g_cipherUpdateMethod;
jmethodID g_cipherUpdateAADMethod;
jmethodID g_cipherInitMethod;
jmethodID g_cipherInit2Method;
jmethodID g_getBlockSizeMethod;

// javax/crypto/spec/IvParameterSpec
jclass    g_ivPsClass;
jmethodID g_ivPsCtor;

// java/math/BigInteger
jclass    g_bigNumClass;
jmethodID g_bigNumCtor;
jmethodID g_toByteArrayMethod;

// javax/net/ssl/SSLParameters
jclass    g_sslParamsClass;
jmethodID g_sslParamsGetProtocolsMethod;

// javax/net/ssl/SSLContext
jclass    g_sslCtxClass;
jmethodID g_sslCtxGetDefaultMethod;
jmethodID g_sslCtxGetDefaultSslParamsMethod;

// javax/crypto/spec/GCMParameterSpec
jclass    g_GCMParameterSpecClass;
jmethodID g_GCMParameterSpecCtor;

// java/security/interfaces/RSAKey
jclass    g_RSAKeyClass;
jmethodID g_RSAKeyGetModulus;

// java/security/interfaces/RSAPublicKey
jclass    g_RSAPublicKeyClass;
jmethodID g_RSAPublicKeyGetPubExpMethod;

// java/security/KeyPair
jclass    g_keyPairClass;
jmethodID g_keyPairGetPrivateMethod;
jmethodID g_keyPairGetPublicMethod;

// java/security/KeyPairGenerator
jclass    g_keyPairGenClass;
jmethodID g_keyPairGenGetInstanceMethod;
jmethodID g_keyPairGenInitializeMethod;
jmethodID g_keyPairGenGenKeyPairMethod;

// java/security/cert/CertificateFactory
jclass    g_CertFactoryClass;
jmethodID g_CertFactoryGetInstance;
jmethodID g_CertFactoryGenerateCertificate;
jmethodID g_CertFactoryGenerateCRL;

// java/security/cert/X509Certificate
jclass    g_X509CertClass;
jmethodID g_X509CertGetEncoded;
jmethodID g_X509CertGetIssuerX500Principal;
jmethodID g_X509CertGetNotAfter;
jmethodID g_X509CertGetNotBefore;
jmethodID g_X509CertGetPublicKey;
jmethodID g_X509CertGetSerialNumber;
jmethodID g_X509CertGetSigAlgOID;
jmethodID g_X509CertGetSubjectX500Principal;
jmethodID g_X509CertGetVersion;

// java/security/cert/X509Certificate implements java/security/cert/X509Extension
jmethodID g_X509CertGetCriticalExtensionOIDs;
jmethodID g_X509CertGetExtensionValue;
jmethodID g_X509CertGetNonCriticalExtensionOIDs;

// java/security/cert/X509CRL
jclass    g_X509CRLClass;
jmethodID g_X509CRLGetNextUpdate;

// java/security/interfaces/RSAPrivateCrtKey
jclass    g_RSAPrivateCrtKeyClass;
jmethodID g_RSAPrivateCrtKeyPubExpField;
jmethodID g_RSAPrivateCrtKeyPrimePField;
jmethodID g_RSAPrivateCrtKeyPrimeQField;
jmethodID g_RSAPrivateCrtKeyPrimeExpPField;
jmethodID g_RSAPrivateCrtKeyPrimeExpQField;
jmethodID g_RSAPrivateCrtKeyCrtCoefField;
jmethodID g_RSAPrivateCrtKeyModulusField;
jmethodID g_RSAPrivateCrtKeyPrivExpField;

// java/security/spec/RSAPrivateCrtKeySpec
jclass    g_RSAPrivateCrtKeySpecClass;
jmethodID g_RSAPrivateCrtKeySpecCtor;

// java/security/spec/RSAPublicKeySpec
jclass    g_RSAPublicCrtKeySpecClass;
jmethodID g_RSAPublicCrtKeySpecCtor;

// java/security/KeyFactory
jclass    g_KeyFactoryClass;
jmethodID g_KeyFactoryGetInstanceMethod;
jmethodID g_KeyFactoryGenPrivateMethod;
jmethodID g_KeyFactoryGenPublicMethod;

// java/security/spec/X509EncodedKeySpec
jclass    g_X509EncodedKeySpecClass;
jmethodID g_X509EncodedKeySpecCtor;

// java/util/Date
jclass    g_DateClass;
jmethodID g_DateGetTime;

// javax/security/auth/x500/X500Principal
jclass    g_X500PrincipalClass;
jmethodID g_X500PrincipalGetEncoded;
jmethodID g_X500PrincipalHashCode;

// com/android/org/conscrypt/NativeCrypto
jclass    g_NativeCryptoClass;

jobject ToGRef(JNIEnv *env, jobject lref)
{
    if (!lref)
        return NULL;
    jobject gref = (*env)->NewGlobalRef(env, lref);
    (*env)->DeleteLocalRef(env, lref);
    return gref;
}

jobject AddGRef(JNIEnv *env, jobject gref)
{
    if (!gref)
        return NULL;
    return (*env)->NewGlobalRef(env, gref);
}

void ReleaseGRef(JNIEnv *env, jobject gref)
{
    if (gref)
        (*env)->DeleteGlobalRef(env, gref);
}

jclass GetClassGRef(JNIEnv *env, const char* name)
{
    LOG_DEBUG("Finding %s class", name);
    jclass klass = ToGRef(env, (*env)->FindClass (env, name));
    if (!klass) {
        LOG_ERROR("class %s was not found", name);
        assert(klass);
    }
    return klass;
}

bool CheckJNIExceptions(JNIEnv* env)
{
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return true;
    }
    return false;
}

void SaveTo(uint8_t* src, uint8_t** dst, size_t len)
{
    assert(!(*dst));
    *dst = (uint8_t*)malloc(len * sizeof(uint8_t));
    memcpy(*dst, src, len);
}

jmethodID GetMethod(JNIEnv *env, bool isStatic, jclass klass, const char* name, const char* sig)
{
    LOG_DEBUG("Finding %s method", name);
    jmethodID mid = isStatic ? (*env)->GetStaticMethodID(env, klass, name, sig) : (*env)->GetMethodID(env, klass, name, sig);
    if (!mid) {
        LOG_ERROR("method %s %s was not found", name, sig);
        assert(mid);
    }
    return mid;
}

jfieldID GetField(JNIEnv *env, bool isStatic, jclass klass, const char* name, const char* sig)
{
    LOG_DEBUG("Finding %s field", name);
    jfieldID fid = isStatic ? (*env)->GetStaticFieldID(env, klass, name, sig) : (*env)->GetFieldID(env, klass, name, sig);
    if (!fid) {
        LOG_ERROR("field %s %s was not found", name, sig);
        assert(fid);
    }
    return fid;
}

JNIEnv* GetJNIEnv()
{
    JNIEnv *env;
    (*gJvm)->GetEnv(gJvm, (void**)&env, JNI_VERSION_1_6);
    if (env)
        return env;
    jint ret = (*gJvm)->AttachCurrentThreadAsDaemon(gJvm, (void**)&env, NULL);
    assert(ret == JNI_OK && "Unable to attach thread to JVM");
    (void)ret;
    return env;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    gJvm = vm;

    JNIEnv* env = GetJNIEnv();

    // cache some classes and methods while we're in the thread-safe JNI_OnLoad
    g_ByteArrayInputStreamClass =   GetClassGRef(env, "java/io/ByteArrayInputStream");
    g_ByteArrayInputStreamCtor =    GetMethod(env, false, g_ByteArrayInputStreamClass, "<init>", "([B)V");

    g_KeyClass =        GetClassGRef(env, "java/security/Key");
    g_KeyGetAlgorithm = GetMethod(env, false, g_KeyClass, "getAlgorithm", "()Ljava/lang/String;");
    g_KeyGetEncoded =   GetMethod(env, false, g_KeyClass, "getEncoded", "()[B");

    g_randClass =               GetClassGRef(env, "java/security/SecureRandom");
    g_randCtor =                GetMethod(env, false, g_randClass, "<init>", "()V");
    g_randNextBytesMethod =     GetMethod(env, false, g_randClass, "nextBytes", "([B)V");

    g_mdClass =                 GetClassGRef(env, "java/security/MessageDigest");
    g_mdGetInstanceMethod =     GetMethod(env, true,  g_mdClass, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    g_mdResetMethod =           GetMethod(env, false, g_mdClass, "reset", "()V");
    g_mdDigestMethod =          GetMethod(env, false, g_mdClass, "digest", "([B)[B");
    g_mdDigestCurrentMethodId = GetMethod(env, false, g_mdClass, "digest", "()[B");
    g_mdUpdateMethod =          GetMethod(env, false, g_mdClass, "update", "([B)V");

    g_macClass =                GetClassGRef(env, "javax/crypto/Mac");
    g_macGetInstanceMethod =    GetMethod(env, true,  g_macClass, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Mac;");
    g_macDoFinalMethod =        GetMethod(env, false, g_macClass, "doFinal", "()[B");
    g_macUpdateMethod =         GetMethod(env, false, g_macClass, "update", "([B)V");
    g_macInitMethod =           GetMethod(env, false, g_macClass, "init", "(Ljava/security/Key;)V");
    g_macResetMethod =          GetMethod(env, false, g_macClass, "reset", "()V");

    g_sksClass =                GetClassGRef(env, "javax/crypto/spec/SecretKeySpec");
    g_sksCtor =                 GetMethod(env, false, g_sksClass, "<init>", "([BLjava/lang/String;)V");

    g_cipherClass =             GetClassGRef(env, "javax/crypto/Cipher");
    g_cipherGetInstanceMethod = GetMethod(env, true,  g_cipherClass, "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
    g_getBlockSizeMethod =      GetMethod(env, false, g_cipherClass, "getBlockSize", "()I");
    g_cipherDoFinalMethod =     GetMethod(env, false, g_cipherClass, "doFinal", "()[B");
    g_cipherDoFinal2Method =    GetMethod(env, false, g_cipherClass, "doFinal", "([B)[B");
    g_cipherUpdateMethod =      GetMethod(env, false, g_cipherClass, "update", "([B)[B");
    g_cipherUpdateAADMethod =   GetMethod(env, false, g_cipherClass, "updateAAD", "([B)V");
    g_cipherInitMethod =        GetMethod(env, false, g_cipherClass, "init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V");
    g_cipherInit2Method =       GetMethod(env, false, g_cipherClass, "init", "(ILjava/security/Key;)V");

    g_ivPsClass =               GetClassGRef(env, "javax/crypto/spec/IvParameterSpec");
    g_ivPsCtor =                GetMethod(env, false, g_ivPsClass, "<init>", "([B)V");

    g_GCMParameterSpecClass =   GetClassGRef(env, "javax/crypto/spec/GCMParameterSpec");
    g_GCMParameterSpecCtor =    GetMethod(env, false, g_GCMParameterSpecClass, "<init>", "(I[B)V");

    g_bigNumClass =             GetClassGRef(env, "java/math/BigInteger");
    g_bigNumCtor =              GetMethod(env, false, g_bigNumClass, "<init>", "([B)V");
    g_toByteArrayMethod =       GetMethod(env, false, g_bigNumClass, "toByteArray", "()[B");

    g_sslParamsClass =              GetClassGRef(env, "javax/net/ssl/SSLParameters");
    g_sslParamsGetProtocolsMethod = GetMethod(env, false,  g_sslParamsClass, "getProtocols", "()[Ljava/lang/String;");

    g_sslCtxClass =                     GetClassGRef(env, "javax/net/ssl/SSLContext");
    g_sslCtxGetDefaultMethod =          GetMethod(env, true,  g_sslCtxClass, "getDefault", "()Ljavax/net/ssl/SSLContext;");
    g_sslCtxGetDefaultSslParamsMethod = GetMethod(env, false, g_sslCtxClass, "getDefaultSSLParameters", "()Ljavax/net/ssl/SSLParameters;");

    g_CertFactoryClass =                GetClassGRef(env, "java/security/cert/CertificateFactory");
    g_CertFactoryGetInstance =          GetMethod(env, true, g_CertFactoryClass, "getInstance", "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    g_CertFactoryGenerateCertificate =  GetMethod(env, false, g_CertFactoryClass, "generateCertificate", "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;");
    g_CertFactoryGenerateCRL =          GetMethod(env, false, g_CertFactoryClass, "generateCRL", "(Ljava/io/InputStream;)Ljava/security/cert/CRL;");

    g_X509CertClass =                       GetClassGRef(env, "java/security/cert/X509Certificate");
    g_X509CertGetEncoded =                  GetMethod(env, false, g_X509CertClass, "getEncoded", "()[B");
    g_X509CertGetIssuerX500Principal =      GetMethod(env, false, g_X509CertClass, "getIssuerX500Principal", "()Ljavax/security/auth/x500/X500Principal;");
    g_X509CertGetNotAfter =                 GetMethod(env, false, g_X509CertClass, "getNotAfter", "()Ljava/util/Date;");
    g_X509CertGetNotBefore =                GetMethod(env, false, g_X509CertClass, "getNotBefore", "()Ljava/util/Date;");
    g_X509CertGetPublicKey =                GetMethod(env, false, g_X509CertClass, "getPublicKey", "()Ljava/security/PublicKey;");
    g_X509CertGetSerialNumber =             GetMethod(env, false, g_X509CertClass, "getSerialNumber", "()Ljava/math/BigInteger;");
    g_X509CertGetSigAlgOID =                GetMethod(env, false, g_X509CertClass, "getSigAlgOID", "()Ljava/lang/String;");
    g_X509CertGetSubjectX500Principal =     GetMethod(env, false, g_X509CertClass, "getSubjectX500Principal", "()Ljavax/security/auth/x500/X500Principal;");
    g_X509CertGetVersion =                  GetMethod(env, false, g_X509CertClass, "getVersion", "()I");
    
    g_X509CertGetCriticalExtensionOIDs =    GetMethod(env, false, g_X509CertClass, "getCriticalExtensionOIDs", "()Ljava/util/Set;");
    g_X509CertGetExtensionValue =           GetMethod(env, false, g_X509CertClass, "getExtensionValue", "(Ljava/lang/String;)[B");
    g_X509CertGetNonCriticalExtensionOIDs = GetMethod(env, false, g_X509CertClass, "getNonCriticalExtensionOIDs", "()Ljava/util/Set;");

    g_X509CRLClass          = GetClassGRef(env, "java/security/cert/X509CRL");
    g_X509CRLGetNextUpdate  = GetMethod(env, false, g_X509CRLClass, "getNextUpdate", "()Ljava/util/Date;");

    g_RSAKeyClass =                    GetClassGRef(env, "java/security/interfaces/RSAKey");
    g_RSAKeyGetModulus =               GetMethod(env, false, g_RSAKeyClass, "getModulus", "()Ljava/math/BigInteger;");

    g_RSAPublicKeyClass =              GetClassGRef(env, "java/security/interfaces/RSAPublicKey");
    g_RSAPublicKeyGetPubExpMethod =    GetMethod(env, false, g_RSAPublicKeyClass, "getPublicExponent", "()Ljava/math/BigInteger;");

    g_keyPairClass =                   GetClassGRef(env, "java/security/KeyPair");
    g_keyPairGetPrivateMethod =        GetMethod(env, false, g_keyPairClass, "getPrivate", "()Ljava/security/PrivateKey;");
    g_keyPairGetPublicMethod =         GetMethod(env, false, g_keyPairClass, "getPublic", "()Ljava/security/PublicKey;");

    g_keyPairGenClass =                GetClassGRef(env, "java/security/KeyPairGenerator");
    g_keyPairGenGetInstanceMethod =    GetMethod(env, true,  g_keyPairGenClass, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;");
    g_keyPairGenInitializeMethod =     GetMethod(env, false, g_keyPairGenClass, "initialize", "(I)V");
    g_keyPairGenGenKeyPairMethod =     GetMethod(env, false, g_keyPairGenClass, "genKeyPair", "()Ljava/security/KeyPair;");

    g_RSAPrivateCrtKeyClass =          GetClassGRef(env, "java/security/interfaces/RSAPrivateCrtKey");
    g_RSAPrivateCrtKeyPubExpField =    GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getPublicExponent", "()Ljava/math/BigInteger;");
    g_RSAPrivateCrtKeyPrimePField =    GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getPrimeP", "()Ljava/math/BigInteger;");
    g_RSAPrivateCrtKeyPrimeQField =    GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getPrimeQ", "()Ljava/math/BigInteger;");
    g_RSAPrivateCrtKeyPrimeExpPField = GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getPrimeExponentP", "()Ljava/math/BigInteger;");
    g_RSAPrivateCrtKeyPrimeExpQField = GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getPrimeExponentQ", "()Ljava/math/BigInteger;");
    g_RSAPrivateCrtKeyCrtCoefField =   GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getCrtCoefficient", "()Ljava/math/BigInteger;");
    g_RSAPrivateCrtKeyModulusField =   GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getModulus", "()Ljava/math/BigInteger;");
    g_RSAPrivateCrtKeyPrivExpField =   GetMethod(env, false, g_RSAPrivateCrtKeyClass, "getPrivateExponent", "()Ljava/math/BigInteger;");

    g_RSAPrivateCrtKeySpecClass =      GetClassGRef(env, "java/security/spec/RSAPrivateCrtKeySpec");
    g_RSAPrivateCrtKeySpecCtor =       GetMethod(env, false, g_RSAPrivateCrtKeySpecClass, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");

    g_RSAPublicCrtKeySpecClass =       GetClassGRef(env, "java/security/spec/RSAPublicKeySpec");
    g_RSAPublicCrtKeySpecCtor =        GetMethod(env, false, g_RSAPublicCrtKeySpecClass, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");

    g_KeyFactoryClass =                GetClassGRef(env, "java/security/KeyFactory");
    g_KeyFactoryGetInstanceMethod =    GetMethod(env, true, g_KeyFactoryClass, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyFactory;");
    g_KeyFactoryGenPrivateMethod =     GetMethod(env, false, g_KeyFactoryClass, "generatePrivate", "(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;");
    g_KeyFactoryGenPublicMethod =      GetMethod(env, false, g_KeyFactoryClass, "generatePublic", "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;");

    g_X509EncodedKeySpecClass       = GetClassGRef(env, "java/security/spec/X509EncodedKeySpec");
    g_X509EncodedKeySpecCtor        = GetMethod(env, false, g_X509EncodedKeySpecClass, "<init>", "([B)V");

    g_DateClass     = GetClassGRef(env, "java/util/Date");
    g_DateGetTime   = GetMethod(env, false, g_DateClass, "getTime", "()J");

    g_X500PrincipalClass =      GetClassGRef(env, "javax/security/auth/x500/X500Principal");
    g_X500PrincipalGetEncoded = GetMethod(env, false, g_X500PrincipalClass, "getEncoded", "()[B");
    g_X500PrincipalHashCode =   GetMethod(env, false, g_X500PrincipalClass, "hashCode", "()I");

    //g_NativeCryptoClass =              GetClassGRef(env, "com/android/org/conscrypt/NativeCrypto");

    return JNI_VERSION_1_6;
}
