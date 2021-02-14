#include "pal_x509.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

int32_t PopulateByteArray(JNIEnv *env, jbyteArray source, uint8_t *dest, int32_t len);
int32_t PopulateString(JNIEnv *env, jstring source, char *dest, int32_t len);

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
    jobject ret = (*env)->CallObjectMethod(env, certFactory, g_CertFactoryGenerateCertificate, stream);

    (*env)->DeleteLocalRef(env, bytes);
    (*env)->DeleteLocalRef(env, stream);
    (*env)->DeleteLocalRef(env, certType);
    (*env)->DeleteLocalRef(env, certFactory);
    return ToGRef(env, ret);
}

// Encodes as DER format
int32_t CryptoNative_EncodeX509(jobject /*X509Certificate*/ cert, uint8_t *buf, int32_t len)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // byte[] encoded = cert.getEncoded();
    // return encoded.length
    jbyteArray encoded =  (*env)->CallObjectMethod(env, cert, g_X509CertGetEncoded);
    int32_t ret = PopulateByteArray(env, encoded, buf, len);
    jsize bytesLen = (*env)->GetArrayLength(env, encoded);

    (*env)->DeleteLocalRef(env, encoded);
    return ret;
}

void CryptoNative_X509Destroy(jobject /*X509Certificate*/ cert)
{
    ReleaseGRef(GetJNIEnv(), cert);
}

jobject /*X509Certificate*/ CryptoNative_X509UpRef(jobject /*X509Certificate*/ cert)
{
    return AddGRef(GetJNIEnv(), cert);
}

int32_t CryptoNative_GetX509Thumbprint(jobject /*X509Certificate*/ cert, uint8_t *buf, int32_t len)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // MessageDigest md = MessageDigest.getInstance("SHA-1");
    jstring algorithm = JSTRING("SHA-1");
    jobject md = (*env)->CallStaticObjectMethod(env, g_mdClass, g_mdGetInstanceMethod, algorithm);

    // byte[] encoded = cert.getEncoded();
    jbyteArray encoded = (*env)->CallObjectMethod(env, cert, g_X509CertGetEncoded);

    // byte[] thumbprint = md.digest(encoded);
    // return thumbprint.length;
    jbyteArray thumbprint = (*env)->CallObjectMethod(env, md, g_mdDigestMethod, encoded);
    int32_t ret = PopulateByteArray(env, thumbprint, buf, len);

    (*env)->DeleteLocalRef(env, algorithm);
    (*env)->DeleteLocalRef(env, md);
    (*env)->DeleteLocalRef(env, encoded);
    (*env)->DeleteLocalRef(env, thumbprint);
    return ret;
}

int64_t CryptoNative_GetX509NotBefore(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // Date notBefore = cert.getNotBefore()
    // return notBefore.getTime()
    jobject notBefore = (*env)->CallObjectMethod(env, cert, g_X509CertGetNotBefore);
    jlong time = (*env)->CallLongMethod(env, notBefore, g_DateGetTime);

    (*env)->DeleteLocalRef(env, notBefore);
    return (int64_t)time;
}

int64_t CryptoNative_GetX509NotAfter(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // Date notAfter = cert.getNotAfter()
    // return notAfter.getTime()
    jobject notAfter = (*env)->CallObjectMethod(env, cert, g_X509CertGetNotAfter);
    jlong time = (*env)->CallLongMethod(env, notAfter, g_DateGetTime);

    (*env)->DeleteLocalRef(env, notAfter);
    return (int64_t)time;
}

int32_t CryptoNative_GetX509Version(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // return cert.getVersion();
    jint ver = (*env)->CallIntMethod(env, cert, g_X509CertGetVersion);
    return (int32_t)ver;
}

int32_t CryptoNative_GetX509PublicKeyAlgorithm(jobject /*X509Certificate*/ cert, char *buf, int32_t len)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // PublicKey key = cert.getPublicKey();
    // String algorithm = key.getAlgorithm();
    // return encoded.length;
    jobject key = (*env)->CallObjectMethod(env, cert, g_X509CertGetPublicKey);
    jstring algorithm = (*env)->CallObjectMethod(env, key, g_KeyGetAlgorithm);
    int32_t ret = PopulateString(env, algorithm, buf, len);

    (*env)->DeleteLocalRef(env, key);
    (*env)->DeleteLocalRef(env, algorithm);
    return ret;
}

int32_t CryptoNative_GetX509SignatureAlgorithm(jobject /*X509Certificate*/ cert, char *buf, int32_t len)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // String oid = cert.getSigAlgOID()
    // return oid.length;
    jstring oid = (jstring)(*env)->CallObjectMethod(env, cert, g_X509CertGetSigAlgOID);
    int32_t ret = PopulateString(env, oid, buf, len);

    (*env)->DeleteLocalRef(env, oid);
    return ret;
}

int32_t CryptoNative_GetX509PublicKeyParameterBytes(jobject /*X509Certificate*/ cert, uint8_t *pBuf, int32_t cBuf)
{
    // [TODO]
    // PublicKey key = cert.publicKey()
    // String algorithm = key.getAlgorithm()
    // if (algorithm == "...") ...
    // getParams()
    return 0;
}

// [TODO] This is currently returning the key with the algorithm (SubjectPublicKeyInfo
int32_t CryptoNative_GetX509PublicKeyBytes(jobject /*X509Certificate*/ cert, uint8_t *buf, int32_t len)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // PublicKey key = cert.getPublicKey();
    // byte[] keyInfoBytes = key.getEncoded();
    jobject key = (*env)->CallObjectMethod(env, cert, g_X509CertGetPublicKey);
    jbyteArray keyInfoBytes = (*env)->CallObjectMethod(env, key, g_KeyGetEncoded);

    // return keyInfoBytes.length;
    int32_t ret = PopulateByteArray(env, keyInfoBytes, buf, len);

    (*env)->DeleteLocalRef(env, key);
    (*env)->DeleteLocalRef(env, keyInfoBytes);
    return ret;
}

// Serial number as a byte array in big-endian byte-order
int32_t CryptoNative_X509GetSerialNumber(jobject /*X509Certificate*/ cert, uint8_t *buf, int32_t len)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // BigInteger serial = cert.getSerialNumber();
    // buf = serial.toByteArray();
    // return buf.length;
    jobject serial = (*env)->CallObjectMethod(env, cert, g_X509CertGetSerialNumber);
    jbyteArray bytes = (jbyteArray)(*env)->CallObjectMethod(env, serial, g_toByteArrayMethod);
    int32_t ret = PopulateByteArray(env, bytes, buf, len);

    (*env)->DeleteLocalRef(env, serial);
    (*env)->DeleteLocalRef(env, bytes);
    return ret;
}

jobject /*X500Principal*/ CryptoNative_X509GetIssuerName(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return NULL;

    JNIEnv *env = GetJNIEnv();

    // return cert.getIssuerX500Principal()
    jobject issuer = (*env)->CallObjectMethod(env, cert, g_X509CertGetIssuerX500Principal);
    return ToGRef(env, issuer);
}

jobject /*X500Principal*/ CryptoNative_X509GetSubjectName(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return NULL;

    JNIEnv *env = GetJNIEnv();

    // return cert.getSubjectX500Principal()
    jobject subject = (*env)->CallObjectMethod(env, cert, g_X509CertGetSubjectX500Principal);
    return ToGRef(env, subject);
}

int32_t CryptoNative_GetX509NameRawBytes(jobject /*X500Principal*/ name, uint8_t *buf, int32_t len)
{
    if (name == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // byte[] raw = name.getEncoded();
    // return raw.length
    jbyteArray encoded = (*env)->CallObjectMethod(env, name, g_X500PrincipalGetEncoded);
    int32_t ret = PopulateByteArray(env, encoded, buf, len);

    (*env)->DeleteLocalRef(env, encoded);
    return ret;
}

uint64_t CryptoNative_X509IssuerNameHash(jobject /*X509Certificate*/ cert)
{
    if (cert == NULL)
        return 0;

    JNIEnv *env = GetJNIEnv();

    // X500Principal issuer = cert.getIssuerX500Principal()
    // return issuer.hashCode();
    jobject issuer = (*env)->CallObjectMethod(env, cert, g_X509CertGetIssuerX500Principal);
    jint hash = (*env)->CallIntMethod(env, issuer, g_X500PrincipalHashCode);

    (*env)->DeleteLocalRef(env, issuer);
    return (uint64_t)hash;
}

int32_t AndroidCryptoNative_X509EnumExtensions(jobject /*X509Certificate*/ cert, EnumX509ExtensionsCallback cb, void *context)
{
    // Set<string> crit = cert.getCriticalExtensionOIDs();
    // Set<string> noncrit = cert.getNonCriticalExtensionOIDs();
    return 0;
}

int32_t AndroidCryptoNative_X509FindExtensionData(jobject /*X509Certificate*/ cert, const char *oid, uint8_t *buf, int32_t len)
{
    // byte[] data = cert.getExtensionValue(oid);
    // return data.length;
    return 0;
}


jobject /*X509CRL*/ CryptoNative_DecodeX509Crl(const uint8_t *buf, int32_t len)
{
    if (buf == NULL || len == 0)
        return NULL;

    JNIEnv *env = GetJNIEnv();

    // byte[] bytes = new byte[] { ... }
    // InputStream stream = new ByteArrayInputStream(bytes);
    jbyteArray bytes = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte *)buf);
    jobject stream = (*env)->NewObject(env, g_ByteArrayInputStreamClass, g_ByteArrayInputStreamCtor, bytes);

    // CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    // return (X509CRL)certFactory.generateCRL(stream);
    jstring certType = JSTRING("X.509");
    jobject certFactory = (*env)->CallStaticObjectMethod(env, g_CertFactoryClass, g_CertFactoryGetInstance, certType);

    jobject ret = (*env)->CallObjectMethod(env, certFactory, g_CertFactoryGenerateCRL, stream);

    (*env)->DeleteLocalRef(env, bytes);
    (*env)->DeleteLocalRef(env, stream);
    (*env)->DeleteLocalRef(env, certType);
    (*env)->DeleteLocalRef(env, certFactory);
    return ToGRef(env, ret);
}

long CryptoNative_GetX509CrlNextUpdate(jobject /*X509CRL*/ crl)
{
    if (crl == NULL)
        return 0;

    return 0;
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
}

int32_t CryptoNative_EncodeX509SubjectPublicKeyInfo(jobject /*X509Certificate*/ cert, uint8_t* buf)
{
    if (cert == NULL)
        return 0;

    return 0;
}

int32_t PopulateByteArray(JNIEnv *env, jbyteArray source, uint8_t *dest, int32_t len)
{
    jsize bytesLen = (*env)->GetArrayLength(env, source);

    // Insufficient buffer
    if (len < bytesLen)
        return -bytesLen;

    (*env)->GetByteArrayRegion(env, source, 0, bytesLen, dest);
    return CheckJNIExceptions(env) ? FAIL : SUCCESS;
}

int32_t PopulateString(JNIEnv *env, jstring source, char *dest, int32_t len)
{
    // Length with null terminator
    jsize bytesLen = (*env)->GetStringUTFLength(env, source) + 1;
 
    // Insufficient buffer
    if (len < bytesLen)
        return -bytesLen;
    
    jsize strLen = (*env)->GetStringLength(env, source);
    (*env)->GetStringUTFRegion(env, source, 0, strLen, dest);
    return CheckJNIExceptions(env) ? FAIL : SUCCESS;
}