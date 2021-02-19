#include "pal_x509.h"

#include <inttypes.h>
#include <time.h>

uint8_t * read_file(const char *path, long *len_out);
void print_hex(const uint8_t *arr, int32_t len);

typedef int32_t (*get_buffer_func)(void *ctx, uint8_t *buf, int32_t len);
void get_buffer(get_buffer_func func, void*ctx, uint8_t **buf, int32_t *buf_len)
{
    int32_t len = func(ctx, NULL, 0);
    len = -len;

    *buf = malloc(len);
    int32_t ret = func(ctx, *buf, len);
    assert(ret == 1);

    *buf_len = len;
}

void enum_extensions_callback(const char *oid, int32_t oid_len, const uint8_t *data, int32_t data_len, bool isCritical, void *context)
{
    printf("  * %s\n  ", oid);
    print_hex(data, data_len);
    printf("    Critical: %d\n", isCritical);
}

void basic_properties(const char *cert_path)
{
    printf("=== %s ===\n", cert_path);

    long cert_len;
    uint8_t *cert_buffer = read_file(cert_path, &cert_len);

    jobject cert = AndroidCryptoNative_DecodeX509(cert_buffer, cert_len);

    // Re-encode
    {
        int32_t len;
        uint8_t *encoded = NULL;
        get_buffer(&AndroidCryptoNative_EncodeX509, cert, &encoded, &len);
        for (int i = 0; i < len; ++i)
            assert(cert_buffer[i] == encoded[i]);

        free(encoded);
    }

    free(cert_buffer);

    printf("[Version]\n  ");
    int32_t ver = AndroidCryptoNative_X509GetVersion(cert);
    printf("%d\n", ver);

    printf("[Subject]\n");
    {
        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&AndroidCryptoNative_X509GetSubjectNameBytes, cert, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Issuer]\n");
    {
        uint64_t hash = AndroidCryptoNative_X509IssuerNameHash(cert);
        printf("  Hash: %" PRIu64 "\n", hash);

        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&AndroidCryptoNative_X509GetIssuerNameBytes, cert, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Serial Number]\n");
    {
        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&AndroidCryptoNative_X509GetSerialNumber, cert, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Not Before]\n");
    {
        int64_t not_before = AndroidCryptoNative_X509GetNotBefore(cert);
        time_t not_before_time = not_before / 1000;
        printf("  %s", asctime(localtime(&not_before_time)));
    }

    printf("[Not After]\n");
    {
        int64_t not_after = AndroidCryptoNative_X509GetNotAfter(cert);
        time_t not_after_time = not_after / 1000;
        printf("  %s", asctime(localtime(&not_after_time)));
    }

    printf("[Thumbprint]\n");
    {
        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&AndroidCryptoNative_X509GetThumbprint, cert, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Signature Algorithm]\n");
    {
        int32_t len;
        char *buf = NULL;
        get_buffer(&AndroidCryptoNative_X509GetSignatureAlgorithm, cert, &buf, &len);
        printf("  %s\n", buf);
        free(buf);
    }

    printf("[Public Key]\n");
    {
        int32_t len;
        char *buf = NULL;
        get_buffer(&AndroidCryptoNative_X509GetPublicKeyAlgorithm, cert, &buf, &len);
        printf("  Algorithm: %s\n", buf);
        free(buf);
    }
    {
        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&AndroidCryptoNative_X509GetPublicKeyBytes, cert, &buf, &len);
        printf("  Bytes: ");
        print_hex(buf, len);
        free(buf);
    }
    {
        printf("  Parameters: \n");
    }

    printf("[Extensions]\n");
    {
        AndroidCryptoNative_X509EnumExtensions(cert, &enum_extensions_callback, NULL);
    }

    CryptoNative_X509Destroy(cert);
}

void x509_test()
{
    const char *cert_path = "[REPLACE]";
    basic_properties(cert_path);
}

void print_hex(const uint8_t *arr, int32_t len)
{
    for (int i = 0; i < len; ++i)
        printf("%02X", arr[i]);

    printf("\n");
}

uint8_t* read_file(const char *path, long *len_out)
{
    *len_out = 0;
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        printf("fopen failed: %d [%s]", errno, path);
        return NULL;
    }

    int res = fseek(file, 0, SEEK_END);
    if (res != 0)
    {
        printf("fseek failed");
        return NULL;
    }

    long size = ftell(file);
    rewind(file);
    long len = sizeof(uint8_t) * size;
    uint8_t *buffer = (uint8_t *)malloc(len);
    if (buffer == NULL)
    {
        printf("malloc returned NULL\n");
        return NULL;
    }

    res = fread(buffer, 1, size, file);
    if (res != size)
    {
        printf("fread failed");
        return NULL;
    }

    fclose(file);
    *len_out = len;
    return buffer;
}
