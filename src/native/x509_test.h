#include "pal_x509.h"

#include <inttypes.h>
#include <time.h>

uint8_t * read_file(const char *path, long *len_out);
void print_hex(uint8_t *arr, int32_t len);

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

void basic_properties(const char *cert_path)
{
    printf("=== %s ===\n", cert_path);

    long cert_len;
    uint8_t *cert_buffer = read_file(cert_path, &cert_len);

    jobject cert = CryptoNative_DecodeX509(cert_buffer, cert_len);

    // Re-encode
    {
        int32_t len;
        uint8_t *encoded = NULL;
        get_buffer(&CryptoNative_EncodeX509, cert, &encoded, &len);
        for (int i = 0; i < len; ++i)
            assert(cert_buffer[i] == encoded[i]);

        free(encoded);
    }

    free(cert_buffer);

    printf("[Version]\n  ");
    int32_t ver = CryptoNative_GetX509Version(cert);
    printf("%d\n", ver);

    printf("[Subject]\n");
    {
        jobject subject = CryptoNative_X509GetSubjectName(cert);

        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&CryptoNative_GetX509NameRawBytes, subject, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Issuer]\n");
    {
        jobject issuer = CryptoNative_X509GetIssuerName(cert);

        uint64_t hash = CryptoNative_X509IssuerNameHash(cert);
        printf("  Hash: %" PRIu64 "\n", hash);

        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&CryptoNative_GetX509NameRawBytes, issuer, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Serial Number]\n");
    {
        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&CryptoNative_X509GetSerialNumber, cert, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Not Before]\n");
    {
        int64_t not_before = CryptoNative_GetX509NotBefore(cert);
        time_t not_before_time = not_before / 1000;
        printf("  %s", asctime(localtime(&not_before_time)));
    }

    printf("[Not After]\n");
    {
        int64_t not_after = CryptoNative_GetX509NotAfter(cert);
        time_t not_after_time = not_after / 1000;
        printf("  %s", asctime(localtime(&not_after_time)));
    }

    printf("[Thumbprint]\n");
    {
        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&CryptoNative_GetX509Thumbprint, cert, &buf, &len);
        printf("  ");
        print_hex(buf, len);
        free(buf);
    }

    printf("[Signature Algorithm]\n");
    {
        int32_t len;
        char *buf = NULL;
        get_buffer(&CryptoNative_GetX509SignatureAlgorithm, cert, &buf, &len);
        printf("  %s\n", buf);
        free(buf);
    }

    printf("[Public Key]\n");
    {
        int32_t len;
        char *buf = NULL;
        get_buffer(&CryptoNative_GetX509PublicKeyAlgorithm, cert, &buf, &len);
        printf("  Algorithm: %s\n", buf);
        free(buf);
    }
    {
        int32_t len;
        uint8_t *buf = NULL;
        get_buffer(&CryptoNative_GetX509PublicKeyBytes, cert, &buf, &len);
        printf("  Bytes: ");
        print_hex(buf, len);
        free(buf);
    }
    {
        printf("  Parameters: \n");
    }

    printf("[Extensions]\n  ");

    CryptoNative_X509Destroy(cert);
}

void x509_test()
{
    const char *cert_path = "[REPLACE]";
    basic_properties(cert_path);
}

void print_hex(uint8_t *arr, int32_t len)
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