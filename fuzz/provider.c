/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include <string.h>
#include "openssl/types.h"
#include "openssl/crypto.h"
#include "openssl/core_names.h"
#include "openssl/kdf.h"
#include "openssl/evp.h"
#include "openssl/provider.h"
#include "fuzzer.h"

#define DEFINE_ALGORITHMS(name, evp) DEFINE_STACK_OF(evp) \
    static int cmp_##evp(const evp *const *a, const evp *const *b); \
    static void collect_##evp(evp * digest, void * stack); \
    static void init_##name(OSSL_LIB_CTX * libctx); \
    static void cleanup_##name(void); \
    static STACK_OF(evp) * name##_collection; \
    static int cmp_##evp(const evp *const *a, const evp *const *b) \
    { \
        return strcmp(OSSL_PROVIDER_get0_name(evp##_get0_provider(*a)), \
                      OSSL_PROVIDER_get0_name(evp##_get0_provider(*b))); \
    } \
    static void collect_##evp(evp * digest, void * stack) \
    { \
        STACK_OF(evp) *digest_stack = stack;  \
        \
        if (sk_##evp##_push(digest_stack, digest) > 0) \
            evp##_up_ref(digest); \
    } \
    static void init_##name(OSSL_LIB_CTX * libctx) \
    { \
        name##_collection = sk_##evp##_new(cmp_##evp); \
        evp##_do_all_provided(libctx, collect_##evp, name##_collection); \
    } \
    static void cleanup_##name(void) \
    { \
        sk_##evp##_free(name##_collection); \
    }

DEFINE_ALGORITHMS(digests, EVP_MD)

DEFINE_ALGORITHMS(kdf, EVP_KDF)

DEFINE_ALGORITHMS(cipher, EVP_CIPHER)

DEFINE_ALGORITHMS(kem, EVP_KEM)

DEFINE_ALGORITHMS(keyexch, EVP_KEYEXCH)

DEFINE_ALGORITHMS(rand, EVP_RAND)

DEFINE_ALGORITHMS(mac, EVP_MAC)

DEFINE_ALGORITHMS(keymgmt, EVP_KEYMGMT)

DEFINE_ALGORITHMS(signature, EVP_SIGNATURE)

DEFINE_ALGORITHMS(asym_ciphers, EVP_ASYM_CIPHER)

static OSSL_LIB_CTX *libctx = NULL;

int FuzzerInitialize(int *argc, char ***argv)
{
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        return 0;

    init_digests(libctx);
    init_kdf(libctx);
    init_cipher(libctx);
    init_kem(libctx);
    init_keyexch(libctx);
    init_rand(libctx);
    init_mac(libctx);
    init_keymgmt(libctx);
    init_signature(libctx);
    init_asym_ciphers(libctx);
    return 1;
}

void FuzzerCleanup(void)
{
    cleanup_digests();
    cleanup_kdf();
    cleanup_cipher();
    cleanup_kem();
    cleanup_keyexch();
    cleanup_rand();
    cleanup_mac();
    cleanup_keymgmt();
    cleanup_signature();
    cleanup_asym_ciphers();

    OSSL_LIB_CTX_free(libctx);
}

static int read_uint(const uint8_t **buf, size_t *len, uint64_t **res)
{
    int r = 1;

    if (*len < sizeof(uint64_t)) {
        r = 0;
        goto end;
    }

    *res = (uint64_t *) *buf;
    *buf += sizeof(uint64_t);
    *len -= sizeof(uint64_t);
end:
    return r;
}

static int read_int(const uint8_t **buf, size_t *len, int64_t **res)
{
    int r = 1;

    if (*len < sizeof(int64_t)) {
        r = 0;
        goto end;
    }

    *res = (int64_t *) *buf;
    *buf += sizeof(int64_t);
    *len -= sizeof(int64_t);
end:
    return r;
}

static int read_double(const uint8_t **buf, size_t *len, double **res)
{
    int r = 1;

    if (*len < sizeof(double)) {
        r = 0;
        goto end;
    }

    *res = (double *) *buf;
    *buf += sizeof(double);
    *len -= sizeof(double);
end:
    return r;
}

static int read_utf8_string(const uint8_t **buf, size_t *len, char **res)
{
    int r;
    const uint8_t *ptr = *buf;
    int found = 0;

    for (size_t i = 0; i < *len; ++i) {
        if (*ptr == 0) {
            ptr++;
            found = 1;
            break;
        }
        ptr++;
    }

    if (!found) {
        r = -1;
        goto end;
    }

    *res = (char *) *buf;

    r = ptr - *buf;
    *len -= r;
    *buf = ptr;

end:
    return r;
}

static int read_utf8_ptr(const uint8_t **buf, size_t *len, char **res)
{
    if (*len > 0 && **buf == 0xFF) {
        /* represent NULL somehow */
        *res = NULL;
        *buf += 1;
        *len -= 1;
        return 0;
    }
    return read_utf8_string(buf, len, res);
}

static int read_octet_string(const uint8_t **buf, size_t *len, char **res)
{
    int r;
    const uint8_t *ptr = *buf;
    int found = 0;

    for (size_t i = 0; i < *len; ++i) {
        if (*ptr == 0xFF &&
            (i + 1 < *len && *(ptr + 1) == 0xFF)) {
            ptr++;
            found = 1;
            break;
        }
        ptr++;
    }

    if (!found) {
        r = -1;
        goto end;
    }

    *res = (char *) *buf;

    r = ptr - *buf;
    *len -= r;
    *buf = ptr;

end:
    return r;
}

static int read_octet_ptr(const uint8_t **buf, size_t *len, char **res)
{
    /* TODO: This representation could need an improvement potentially. */
    if (*len > 1 && **buf == 0xFF && *(*buf + 1) == 0xFF) {
        /* represent NULL somehow */
        *res = NULL;
        *buf += 2;
        *len -= 2;
        return 0;
    }
    return read_octet_string(buf, len, res);
}

static int64_t NO_PARAM = 0;
static int64_t DFLT_INT = 0;
static uint64_t DFLT_UINT = 0;
static double DFLT_DOUBLE = 0;
static char *DFLT_STR = "";
static char *DFLT_UTF8_PTR = NULL;
static char *DFLT_OCTET_STRING = NULL;
static char *DFLT_OCTET_PTR = NULL;

static int64_t ITERS = 1;
static uint64_t UITERS = 1;
static int64_t BLOCKSIZE = 8;
static uint64_t UBLOCKSIZE = 8;

static OSSL_PARAM *fuzz_params(OSSL_PARAM *param, const uint8_t **buf, size_t *len)
{
    OSSL_PARAM *p;
    int p_num = 0;

    for (p = param; p != NULL && p->key != NULL; p++) {
        p_num++;
    }

    OSSL_PARAM *fuzzed_parameters = OPENSSL_zalloc(sizeof(OSSL_PARAM) * (p_num + 1));
    p = fuzzed_parameters;

    for (; param != NULL && param->key != NULL; param++) {
        int64_t *use_param = NULL;
        int64_t *p_value_int = &DFLT_INT;
        uint64_t *p_value_uint = &DFLT_UINT;
        double *p_value_double = &DFLT_DOUBLE;
        char *p_value_utf8_str = DFLT_STR;
        char *p_value_octet_str = DFLT_OCTET_STRING;
        char *p_value_utf8_ptr = DFLT_UTF8_PTR;
        char *p_value_octet_ptr = DFLT_OCTET_PTR;
        int data_len = 0;

        if (!read_int(buf, len, &use_param)) {
            use_param = &NO_PARAM;
        }

        switch (param->data_type) {
        case OSSL_PARAM_INTEGER:
            if (*use_param && !read_int(buf, len, &p_value_int)) {
                /* use default */
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_ITER) == 0) {
                p_value_int = &ITERS;
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_SCRYPT_N) == 0) {
                p_value_int = &ITERS;
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_SCRYPT_R) == 0) {
                p_value_int = &BLOCKSIZE;
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_SCRYPT_P) == 0) {
                p_value_int = &BLOCKSIZE;
            }

            *p = *param;
            p->data = p_value_int;
            p++;
            break;
        case OSSL_PARAM_UNSIGNED_INTEGER:
            if (*use_param && !read_uint(buf, len, &p_value_uint)) {
                /* use default */
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_ITER) == 0) {
                p_value_uint = &UITERS;
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_SCRYPT_N) == 0) {
                p_value_uint = &UITERS;
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_SCRYPT_R) == 0) {
                p_value_uint = &UBLOCKSIZE;
            }

            if (strcmp(param->key, OSSL_KDF_PARAM_SCRYPT_P) == 0) {
                p_value_uint = &UBLOCKSIZE;
            }

            *p = *param;
            p->data = p_value_uint;
            p++;
            break;
        case OSSL_PARAM_REAL:
            if (*use_param && !read_double(buf, len, &p_value_double)) {
                /* use default */
            }
            *p = *param;
            p->data = p_value_double;
            p++;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (*use_param && (data_len = read_utf8_string(buf, len, &p_value_utf8_str)) < 0) {
                data_len = 0;
            }
            *p = *param;
            p->data = p_value_utf8_str;
            p->data_size = data_len;
            p++;
            break;
        case OSSL_PARAM_OCTET_STRING:
            if (*use_param && (data_len = read_octet_string(buf, len, &p_value_octet_str)) < 0) {
                data_len = 0;
            }
            *p = *param;
            p->data = p_value_octet_str;
            p->data_size = data_len;
            p++;
            break;
        case OSSL_PARAM_UTF8_PTR:
            if (*use_param && (data_len = read_utf8_ptr(buf, len, &p_value_utf8_ptr)) < 0) {
                data_len = 0;
            }
            *p = *param;
            p->data = p_value_utf8_ptr;
            p->data_size = data_len;
            p++;
            break;
        case OSSL_PARAM_OCTET_PTR:
            if (*use_param && (data_len = read_octet_ptr(buf, len, &p_value_octet_ptr)) < 0) {
                data_len = 0;
            }
            *p = *param;
            p->data = p_value_octet_ptr;
            p->data_size = data_len;
            p++;
            break;
        default:
            break;
        }
    }

    return fuzzed_parameters;
}

static int do_evp_cipher(const EVP_CIPHER *evp_cipher, const OSSL_PARAM param[])
{
    unsigned char outbuf[1024];
    int outlen, tmplen;
    unsigned char key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    unsigned char iv[] = {1, 2, 3, 4, 5, 6, 7, 8};
    const char intext[] = "text";
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_CIPHER_CTX_set_params(ctx, param)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_EncryptInit_ex2(ctx, evp_cipher, key, iv, NULL)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, (const unsigned char *) intext, strlen(intext))) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    /*
     * Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static int do_evp_kdf(EVP_KDF *evp_kdf, const OSSL_PARAM params[])
{
    int r = 1;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char derived[32];

    kctx = EVP_KDF_CTX_new(evp_kdf);

    if (kctx == NULL) {
        r = 0;
        goto end;
    }

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        r = 0;
        goto end;
    }

    if (EVP_KDF_derive(kctx, derived, sizeof(derived), NULL) <= 0) {
        r = 0;
        goto end;
    }

end:
    EVP_KDF_CTX_free(kctx);
    return r;
}

static int do_evp_mac(EVP_MAC *evp_mac, const OSSL_PARAM params[])
{
    int r = 1;
    const char *key = "mac_key";
    char text[] = "Some Crypto Text";
    EVP_MAC_CTX *ctx = NULL;
    unsigned char buf[4096];
    size_t final_l;

    if ((ctx = EVP_MAC_CTX_new(evp_mac)) == NULL
        || !EVP_MAC_init(ctx, (const unsigned char *) key, strlen(key),
                         params)) {
        r = 0;
        goto end;
    }

    if (EVP_MAC_CTX_set_params(ctx, params) <= 0) {
        r = 0;
        goto end;
    }

    if (!EVP_MAC_update(ctx, (unsigned char *) text, sizeof(text))) {
        r = 0;
        goto end;
    }

    if (!EVP_MAC_final(ctx, buf, &final_l, sizeof(buf))) {
        r = 0;
        goto end;
    }

end:
    EVP_MAC_CTX_free(ctx);
    return r;
}

static int do_evp_rand(EVP_RAND *evp_rand, const OSSL_PARAM params[])
{
    int r = 1;
    EVP_RAND_CTX *ctx = NULL;
    unsigned char buf[4096];

    if (!(ctx = EVP_RAND_CTX_new(evp_rand, NULL))) {
        r = 0;
        goto end;
    }

    if (EVP_RAND_CTX_set_params(ctx, params) <= 0) {
        r = 0;
        goto end;
    }

    if (!EVP_RAND_generate(ctx, buf, sizeof(buf), 0, 0, NULL, 0)) {
        r = 0;
        goto end;
    }

    if (!EVP_RAND_reseed(ctx, 0, 0, 0, NULL, 0)) {
        r = 0;
        goto end;
    }

end:
    EVP_RAND_CTX_free(ctx);
    return r;
}

static int do_evp_sig(EVP_SIGNATURE *evp_sig, const OSSL_PARAM params[])
{
    return 0;
}

static int do_evp_asym_cipher(EVP_ASYM_CIPHER *evp_asym_cipher, const OSSL_PARAM params[])
{
    return 0;
}

static int do_evp_kem(EVP_KEM *evp_kem, const OSSL_PARAM params[])
{
    return 0;
}

static int do_evp_key_exch(EVP_KEYEXCH *evp_kdf, const OSSL_PARAM params[])
{
    return 0;
}

static int do_evp_md(EVP_MD *evp_md, const OSSL_PARAM params[])
{
    int r = 1;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_MD_CTX *mdctx = NULL;

    if (!(mdctx = EVP_MD_CTX_new())) {
        r = 0;
        goto end;
    }

    if (!EVP_MD_CTX_set_params(mdctx, params)) {
        r = 0;
        goto end;
    }

    if (!EVP_DigestInit_ex2(mdctx, evp_md, NULL)) {
        r = 0;
        goto end;
    }
    if (!EVP_DigestUpdate(mdctx, "Test", strlen("Test"))) {
        r = 0;
        goto end;
    }
    if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len)) {
        r = 0;
        goto end;
    }

end:
    EVP_MD_CTX_free(mdctx);
    return r;
}

#define EVP_FUZZ(source, evp, f) \
    do { \
        evp * alg = sk_##evp##_value(source, *algorithm % sk_##evp##_num(source)); \
        \
        if (!alg) { \
            break; \
        } \
        OSSL_PARAM *fuzzed_params = fuzz_params((OSSL_PARAM*) evp##_settable_ctx_params(alg), &buf, &len); \
        if (fuzzed_params) { \
            f(alg, fuzzed_params); \
        } \
        OSSL_PARAM_free(fuzzed_params); \
    } while (0);

static uint64_t DFLT_OP = 0;
static int64_t DFLT_ALG = 0;

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    int r = 1;
    uint64_t *operation = &DFLT_OP;
    int64_t *algorithm = &DFLT_ALG;

    if (!read_uint(&buf, &len, &operation)) {
        r = 0;
        goto end;
    }

    if (!read_int(&buf, &len, &algorithm)) {
        r = 0;
        goto end;
    }

    switch (*operation % 10) {
    case 0:
        EVP_FUZZ(digests_collection, EVP_MD, do_evp_md);
        break;
    case 1:
        EVP_FUZZ(cipher_collection, EVP_CIPHER, do_evp_cipher);
        break;
    case 2:
        EVP_FUZZ(kdf_collection, EVP_KDF, do_evp_kdf);
        break;
    case 3:
        EVP_FUZZ(mac_collection, EVP_MAC, do_evp_mac);
        break;
    case 4:
        EVP_FUZZ(kem_collection, EVP_KEM, do_evp_kem);
        break;
    case 5:
        EVP_FUZZ(rand_collection, EVP_RAND, do_evp_rand);
        break;
    case 6:
        EVP_FUZZ(asym_ciphers_collection, EVP_ASYM_CIPHER, do_evp_asym_cipher);
        break;
    case 7:
        EVP_FUZZ(signature_collection, EVP_SIGNATURE, do_evp_sig);
        break;
    case 8:
        EVP_FUZZ(keyexch_collection, EVP_KEYEXCH, do_evp_key_exch);
        break;
    case 9:
        /*
        Implement and call:
        static int do_evp_keymgmt(EVP_KEYMGMT *evp_kdf, const OSSL_PARAM params[])
        {
            return 0;
        }
        */
        /* not yet implemented */
        break;
    default:
        r = 0;
        goto end;
    }

end:
    return r;
}
