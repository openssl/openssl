/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <openssl/opensslconf.h>

#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "testutil.h"


/* Use a buffer size which is not aligned to block size */
#define BUFFER_SIZE     17

#ifndef OPENSSL_NO_ENGINE
static ENGINE *e;
#endif


#ifndef OPENSSL_NO_AFALGENG
# include <linux/version.h>
# define K_MAJ   4
# define K_MIN1  1
# define K_MIN2  0
# if LINUX_VERSION_CODE < KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)
/*
 * If we get here then it looks like there is a mismatch between the linux
 * headers and the actual kernel version, so we have tried to compile with
 * afalg support, but then skipped it in e_afalg.c. As far as this test is
 * concerned we behave as if we had been configured without support
 */
#  define OPENSSL_NO_AFALGENG
# endif
#endif

#ifndef OPENSSL_NO_AFALGENG

#if defined(OPENSSL_SYS_UNIX)
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#endif

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};
static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};
static const unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};
static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};
static const unsigned char gcm_ct_128[] = {
    0xf5, 0xc9, 0x4f, 0x28, 0x9c, 0x59, 0xd0, 0x74, 0xb8, 0x43, 0x2e, 0xf8,
    0xe4, 0xab, 0x0a, 0x72
};
static const unsigned char gcm_tag_128[] = {
    0xdc, 0x63, 0x1e, 0xbe, 0xcf, 0x1e, 0x4f, 0x3a, 0x01, 0x62, 0xa3, 0x86,
    0xd6, 0x0d, 0x4a, 0x1e
};
static const unsigned char gcm_ct_192[] = {
    0x63, 0x87, 0x7f, 0xc0, 0xcf,0x0c, 0xb8, 0x6f, 0x21, 0x62, 0x1d, 0x2d,
    0x8d, 0xcc, 0xc3, 0x7c
};
static const unsigned char gcm_tag_192[] = {
    0x7a, 0x70, 0xba, 0x98, 0x9d, 0x67, 0x65, 0x1e, 0x55, 0xd0, 0x6a, 0xdf,
    0xb1, 0x08, 0xfa, 0xf9
};
static const unsigned char gcm_ct_256[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};
static const unsigned char gcm_tag_256[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

static int chk_gcm_kernel_supp(void)
{
    struct sockaddr_alg sa;
    int sock;
    int r;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *) sa.salg_type, "aead", sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *) sa.salg_name, "gcm(aes)", sizeof(sa.salg_name));
    sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1)
        return 0;
    r = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0)
        return 0;
    close(sock);

    return 1;
}

static int do_encrypt(const EVP_CIPHER *cipher, unsigned char *ct, int *ct_len,
                      unsigned char *tag, int *tag_len)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen;
    unsigned char outbuf[64];

    *tag_len = 16;
    ret = TEST_ptr(ctx = EVP_CIPHER_CTX_new())
          && TEST_true(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL,
                                          NULL) > 0)
          && TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key,
                                          gcm_iv) > 0)
          && TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad,
                                         sizeof(gcm_aad)) > 0)
          && TEST_true(EVP_EncryptUpdate(ctx, ct, ct_len, gcm_pt,
                                         sizeof(gcm_pt)) > 0)
          && TEST_true(EVP_EncryptFinal_ex(ctx, outbuf, &outlen) > 0)
          && TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                           tag) > 0);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int do_decrypt(const EVP_CIPHER *cipher, const unsigned char *ct,
                      int ct_len, const unsigned char *tag, int tag_len)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int outlen, ptlen;
    unsigned char pt[32];
    unsigned char outbuf[32];

    ret = TEST_ptr(ctx = EVP_CIPHER_CTX_new())
              && TEST_true(EVP_DecryptInit_ex(ctx, cipher, NULL,
                                              NULL, NULL) > 0)
              && TEST_true(EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key,
                                              gcm_iv) > 0)
              && TEST_true(EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad,
                                             sizeof(gcm_aad)) > 0)
              && TEST_true(EVP_DecryptUpdate(ctx, pt, &ptlen, ct,
                                             ct_len) > 0)
              && TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                               tag_len, (void *)tag) > 0)
              && TEST_true(EVP_DecryptFinal_ex(ctx, outbuf, &outlen) > 0)
              && TEST_mem_eq(gcm_pt, sizeof(gcm_pt), pt, ptlen);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int test_afalg_aes_gcm(int keysize_idx)
{
    int ctlen = 0, taglen = 0, ret = 0, encl = 0, tagl = 0;
    unsigned const char *enc_result = NULL;
    unsigned const char *tag_result = NULL;
    const EVP_CIPHER *cipher;
    unsigned char tag[32];
    unsigned char ct[32];

    switch (keysize_idx) {
        case 0:
            cipher = EVP_aes_128_gcm();
            enc_result = &gcm_ct_128[0];
            tag_result = &gcm_tag_128[0];
            encl = sizeof(gcm_ct_128);
            tagl = sizeof(gcm_tag_128);
            break;
        case 1:
            cipher = EVP_aes_192_gcm();
            enc_result = &gcm_ct_192[0];
            tag_result = &gcm_tag_192[0];
            encl = sizeof(gcm_ct_192);
            tagl = sizeof(gcm_tag_192);
            break;
        case 2:
            cipher = EVP_aes_256_gcm();
            enc_result = &gcm_ct_256[0];
            tag_result = &gcm_tag_256[0];
            encl = sizeof(gcm_ct_256);
            tagl = sizeof(gcm_tag_256);
            break;
        default:
            cipher = NULL;
    }

    ret = do_encrypt(cipher, ct, &ctlen, tag, &taglen)
          && TEST_mem_eq(enc_result, encl, ct, ctlen)
          && TEST_mem_eq(tag_result, tagl, tag, taglen)
          && do_decrypt(cipher, ct, ctlen, tag, taglen);

    return ret;

}
static int test_afalg_aes_cbc(int keysize_idx)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char key[] = "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
                          "\x51\x2e\x03\xd5\x34\x12\x00\x06"
                          "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
                          "\x51\x2e\x03\xd5\x34\x12\x00\x06";
    unsigned char iv[] = "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30"
                         "\xb4\x22\xda\x80\x2c\x9f\xac\x41";
    /* input = "Single block msg\n"  17Bytes*/
    unsigned char in[BUFFER_SIZE] = "\x53\x69\x6e\x67\x6c\x65\x20\x62"
                                    "\x6c\x6f\x63\x6b\x20\x6d\x73\x67\x0a";
    unsigned char ebuf[BUFFER_SIZE + 32];
    unsigned char dbuf[BUFFER_SIZE + 32];
    unsigned char encresult_128[] = "\xe3\x53\x77\x9c\x10\x79\xae\xb8"
                                    "\x27\x08\x94\x2d\xbe\x77\x18\x1a\x2d";
    unsigned char encresult_192[] = "\xf7\xe4\x26\xd1\xd5\x4f\x8f\x39"
                                    "\xb1\x9e\xe0\xdf\x61\xb9\xc2\x55\xeb";
    unsigned char encresult_256[] = "\xa0\x76\x85\xfd\xc1\x65\x71\x9d"
                                    "\xc7\xe9\x13\x6e\xae\x55\x49\xb4\x13";
    unsigned char *enc_result = NULL;

    int encl, encf, decl, decf;
    int ret = 0;

    switch (keysize_idx) {
        case 0:
            cipher = EVP_aes_128_cbc();
            enc_result = &encresult_128[0];
            break;
        case 1:
            cipher = EVP_aes_192_cbc();
            enc_result = &encresult_192[0];
            break;
        case 2:
            cipher = EVP_aes_256_cbc();
            enc_result = &encresult_256[0];
            break;
        default:
            cipher = NULL;
    }
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
            return 0;

    if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, e, key, iv, 1))
            || !TEST_true(EVP_CipherUpdate(ctx, ebuf, &encl, in, BUFFER_SIZE))
            || !TEST_true(EVP_CipherFinal_ex(ctx, ebuf+encl, &encf)))
        goto end;
    encl += encf;

    if (!TEST_mem_eq(enc_result, BUFFER_SIZE, ebuf, BUFFER_SIZE))
        goto end;

    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
            || !TEST_true(EVP_CipherInit_ex(ctx, cipher, e, key, iv, 0))
            || !TEST_true(EVP_CipherUpdate(ctx, dbuf, &decl, ebuf, encl))
            || !TEST_true(EVP_CipherFinal_ex(ctx, dbuf+decl, &decf)))
        goto end;
    decl += decf;

    if (!TEST_int_eq(decl, BUFFER_SIZE)
            || !TEST_mem_eq(dbuf, BUFFER_SIZE, in, BUFFER_SIZE))
        goto end;

    ret = 1;

 end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
#endif

#ifndef OPENSSL_NO_ENGINE
int global_init(void)
{
    ENGINE_load_builtin_engines();
# ifndef OPENSSL_NO_STATIC_ENGINE
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL);
# endif
    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ENGINE
    if ((e = ENGINE_by_id("afalg")) == NULL) {
        /* Probably a platform env issue, not a test failure. */
        TEST_info("Can't load AFALG engine");
    } else {
# ifndef OPENSSL_NO_AFALGENG
        ADD_ALL_TESTS(test_afalg_aes_cbc, 3);
        if (chk_gcm_kernel_supp())
            ADD_ALL_TESTS(test_afalg_aes_gcm, 3);
# endif
    }
#endif

    return 1;
}

#ifndef OPENSSL_NO_ENGINE
void cleanup_tests(void)
{
    ENGINE_free(e);
}
#endif
