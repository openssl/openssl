/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/* Shamelessly copied from BoringSSL and converted to C. */

/* Test ECH split mode */

#include <time.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include "fuzzer.h"
#if !defined(OPENSSL_NO_ECH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX)
# include <internal/ech_helpers.h>
#endif

/* unused, to avoid warning. */
static int idx;

#define FUZZTIME 1485898104

#define TIME_IMPL(t) { if (t != NULL) *t = FUZZTIME; return FUZZTIME; }

/*
 * This might not work in all cases (and definitely not on Windows
 * because of the way linkers are) and callees can still get the
 * current time instead of the fixed time. This will just result
 * in things not being fully reproducible and have a slightly
 * different coverage.
 */
#if !defined(_WIN32)
time_t time(time_t *t) TIME_IMPL(t)
#endif

#if !defined(OPENSSL_NO_ECH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX)
static unsigned char s_echconfig[400];
static size_t s_echconfiglen = sizeof(s_echconfig);
static unsigned char config_id = 0;
static unsigned char priv[200];
static size_t privlen = sizeof(priv);
static uint16_t ech_version = OSSL_ECH_RFCXXXX_VERSION;
static uint16_t max_name_length = 0;
static char *public_name = "example.com";
static OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
static unsigned char *extvals = NULL;
static size_t extlen = 0;
static char echkeybuf[1000];
static size_t echkeybuflen = sizeof(echkeybuf);
static unsigned char *hpke_info = NULL;
static size_t hpke_infolen = 0;
#endif

#if !defined(OPENSSL_NO_ECH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX)
/*
 * We'll use the input buffer as the outer CH, then also HPKE
 * encrypt that and add it to the outer CH as an ECH extension.
 * For now, there's no attempt to ensure any other formatting
 * is correct, we'll see how the fuzzer gets on with finding
 * those itself first.
 */
static int make_ch_with_ech(unsigned char **out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    int res = 0;
    OSSL_HPKE_CTX *hctx = NULL;
    unsigned char *mypub = NULL;
    static size_t mypublen = 0;
    unsigned char *theirpub = NULL;
    size_t theirpublen = 0;
    unsigned char *ct = NULL;
    size_t ctlen = 0;
    unsigned char *aad = NULL;
    size_t aadlen = 0;
    unsigned char *chout = NULL;
    size_t choutlen = 0;
    size_t echlen = 0;
    unsigned char *cp = NULL;
    const unsigned char *pt = in;

    hctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, hpke_suite,
                             OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    if (hctx == NULL)
        goto err;
    mypublen = OSSL_HPKE_get_public_encap_size(hpke_suite);
    mypub = OPENSSL_malloc(mypublen);
    if (mypub == NULL)
        goto err;
    theirpub = s_echconfig + 11;
    theirpublen = 32;
    if (OSSL_HPKE_encap(hctx, mypub, &mypublen,
                        theirpub, theirpublen,
                        hpke_info, hpke_infolen) != 1)
        goto err;
    /* form up aad which is entire outer CH: zero's instead of ECH ciphertext */
    ctlen = OSSL_HPKE_get_ciphertext_size(hpke_suite, inlen);
    echlen = 14 + mypublen + ctlen;
    choutlen = inlen + echlen;
    chout = OPENSSL_malloc(choutlen);
    if (chout == NULL)
        goto err;
    cp = chout;
    /* outer CH from fuzzer */
    memcpy(cp, in, inlen);
    cp += inlen;
    *cp++ = 0xfe;
    *cp++ = 0x0d;
    *cp++ = (echlen >> 8) & 0xff;
    *cp++ = echlen & 0xff;
    *cp++ = 0x00;
    *cp++ = 0x00;
    *cp++ = 0x01;
    *cp++ = 0x00;
    *cp++ = 0x01;
    *cp++ = config_id;
    *cp++ = (mypublen >> 8) & 0xff;
    *cp++ = mypublen & 0xff;
    memcpy(cp, mypub, mypublen);
    cp += mypublen;
    *cp++ = (ctlen >> 8) & 0xff;
    *cp++ = ctlen & 0xff;
    memset(cp, 0, ctlen);
    ct = cp;
    cp += ctlen;
    choutlen = (cp - chout);
    /* skip the record layer header */
    aad = chout + SSL3_RT_HEADER_LENGTH + SSL3_HM_HEADER_LENGTH;
    aadlen = choutlen - (SSL3_RT_HEADER_LENGTH + SSL3_HM_HEADER_LENGTH);
    if (OSSL_HPKE_seal(hctx, ct, &ctlen, aad, aadlen, pt, inlen) != 1)
        goto err;
    *out = chout;
    *outlen = choutlen;
    res = 1;
err:
    if (res != 1) 
        OPENSSL_free(chout);
    OPENSSL_free(mypub);
    OSSL_HPKE_CTX_free(hctx);
    return res;
}
#endif

int FuzzerInitialize(int *argc, char ***argv)
{
    STACK_OF(SSL_COMP) *comp_methods;
#if !defined(OPENSSL_NO_ECH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX)
    static unsigned char *bin_echconfig;
    static size_t bin_echconfiglen = 0;
#endif

    FuzzerSetRand();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ASYNC, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    comp_methods = SSL_COMP_get_compression_methods();
    if (comp_methods != NULL)
        sk_SSL_COMP_sort(comp_methods);

#if !defined(OPENSSL_NO_ECH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX)
    if (OSSL_ech_make_echconfig(s_echconfig, &s_echconfiglen,
                                priv, &privlen,
                                ech_version, max_name_length,
                                public_name, hpke_suite,
                                extvals, extlen) != 1)
        return 0;
    snprintf(echkeybuf, echkeybuflen,
             "%s-----BEGIN ECHCONFIG-----\n%s\n-----END ECHCONFIG-----\n",
             priv, (char *)s_echconfig);
    echkeybuflen = strlen(echkeybuf);

    hpke_infolen = s_echconfiglen + 200;
    hpke_info = OPENSSL_malloc(hpke_infolen);
    if (hpke_info == NULL)
        return 0;
    /* +/- 2 is to drop the ECHConfigList length at the start */
    bin_echconfiglen = ech_helper_base64_decode((char *)s_echconfig,
                                                s_echconfiglen,
                                                &bin_echconfig);
    /* echconfig id */
    config_id = bin_echconfig[6];
    hpke_infolen = bin_echconfiglen + 200;
    if (ech_helper_make_enc_info((unsigned char *)bin_echconfig + 2,
                                 bin_echconfiglen - 2,
                                 hpke_info, &hpke_infolen) != 1) {
        OPENSSL_free(bin_echconfig);
        return 0;
    }
    OPENSSL_free(bin_echconfig);
#endif

    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    SSL_CTX *ctx;
    int ret;
#if !defined(OPENSSL_NO_ECH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX)
    unsigned char *inner = NULL;
    size_t innerlen = 0;
    char *inner_sni = NULL, *outer_sni = NULL;
    int dec_ok = 0;
    unsigned char *msgout = NULL;
    size_t msgoutlen = 0;
#endif

    if (len < 2)
        return 0;

    /* This only fuzzes the initial flow from the client so far. */
    ctx = SSL_CTX_new(SSLv23_method());

    ret = SSL_CTX_set_min_proto_version(ctx, 0);
    OPENSSL_assert(ret == 1);
    ret = SSL_CTX_set_cipher_list(ctx, "ALL:eNULL:@SECLEVEL=0");
    OPENSSL_assert(ret == 1);

#if !defined(OPENSSL_NO_ECH) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX)
    ret = SSL_CTX_ech_server_enable_buffer(ctx, (unsigned char *)echkeybuf,
                                           echkeybuflen, SSL_ECH_USE_FOR_RETRY);
    OPENSSL_assert(ret == 1);
    /* outer has to be longer than inner, so this is safe */
    ret = make_ch_with_ech(&msgout, &msgoutlen, buf, len);
    OPENSSL_assert(ret == 1);
    innerlen = msgoutlen;
    inner = OPENSSL_malloc(innerlen);
    OPENSSL_assert(inner != NULL);
    memset(inner, 0xAA, innerlen);
    /* so far, dec_ok will never happen, fix that in a bit */
    ret = SSL_CTX_ech_raw_decrypt(ctx, &dec_ok, &inner_sni, &outer_sni,
                                  (unsigned char *)msgout, msgoutlen,
                                  inner, &innerlen, NULL, NULL);
    /* ret can be zero with bad encodings */
    OPENSSL_free(msgout);
    OPENSSL_free(inner);
#endif

    ERR_clear_error();
    SSL_CTX_free(ctx);

    return 0;
}

void FuzzerCleanup(void)
{
    FuzzerClearRand();
}
