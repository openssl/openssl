/* crypto/engine/eng_openssl.c */
/*
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/engine.h>
#include <openssl/dso.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif

#include <openssl/hmac.h>
#include <openssl/x509v3.h>

/*
 * This testing gunk is implemented (and explained) lower down. It also
 * assumes the application explicitly calls "ENGINE_load_openssl()" because
 * this is no longer automatic in ENGINE_load_builtin_engines().
 */
#define TEST_ENG_OPENSSL_RC4
#ifndef OPENSSL_NO_STDIO
#define TEST_ENG_OPENSSL_PKEY
#endif
/* #define TEST_ENG_OPENSSL_HMAC */
/* #define TEST_ENG_OPENSSL_HMAC_INIT */
/* #define TEST_ENG_OPENSSL_RC4_OTHERS */
#define TEST_ENG_OPENSSL_RC4_P_INIT
/* #define TEST_ENG_OPENSSL_RC4_P_CIPHER */
#define TEST_ENG_OPENSSL_SHA
/* #define TEST_ENG_OPENSSL_SHA_OTHERS */
/* #define TEST_ENG_OPENSSL_SHA_P_INIT */
/* #define TEST_ENG_OPENSSL_SHA_P_UPDATE */
/* #define TEST_ENG_OPENSSL_SHA_P_FINAL */

/* Now check what of those algorithms are actually enabled */
#ifdef OPENSSL_NO_RC4
# undef TEST_ENG_OPENSSL_RC4
# undef TEST_ENG_OPENSSL_RC4_OTHERS
# undef TEST_ENG_OPENSSL_RC4_P_INIT
# undef TEST_ENG_OPENSSL_RC4_P_CIPHER
#endif

#ifdef TEST_ENG_OPENSSL_RC4
static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid);
#endif
#ifdef TEST_ENG_OPENSSL_SHA
static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid);
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data);
#endif

#ifdef TEST_ENG_OPENSSL_HMAC
static int ossl_register_hmac_meth(void);
static int ossl_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid);
#endif

/* The constants used when creating the ENGINE */
static const char *engine_openssl_id = "openssl";
static const char *engine_openssl_name = "Software engine support";

/*
 * This internal function is used by ENGINE_openssl() and possibly by the
 * "dynamic" ENGINE support too
 */
static int bind_helper(ENGINE *e)
{
    if (!ENGINE_set_id(e, engine_openssl_id)
        || !ENGINE_set_name(e, engine_openssl_name)
#ifndef TEST_ENG_OPENSSL_NO_ALGORITHMS
# ifndef OPENSSL_NO_RSA
        || !ENGINE_set_RSA(e, RSA_get_default_method())
# endif
# ifndef OPENSSL_NO_DSA
        || !ENGINE_set_DSA(e, DSA_get_default_method())
# endif
# ifndef OPENSSL_NO_EC
        || !ENGINE_set_ECDH(e, ECDH_OpenSSL())
        || !ENGINE_set_ECDSA(e, ECDSA_OpenSSL())
# endif
# ifndef OPENSSL_NO_DH
        || !ENGINE_set_DH(e, DH_get_default_method())
# endif
        || !ENGINE_set_RAND(e, RAND_OpenSSL())
# ifdef TEST_ENG_OPENSSL_RC4
        || !ENGINE_set_ciphers(e, openssl_ciphers)
# endif
# ifdef TEST_ENG_OPENSSL_SHA
        || !ENGINE_set_digests(e, openssl_digests)
# endif
#endif
#ifdef TEST_ENG_OPENSSL_PKEY
        || !ENGINE_set_load_privkey_function(e, openssl_load_privkey)
#endif
#ifdef TEST_ENG_OPENSSL_HMAC
        || !ossl_register_hmac_meth()
        || !ENGINE_set_pkey_meths(e, ossl_pkey_meths)
#endif
        )
        return 0;
    /*
     * If we add errors to this ENGINE, ensure the error handling is setup
     * here
     */
    /* openssl_load_error_strings(); */
    return 1;
}

static ENGINE *engine_openssl(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_openssl(void)
{
    ENGINE *toadd = engine_openssl();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    /*
     * If the "add" worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     */
    ENGINE_free(toadd);
    ERR_clear_error();
}

/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */
#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_openssl_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif                          /* ENGINE_DYNAMIC_SUPPORT */
#ifdef TEST_ENG_OPENSSL_RC4
/*-
 * This section of code compiles an "alternative implementation" of two modes of
 * RC4 into this ENGINE. The result is that EVP_CIPHER operation for "rc4"
 * should under normal circumstances go via this support rather than the default
 * EVP support. There are other symbols to tweak the testing;
 *    TEST_ENC_OPENSSL_RC4_OTHERS - print a one line message to stderr each time
 *        we're asked for a cipher we don't support (should not happen).
 *    TEST_ENG_OPENSSL_RC4_P_INIT - print a one line message to stderr each time
 *        the "init_key" handler is called.
 *    TEST_ENG_OPENSSL_RC4_P_CIPHER - ditto for the "cipher" handler.
 */
# include <openssl/rc4.h>
# define TEST_RC4_KEY_SIZE               16
static const int test_cipher_nids[] = { NID_rc4, NID_rc4_40 };

static const int test_cipher_nids_number = 2;
typedef struct {
    unsigned char key[TEST_RC4_KEY_SIZE];
    RC4_KEY ks;
} TEST_RC4_KEY;
# define test(ctx) ((TEST_RC4_KEY *)(ctx)->cipher_data)
static int test_rc4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
# ifdef TEST_ENG_OPENSSL_RC4_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_init_key() called\n");
# endif
    memcpy(&test(ctx)->key[0], key, EVP_CIPHER_CTX_key_length(ctx));
    RC4_set_key(&test(ctx)->ks, EVP_CIPHER_CTX_key_length(ctx),
                test(ctx)->key);
    return 1;
}

static int test_rc4_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
# ifdef TEST_ENG_OPENSSL_RC4_P_CIPHER
    fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) test_cipher() called\n");
# endif
    RC4(&test(ctx)->ks, inl, in, out);
    return 1;
}

static const EVP_CIPHER test_r4_cipher = {
    NID_rc4,
    1, TEST_RC4_KEY_SIZE, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    test_rc4_init_key,
    test_rc4_cipher,
    NULL,
    sizeof(TEST_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

static const EVP_CIPHER test_r4_40_cipher = {
    NID_rc4_40,
    1, 5 /* 40 bit */ , 0,
    EVP_CIPH_VARIABLE_LENGTH,
    test_rc4_init_key,
    test_rc4_cipher,
    NULL,
    sizeof(TEST_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid)
{
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = test_cipher_nids;
        return test_cipher_nids_number;
    }
    /* We are being asked for a specific cipher */
    if (nid == NID_rc4)
        *cipher = &test_r4_cipher;
    else if (nid == NID_rc4_40)
        *cipher = &test_r4_40_cipher;
    else {
# ifdef TEST_ENG_OPENSSL_RC4_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_RC4) returning NULL for "
                "nid %d\n", nid);
# endif
        *cipher = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_SHA
/* Much the same sort of comment as for TEST_ENG_OPENSSL_RC4 */
# include <openssl/sha.h>
static const int test_digest_nids[] = { NID_sha1 };

static const int test_digest_nids_number = 1;
static int test_sha1_init(EVP_MD_CTX *ctx)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_init() called\n");
# endif
    return SHA1_Init(ctx->md_data);
}

static int test_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_UPDATE
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_update() called\n");
# endif
    return SHA1_Update(ctx->md_data, data, count);
}

static int test_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_FINAL
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_final() called\n");
# endif
    return SHA1_Final(md, ctx->md_data);
}

static const EVP_MD test_sha_md = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    0,
    test_sha1_init,
    test_sha1_update,
    test_sha1_final,
    NULL,
    NULL,
    EVP_PKEY_RSA_method,
    SHA_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid)
{
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = test_digest_nids;
        return test_digest_nids_number;
    }
    /* We are being asked for a specific digest */
    if (nid == NID_sha1)
        *digest = &test_sha_md;
    else {
# ifdef TEST_ENG_OPENSSL_SHA_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) returning NULL for "
                "nid %d\n", nid);
# endif
        *digest = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data)
{
    BIO *in;
    EVP_PKEY *key;
    fprintf(stderr, "(TEST_ENG_OPENSSL_PKEY)Loading Private key %s\n",
            key_id);
    in = BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    BIO_free(in);
    return key;
}
#endif

#ifdef TEST_ENG_OPENSSL_HMAC

/*
 * Experimental HMAC redirection implementation: mainly copied from
 * hm_pmeth.c
 */

/* HMAC pkey context structure */

typedef struct {
    const EVP_MD *md;           /* MD for HMAC use */
    ASN1_OCTET_STRING ktmp;     /* Temp storage for key */
    HMAC_CTX ctx;
} OSSL_HMAC_PKEY_CTX;

static int ossl_hmac_init(EVP_PKEY_CTX *ctx)
{
    OSSL_HMAC_PKEY_CTX *hctx;

    hctx = OPENSSL_zalloc(sizeof(*hctx));
    if (hctx == NULL)
        return 0;
    hctx->ktmp.type = V_ASN1_OCTET_STRING;
    HMAC_CTX_init(&hctx->ctx);
    EVP_PKEY_CTX_set_data(ctx, hctx);
    EVP_PKEY_CTX_set0_keygen_info(ctx, NULL, 0);
# ifdef TEST_ENG_OPENSSL_HMAC_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_HMAC) ossl_hmac_init() called\n");
# endif
    return 1;
}

static int ossl_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    OSSL_HMAC_PKEY_CTX *sctx, *dctx;
    if (!ossl_hmac_init(dst))
        return 0;
    sctx = EVP_PKEY_CTX_get_data(src);
    dctx = EVP_PKEY_CTX_get_data(dst);
    dctx->md = sctx->md;
    HMAC_CTX_init(&dctx->ctx);
    if (!HMAC_CTX_copy(&dctx->ctx, &sctx->ctx))
        return 0;
    if (sctx->ktmp.data) {
        if (!ASN1_OCTET_STRING_set(&dctx->ktmp,
                                   sctx->ktmp.data, sctx->ktmp.length))
            return 0;
    }
    return 1;
}

static void ossl_hmac_cleanup(EVP_PKEY_CTX *ctx)
{
    OSSL_HMAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    HMAC_CTX_cleanup(&hctx->ctx);
    OPENSSL_clear_free(hctx->ktmp.data, hctx->ktmp.length);
    OPENSSL_free(hctx);
}

static int ossl_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *hkey = NULL;
    OSSL_HMAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);
    if (!hctx->ktmp.data)
        return 0;
    hkey = ASN1_OCTET_STRING_dup(&hctx->ktmp);
    if (!hkey)
        return 0;
    EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, hkey);

    return 1;
}

static int ossl_int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    OSSL_HMAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx->pctx);
    if (!HMAC_Update(&hctx->ctx, data, count))
        return 0;
    return 1;
}

static int ossl_hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    mctx->update = ossl_int_update;
    return 1;
}

static int ossl_hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                             size_t *siglen, EVP_MD_CTX *mctx)
{
    unsigned int hlen;
    OSSL_HMAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);
    int l = EVP_MD_CTX_size(mctx);

    if (l < 0)
        return 0;
    *siglen = l;
    if (!sig)
        return 1;

    if (!HMAC_Final(&hctx->ctx, sig, &hlen))
        return 0;
    *siglen = (size_t)hlen;
    return 1;
}

static int ossl_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    OSSL_HMAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pk;
    ASN1_OCTET_STRING *key;
    switch (type) {

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if ((!p2 && p1 > 0) || (p1 < -1))
            return 0;
        if (!ASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1))
            return 0;
        break;

    case EVP_PKEY_CTRL_MD:
        hctx->md = p2;
        break;

    case EVP_PKEY_CTRL_DIGESTINIT:
        pk = EVP_PKEY_CTX_get0_pkey(ctx);
        key = EVP_PKEY_get0(pk);
        if (!HMAC_Init_ex(&hctx->ctx, key->data, key->length, hctx->md, NULL))
            return 0;
        break;

    default:
        return -2;

    }
    return 1;
}

static int ossl_hmac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    if (!value) {
        return 0;
    }
    if (strcmp(type, "key") == 0) {
        void *p = (void *)value;
        return ossl_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, -1, p);
    }
    if (strcmp(type, "hexkey") == 0) {
        unsigned char *key;
        int r;
        long keylen;
        key = string_to_hex(value, &keylen);
        if (!key)
            return 0;
        r = ossl_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key);
        OPENSSL_free(key);
        return r;
    }
    return -2;
}

static EVP_PKEY_METHOD *ossl_hmac_meth;

static int ossl_register_hmac_meth(void)
{
    EVP_PKEY_METHOD *meth;
    meth = EVP_PKEY_meth_new(EVP_PKEY_HMAC, 0);
    if (meth == NULL)
        return 0;
    EVP_PKEY_meth_set_init(meth, ossl_hmac_init);
    EVP_PKEY_meth_set_copy(meth, ossl_hmac_copy);
    EVP_PKEY_meth_set_cleanup(meth, ossl_hmac_cleanup);

    EVP_PKEY_meth_set_keygen(meth, 0, ossl_hmac_keygen);

    EVP_PKEY_meth_set_signctx(meth, ossl_hmac_signctx_init,
                              ossl_hmac_signctx);

    EVP_PKEY_meth_set_ctrl(meth, ossl_hmac_ctrl, ossl_hmac_ctrl_str);
    ossl_hmac_meth = meth;
    return 1;
}

static int ossl_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    static int ossl_pkey_nids[] = {
        EVP_PKEY_HMAC,
        0
    };
    if (!pmeth) {
        *nids = ossl_pkey_nids;
        return 1;
    }

    if (nid == EVP_PKEY_HMAC) {
        *pmeth = ossl_hmac_meth;
        return 1;
    }

    *pmeth = NULL;
    return 0;
}

#endif
