/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/rand.h>
#include <openssl/params.h>
/* For TLS1_3_VERSION */
#include <openssl/ssl.h>

int tls_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx);

#define XOR_KEY_SIZE 32

/*
 * Top secret. This algorithm only works if no one knows what this number is.
 * Please don't tell anyone what it is.
 * 
 * This algorithm is for testing only - don't really use it!
 */
static const unsigned char private_constant[XOR_KEY_SIZE] = {
    0xd3, 0x6b, 0x54, 0xec, 0x5b, 0xac, 0x89, 0x96, 0x8c, 0x2c, 0x66, 0xa5,
    0x67, 0x0d, 0xe3, 0xdd, 0x43, 0x69, 0xbc, 0x83, 0x3d, 0x60, 0xc7, 0xb8,
    0x2b, 0x1c, 0x5a, 0xfd, 0xb5, 0xcd, 0xd0, 0xf8
};

typedef struct xorkey_st {
    unsigned char privkey[XOR_KEY_SIZE];
    unsigned char pubkey[XOR_KEY_SIZE];
    int hasprivkey;
    int haspubkey;
} XORKEY;

/* We define a dummy TLS group called "xorgroup" for test purposes */

static unsigned int group_id = 0; /* IANA reserved for private use */
static unsigned int secbits = 128;
static unsigned int mintls = TLS1_3_VERSION;
static unsigned int maxtls = 0;
static unsigned int mindtls = -1;
static unsigned int maxdtls = -1;

#define GROUP_NAME "xorgroup"
#define GROUP_NAME_INTERNAL "xorgroup-int"
#define ALGORITHM "XOR"

static const OSSL_PARAM xor_group_params[] = {
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,
                           GROUP_NAME, sizeof(GROUP_NAME)),
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                           GROUP_NAME_INTERNAL, sizeof(GROUP_NAME_INTERNAL)),
    OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, ALGORITHM,
                           sizeof(ALGORITHM)),
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &group_id),
    OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, &secbits),
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &mintls),
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &maxtls),
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &mindtls),
    OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &maxdtls),
    OSSL_PARAM_END
};

static int tls_prov_get_capabilities(void *provctx, const char *capability,
                                     OSSL_CALLBACK *cb, void *arg)
{
    /* We're only adding one group so we only call the callback once */
    if (strcmp(capability, "TLS-GROUP") == 0)
        return cb(xor_group_params, arg);

    /* We don't support this capability */
    return 0;
}

/*
 * Dummy "XOR" Key Exchange algorithm. We just xor the private and public keys
 * together. Don't use this!
 */

static OSSL_FUNC_keyexch_newctx_fn xor_newctx;
static OSSL_FUNC_keyexch_init_fn xor_init;
static OSSL_FUNC_keyexch_set_peer_fn xor_set_peer;
static OSSL_FUNC_keyexch_derive_fn xor_derive;
static OSSL_FUNC_keyexch_freectx_fn xor_freectx;
static OSSL_FUNC_keyexch_dupctx_fn xor_dupctx;

typedef struct {
    XORKEY *key;
    XORKEY *peerkey;
} PROV_XOR_CTX;

static void *xor_newctx(void *provctx)
{
    PROV_XOR_CTX *pxorctx = OPENSSL_zalloc(sizeof(PROV_XOR_CTX));

    if (pxorctx == NULL)
        return NULL;

    return pxorctx;
}

static int xor_init(void *vpxorctx, void *vkey)
{
    PROV_XOR_CTX *pxorctx = (PROV_XOR_CTX *)vpxorctx;

    if (pxorctx == NULL || vkey == NULL)
        return 0;
    pxorctx->key = vkey;
    return 1;
}

static int xor_set_peer(void *vpxorctx, void *vpeerkey)
{
    PROV_XOR_CTX *pxorctx = (PROV_XOR_CTX *)vpxorctx;

    if (pxorctx == NULL || vpeerkey == NULL)
        return 0;
    pxorctx->peerkey = vpeerkey;
    return 1;
}

static int xor_derive(void *vpxorctx, unsigned char *secret, size_t *secretlen,
                      size_t outlen)
{
    PROV_XOR_CTX *pxorctx = (PROV_XOR_CTX *)vpxorctx;
    int i;

    if (pxorctx->key == NULL || pxorctx->peerkey == NULL)
        return 0;

    *secretlen = XOR_KEY_SIZE;
    if (secret == NULL)
        return 1;

    if (outlen < XOR_KEY_SIZE)
        return 0;

    for (i = 0; i < XOR_KEY_SIZE; i++)
        secret[i] = pxorctx->key->privkey[i] ^ pxorctx->peerkey->pubkey[i];

    return 1;
}

static void xor_freectx(void *pxorctx)
{
    OPENSSL_free(pxorctx);
}

static void *xor_dupctx(void *vpxorctx)
{
    PROV_XOR_CTX *srcctx = (PROV_XOR_CTX *)vpxorctx;
    PROV_XOR_CTX *dstctx;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;

    return dstctx;
}

static const OSSL_DISPATCH xor_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))xor_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))xor_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))xor_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))xor_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))xor_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))xor_dupctx },
    { 0, NULL }
};

static const OSSL_ALGORITHM tls_prov_keyexch[] = {
    /*
     * Obviously this is not FIPS approved, but in order to test in conjuction
     * with the FIPS provider we pretend that it is.
     */
    { "XOR", "provider=tls-provider,fips=yes", xor_keyexch_functions },
    { NULL, NULL, NULL }
};

/* Key Management for the dummy XOR key exchange algorithm */

static OSSL_FUNC_keymgmt_new_fn xor_newdata;
static OSSL_FUNC_keymgmt_free_fn xor_freedata;
static OSSL_FUNC_keymgmt_has_fn xor_has;
static OSSL_FUNC_keymgmt_copy_fn xor_copy;
static OSSL_FUNC_keymgmt_gen_init_fn xor_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn xor_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn xor_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn xor_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn xor_gen_cleanup;
static OSSL_FUNC_keymgmt_get_params_fn xor_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn xor_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn xor_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn xor_settable_params;

static void *xor_newdata(void *provctx)
{
    return OPENSSL_zalloc(sizeof(XORKEY));
}

static void xor_freedata(void *keydata)
{
    OPENSSL_free(keydata);
}

static int xor_has(void *vkey, int selection)
{
    XORKEY *key = vkey;
    int ok = 0;

    if (key != NULL) {
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->haspubkey;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->hasprivkey;
    }
    return ok;
}

static int xor_copy(void *vtokey, const void *vfromkey, int selection)
{
    XORKEY *tokey = vtokey;
    const XORKEY *fromkey = vfromkey;
    int ok = 0;

    if (tokey != NULL && fromkey != NULL) {
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            if (fromkey->haspubkey) {
                memcpy(tokey->pubkey, fromkey->pubkey, XOR_KEY_SIZE);
                tokey->haspubkey = 1;
            } else {
                tokey->haspubkey = 0;
            }
        }
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (fromkey->hasprivkey) {
                memcpy(tokey->privkey, fromkey->privkey, XOR_KEY_SIZE);
                tokey->hasprivkey = 1;
            } else {
                tokey->hasprivkey = 0;
            }
        }
    }
    return ok;
}

static ossl_inline int xor_get_params(void *vkey, OSSL_PARAM params[])
{
    XORKEY *key = vkey;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, XOR_KEY_SIZE))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, secbits))
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_TLS_ENCODED_PT)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        p->return_size = XOR_KEY_SIZE;
        if (p->data != NULL && p->data_size >= XOR_KEY_SIZE)
            memcpy(p->data, key->pubkey, XOR_KEY_SIZE);
    }

    return 1;
}

static const OSSL_PARAM xor_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_TLS_ENCODED_PT, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *xor_gettable_params(void *provctx)
{
    return xor_params;
}

static int xor_set_params(void *vkey, const OSSL_PARAM params[])
{
    XORKEY *key = vkey;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TLS_ENCODED_PT);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING
                || p->data_size != XOR_KEY_SIZE)
            return 0;
        memcpy(key->pubkey, p->data, XOR_KEY_SIZE);
        key->haspubkey = 1;
    }

    return 1;
}

static const OSSL_PARAM xor_known_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_TLS_ENCODED_PT, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *xor_settable_params(void *provctx)
{
    return xor_known_settable_params;
}

struct xor_gen_ctx {
    int selection;
    OPENSSL_CTX *libctx;
};

static void *xor_gen_init(void *provctx, int selection)
{
    struct xor_gen_ctx *gctx = NULL;

    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR
                      | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) == 0)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL)
        gctx->selection = selection;

    /* Our provctx is really just an OPENSSL_CTX */
    gctx->libctx = (OPENSSL_CTX *)provctx;

    return gctx;
}

static int xor_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct xor_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
                || strcmp(p->data, GROUP_NAME_INTERNAL) != 0)
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *xor_gen_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void *xor_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct xor_gen_ctx *gctx = genctx;
    XORKEY *key = OPENSSL_zalloc(sizeof(*key));
    size_t i;

    if (key == NULL)
        return NULL;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (RAND_bytes_ex(gctx->libctx, key->privkey, XOR_KEY_SIZE) <= 0) {
            OPENSSL_free(key);
            return NULL;
        }
        for (i = 0; i < XOR_KEY_SIZE; i++)
            key->pubkey[i] = key->privkey[i] ^ private_constant[i];
        key->hasprivkey = 1;
        key->haspubkey = 1;
    }

    return key;
}

static void xor_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static const OSSL_DISPATCH xor_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))xor_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))xor_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))xor_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))xor_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))xor_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))xor_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))xor_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))xor_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))xor_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))xor_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))xor_has },
    { OSSL_FUNC_KEYMGMT_COPY, (void (*)(void))xor_copy },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))xor_freedata },
    { 0, NULL }
};

static const OSSL_ALGORITHM tls_prov_keymgmt[] = {
    /*
     * Obviously this is not FIPS approved, but in order to test in conjuction
     * with the FIPS provider we pretend that it is.
     */
    { "XOR", "provider=tls-provider,fips=yes", xor_keymgmt_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *tls_prov_query(void *provctx, int operation_id,
                                            int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return tls_prov_keymgmt;
    case OSSL_OP_KEYEXCH:
        return tls_prov_keyexch;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH tls_prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OPENSSL_CTX_free },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tls_prov_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))tls_prov_get_capabilities },
    { 0, NULL }
};

int tls_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{
    OPENSSL_CTX *libctx = OPENSSL_CTX_new();

    *provctx = libctx;

    /*
     * Randomise the group_id we're going to use to ensure we don't interoperate
     * with anything but ourselves.
     */
    if (!RAND_bytes_ex(libctx, (unsigned char *)&group_id, sizeof(group_id)))
        return 0;
    /*
     * Ensure group_id is within the IANA Reserved for private use range
     * (65024-65279)
     */
    group_id %= 65279 - 65024;
    group_id += 65024;

    *out = tls_prov_dispatch_table;
    return 1;
}
