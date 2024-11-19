/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/self_test.h>
#include "internal/param_build_set.h"
#include <openssl/param_build.h>
#include "prov/mlkem.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"
#include <assert.h>

#define BUFSIZE 1000
#if defined(NDEBUG) || defined(OPENSSL_NO_STDIO)
/* TODO(ML-KEM) to remove or replace with TRACE */
static void debug_print(char *fmt, ...)
{
}
#else
static void debug_print(char *fmt, ...)
{
    char out[BUFSIZE];
    va_list argptr;

    va_start(argptr, fmt);
    vsnprintf(out, BUFSIZE, fmt, argptr);
    va_end(argptr);
    if (getenv("TEMPLATEKM"))
        fprintf(stderr, "TEMPLATE_KM: %s", out);
}
#endif

static void print_hex(const uint8_t *data, int len, const char *msg)
{
#ifndef NDEBUG
    if (msg)
        printf("%s: \n", msg);
    BIO_dump_fp(stdout, data, len);
    printf("\n\n");
#endif
}

static OSSL_FUNC_keymgmt_new_fn mlkem_new;
static OSSL_FUNC_keymgmt_free_fn mlkem_free;
static OSSL_FUNC_keymgmt_gen_init_fn mlkem_gen_init;
static OSSL_FUNC_keymgmt_gen_fn mlkem_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn mlkem_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn mlkem_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn mlkem_gen_settable_params;
static OSSL_FUNC_keymgmt_get_params_fn mlkem_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn mlkem_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn mlkem_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn mlkem_settable_params;
static OSSL_FUNC_keymgmt_has_fn mlkem_has;
static OSSL_FUNC_keymgmt_match_fn mlkem_match;
static OSSL_FUNC_keymgmt_import_fn mlkem_import;
static OSSL_FUNC_keymgmt_export_fn mlkem_export;
static OSSL_FUNC_keymgmt_import_types_fn mlkem_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn mlkem_imexport_types;
static OSSL_FUNC_keymgmt_dup_fn mlkem_dup;

struct mlkem_gen_ctx {
    void *provctx;
    int selection;
    uint8_t *seed;
};

static void *mlkem_new(void *provctx)
{
    MLKEM768_KEY *key = NULL;

    debug_print("MLKEMKM new key req\n");
    if (!ossl_prov_is_running())
        return 0;

    key = OPENSSL_zalloc(sizeof(MLKEM768_KEY));
    if (key != NULL) {
        key->keytype = MLKEM_KEY_TYPE_768; /* TODO(ML-KEM) any type */
        key->provctx = provctx;
        /*
         * ideally, this is a one-time allocation and ctx that should be within the
         * provider context: OK to move it there to improve performance?? It would be
         * the first algorithmspecific context stored: Feels weird (TODO(ML-KEM)).
         */
        key->mlkem_ctx = ossl_mlkem_newctx(provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx), NULL);
        if (key->mlkem_ctx == NULL) {
            OPENSSL_free(key);
            key = NULL;
        }
    }

    debug_print("MLKEMKM new key = %p\n", key);
    return key;
}

static void mlkem_free(void *vkey)
{
    MLKEM768_KEY *mkey = (MLKEM768_KEY *)vkey;

    debug_print("MLKEMKM free key %p\n", mkey);
    if (mkey == NULL)
        return;
    ossl_mlkem_ctx_free(mkey->mlkem_ctx);
    OPENSSL_free(mkey->encoded_pubkey);
    OPENSSL_free(mkey->encoded_privkey);
    OPENSSL_free(mkey);
}

static int mlkem_has(const void *keydata, int selection)
{
    const MLKEM768_KEY *key = keydata;
    int ok = 0;

    debug_print("MLKEMKM has %p\n", key);
    if (ossl_prov_is_running() && key != NULL) {
        /*
         * ML-KEM keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->encoded_pubkey != NULL;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->encoded_privkey != NULL;
    }
    debug_print("MLKEMKM has result %d\n", ok);
    return ok;
}

static int mlkem_match(const void *keydata1, const void *keydata2, int selection)
{
    const MLKEM768_KEY *key1 = keydata1;
    const MLKEM768_KEY *key2 = keydata2;
    int ok = 1;

    debug_print("MLKEMKM matching %p and %p\n", key1, key2);
    if (!ossl_prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && key1->keytype == key2->keytype;

    /* TODO(ML-KEM) */
    debug_print("MLKEMKM matching for now NOT YET IMPLEMENTED\n");

/* TODO(ML-KEM) template code to be completed as and when needed: */
#ifdef UNDEF
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            const uint8_t *pa = key1->pubkey;
            const uint8_t *pb = key2->pubkey;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->keytype == key2->keytype
                    && CRYPTO_memcmp(pa, pb, MLKEM768_PUBLICKEYBYTES) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            const uint8_t *pa = key1->privkey;
            const uint8_t *pb = key2->privkey;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->keytype == key2->keytype
                    && CRYPTO_memcmp(pa, pb, MLKEM768_SECRETKEYBYTES) == 0;
                key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
#endif /* UNDEF */
    debug_print("MLKEMKM match result %d\n", ok);
    return ok;
}

static int key_to_params(MLKEM768_KEY *key, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], int include_private)
{
    if (key == NULL)
        return 0;

    if (key->keytype != MLKEM_KEY_TYPE_768)
        return 0;

    if (key->encoded_pubkey != NULL
        && !ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PUB_KEY,
                                              key->encoded_pubkey,
                                              OSSL_MLKEM768_PUBLIC_KEY_BYTES))
        return 0;

    if (include_private
        && key->encoded_privkey != NULL
        && !ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key->encoded_privkey,
                                              OSSL_MLKEM768_PRIVATE_KEY_BYTES))
        return 0;

    return 1;
}

static int mlkem_export(void *key, int selection, OSSL_CALLBACK *param_cb,
                        void *cbarg)
{
    MLKEM768_KEY *mkey = key;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    debug_print("MLKEMKM export %p\n", key);
    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

        if (!key_to_params(mkey, tmpl, NULL, include_private))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    debug_print("MLKEMKM export result %d\n", ret);
    return ret;
}

#define MLKEM768_KEY_TYPES()                                            \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),          \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM mlkem_key_types[] = {
    MLKEM768_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_imexport_types(int selection)
{
    debug_print("MLKEMKM getting imexport types\n");
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return mlkem_key_types;
    return NULL;
}

static int ossl_mlkem_key_fromdata(MLKEM768_KEY *key,
                                   const OSSL_PARAM params[],
                                   int include_private)
{
    size_t privkeylen = 0, pubkeylen = 0;
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key;

    if (key == NULL)
        return 0;

    if (key->keytype != MLKEM_KEY_TYPE_768)
        return 0;

    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (include_private)
        param_priv_key = OSSL_PARAM_locate_const(params,
                                                 OSSL_PKEY_PARAM_PRIV_KEY);

    if (param_pub_key == NULL && param_priv_key == NULL)
        return 0;

    if (param_priv_key != NULL) {
        if (!OSSL_PARAM_get_octet_string(param_priv_key,
                                         (void **)&key->encoded_privkey,
                                         OSSL_MLKEM768_PRIVATE_KEY_BYTES,
                                         &privkeylen))
            return 0;
        if (privkeylen != OSSL_MLKEM768_PRIVATE_KEY_BYTES) {
            debug_print("sec key len mismatch in import: %ld vs %d\n",
                        privkeylen, OSSL_MLKEM768_PRIVATE_KEY_BYTES);
            return 0;
        }
        if (!ossl_mlkem768_parse_private_key(&key->privkey, key->encoded_privkey,
                                             key->mlkem_ctx))
            return 0;
    }

    if (param_pub_key != NULL) {
        if (!OSSL_PARAM_get_octet_string(param_pub_key,
                                         (void **)&key->encoded_pubkey,
                                         OSSL_MLKEM768_PUBLIC_KEY_BYTES,
                                         &pubkeylen))
            return 0;
        if (pubkeylen != OSSL_MLKEM768_PUBLIC_KEY_BYTES) {
            debug_print("sec key len mismatch in import: %ld vs %d\n",
                        pubkeylen, OSSL_MLKEM768_PUBLIC_KEY_BYTES);
            return 0;
        }
        if (!ossl_mlkem768_parse_public_key(&key->pubkey, key->encoded_pubkey,
                                            key->mlkem_ctx))
            return 0;
    }

    /*
     * TBD if hybrid logic is not getting cleanly implemented in separate logic:
     * reconstitute (only) classic part here
     */

    return 1;
}

static int mlkem_import(void *key, int selection, const OSSL_PARAM params[])
{
    MLKEM768_KEY *mkey = key;
    int ok = 1;
    int include_private;

    debug_print("MLKEMKM import %p\n", mkey);
    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    ok = ok && ossl_mlkem_key_fromdata(mkey, params, include_private);

    debug_print("MLKEMKM import result %d\n", ok);
    return ok;
}

static int mlkem_get_params(void *key, OSSL_PARAM params[])
{
    MLKEM768_KEY *mkey = key;
    OSSL_PARAM *p;

    debug_print("MLKEMKM get params %p\n", mkey);
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, sizeof(ossl_mlkem768_private_key) * 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, OSSL_MLKEM768_SECURITY_BITS))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, OSSL_MLKEM768_CIPHERTEXT_BYTES))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL
        && mkey->encoded_pubkey != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, mkey->encoded_pubkey, OSSL_MLKEM768_PUBLIC_KEY_BYTES))
            return 0;
        debug_print("MLKEMKM got encoded public key of len %d\n", OSSL_MLKEM768_PUBLIC_KEY_BYTES);
        print_hex(mkey->encoded_pubkey, OSSL_MLKEM768_PUBLIC_KEY_BYTES, "enc PK");
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL
        && mkey->encoded_privkey != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, mkey->encoded_privkey, OSSL_MLKEM768_PRIVATE_KEY_BYTES))
            return 0;
        debug_print("MLKEMKM got encoded private key of len %d\n", OSSL_MLKEM768_PRIVATE_KEY_BYTES);
        print_hex(mkey->encoded_privkey, OSSL_MLKEM768_PRIVATE_KEY_BYTES, "enc SK");
    }

    debug_print("MLKEMKM get params OK\n");
    return 1;
}

static const OSSL_PARAM mlkem_gettable_params_arr[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_MLKEM_SEED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_gettable_params(void *provctx)
{
    debug_print("MLKEMKM gettable params called\n");
    return mlkem_gettable_params_arr;
}

static int mlkem_set_params(void *key, const OSSL_PARAM params[])
{
    MLKEM768_KEY *mkey = key;
    const OSSL_PARAM *p;
    size_t len_stored;

    debug_print("MLKEMKM set params called for %p\n", mkey);
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data_size != OSSL_MLKEM768_PUBLIC_KEY_BYTES
                || !OSSL_PARAM_get_octet_string(p, (void **)&mkey->encoded_pubkey,
                                                OSSL_MLKEM768_PUBLIC_KEY_BYTES,
                                                &len_stored)
                || len_stored != OSSL_MLKEM768_PUBLIC_KEY_BYTES)
            return 0;
        debug_print("encoded pub key successfully stored with %ld bytes\n", len_stored);
        if (!ossl_mlkem768_parse_public_key(&mkey->pubkey, mkey->encoded_pubkey,
                                            mkey->mlkem_ctx))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        if (p->data_size != OSSL_MLKEM768_PRIVATE_KEY_BYTES
            || !OSSL_PARAM_get_octet_string(p, (void **)&mkey->encoded_privkey,
                                            OSSL_MLKEM768_PRIVATE_KEY_BYTES,
                                            &len_stored))
            return 0;
        ossl_mlkem768_parse_private_key(&mkey->privkey, mkey->encoded_privkey,
                                        mkey->mlkem_ctx);
    }

    debug_print("MLKEMKM set params OK\n");
    return 1;
}

static const OSSL_PARAM mlkem_settable_params_arr[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_settable_params(void *provctx)
{
    debug_print("MLKEMKM settable params called\n");
    return mlkem_settable_params_arr;
}

static void *mlkem_gen_init(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    struct mlkem_gen_ctx *gctx = NULL;

    debug_print("MLKEMKM gen init called for %p\n", provctx);
    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        gctx->selection = selection;
    }
    if (!mlkem_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx);
        gctx = NULL;
    }
    debug_print("MLKEMKM gen init returns %p\n", gctx);
    return gctx;
}

static int mlkem_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct mlkem_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    if (ossl_param_is_empty(params))
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MLKEM_SEED)) != NULL) {
        if (gctx->seed != NULL)
            OPENSSL_free(gctx->seed);
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p->data_size != OSSL_MLKEM_SEED_BYTES
            || (gctx->seed = OPENSSL_memdup(p->data, OSSL_MLKEM_SEED_BYTES)) == NULL)
            return 0;
    }

    debug_print("MLKEMKM gen_set params called for %p\n", gctx);
    return 1;
}

static const OSSL_PARAM *mlkem_gen_settable_params(ossl_unused void *genctx,
                                                   ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_MLKEM_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void *mlkem_gen(void *vctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct mlkem_gen_ctx *gctx = (struct mlkem_gen_ctx *)vctx;
    MLKEM768_KEY *mkey;

    debug_print("MLKEMKM gen called for %p\n", gctx);
    if (gctx == NULL)
        return NULL;

    if ((mkey = mlkem_new(gctx->provctx)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    /* If we're doing parameter generation then we just return a blank key */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        debug_print("MLKEMKM gen returns blank %p\n", mkey);
        return mkey;
    }

    mkey->keytype = MLKEM_KEY_TYPE_768;

    if (mkey->encoded_pubkey == NULL) {
        mkey->encoded_pubkey = OPENSSL_malloc(OSSL_MLKEM768_PUBLIC_KEY_BYTES);
        if (mkey->encoded_pubkey == NULL)
            goto err;
    }

    if (mkey->encoded_privkey == NULL) {
        mkey->encoded_privkey = OPENSSL_malloc(OSSL_MLKEM768_PRIVATE_KEY_BYTES);
        if (mkey->encoded_privkey == NULL)
            goto err;
    }

    if (gctx->seed != NULL) {
        debug_print("MLKEMKM generate keys from seed");
        if (!ossl_mlkem768_private_key_from_seed(&mkey->privkey, gctx->seed,
                                                 OSSL_MLKEM_SEED_BYTES,
                                                 mkey->mlkem_ctx)
            || !ossl_mlkem768_marshal_private_key(mkey->encoded_privkey,
                                                  &mkey->privkey)
            || !ossl_mlkem768_public_from_private(&mkey->pubkey, &mkey->privkey)
            || !ossl_mlkem768_marshal_public_key(mkey->encoded_pubkey,
                                                 &mkey->pubkey))
            goto err;
    } else {
        debug_print("MLKEMKM generate random keys");
        if (!ossl_mlkem768_generate_key(mkey->encoded_pubkey, gctx->seed,
                                        &mkey->privkey, mkey->mlkem_ctx)
            || !ossl_mlkem768_marshal_private_key(mkey->encoded_privkey,
                                                  &mkey->privkey)
            || !ossl_mlkem768_public_from_private(&mkey->pubkey,
                                                  &mkey->privkey))
            goto err;
    }

    debug_print("MLKEMKM gen returns set %p\n", mkey);
    return mkey;

err:
    OPENSSL_free(mkey);
    return NULL;
}

static void mlkem_gen_cleanup(void *genctx)
{
    struct mlkem_gen_ctx *gctx = genctx;

    OPENSSL_free(gctx->seed);
    debug_print("MLKEMKM gen cleanup for %p\n", gctx);
    OPENSSL_free(gctx);
}

static void *mlkem_dup(const void *vsrckey, int selection)
{
    const MLKEM768_KEY *srckey = (const MLKEM768_KEY *)vsrckey;
    MLKEM768_KEY *dstkey;

    debug_print("MLKEMKM dup called for %p\n", srckey);
    if (!ossl_prov_is_running())
        return NULL;

    dstkey = mlkem_new(srckey->provctx);
    if (dstkey == NULL)
        return NULL;

    dstkey->keytype = srckey->keytype;
    if (srckey->encoded_pubkey != NULL
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        memcpy((void *)&dstkey->pubkey, (void *)&srckey->pubkey,
               sizeof(srckey->pubkey));
        if ((dstkey->encoded_pubkey = OPENSSL_memdup(srckey->encoded_pubkey,
                                                     OSSL_MLKEM768_PUBLIC_KEY_BYTES)) == NULL)
            return NULL;
    }
    if (srckey->encoded_privkey != NULL
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        memcpy((void *)&dstkey->privkey, (void *)&srckey->privkey,
               sizeof(srckey->privkey));
        if ((dstkey->encoded_privkey = OPENSSL_memdup(srckey->encoded_privkey,
                                                      OSSL_MLKEM768_PRIVATE_KEY_BYTES)) == NULL)
            return NULL;
    }

    debug_print("MLKEMKM dup returns %p\n", dstkey);
    return dstkey;
}

const OSSL_DISPATCH ossl_mlkem768_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))mlkem_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))mlkem_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))mlkem_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))mlkem_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))mlkem_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))mlkem_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))mlkem_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))mlkem_match },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mlkem_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))mlkem_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))mlkem_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))mlkem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))mlkem_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))mlkem_dup },
    /*
     * TODO(ML-KEM): https://github.com/openssl/openssl/issues/25885
     * Export/import functionality has been partially implemented. Need to test
     * for interopability.
     */
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))mlkem_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))mlkem_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))mlkem_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))mlkem_imexport_types },
    OSSL_DISPATCH_END
};
