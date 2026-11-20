/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Lifetime of providers that own a child library context when the parent
 * library context is freed.  Each scenario runs in its own process (see
 * test/recipes/04-test_provider_child_teardown.t) and ends with the test
 * driver's OPENSSL_cleanup().  The failures are use-after-free reads, so they
 * are only reliably detected in sanitizer builds.
 *
 * All providers are built-in and obtain their library context through
 * OSSL_LIB_CTX_new_child(); "pkeyctx-unload" and "keyname-unload" also use
 * the core_get_libctx() cast that provider-base(7) allows for built-in
 * providers.
 *
 *   orig            A child owner's method is cached in the parent, and the
 *                   child's DRBG (default provider mirror) uses the parent's
 *                   AES.  Handles are unloaded.
 *   keep-rand       The child owner pulls RAND into its child during init;
 *                   the provider handles are kept across OSSL_LIB_CTX_free().
 *   hmac-unload     The child owner supplies XDIGEST and keeps an
 *                   HMAC(XDIGEST) context created in its child.  The default
 *                   provider's HMAC runs with that provider's provctx and
 *                   fetches XDIGEST from the parent, i.e. the child owner's
 *                   own method in the parent's store.  Handles are unloaded.
 *   hmac-keep       As hmac-unload, handles kept.
 *   pkeyctx-unload  The child owner keeps an EVP_PKEY_CTX created in the
 *                   parent for its own key type and frees it in teardown.
 *   keyname-unload  As pkeyctx-unload; teardown also uses the method's name.
 *   cross           Two child owners: a-owner implements XDIGEST with SHA2-256
 *                   fetched in its own child; b-holder keeps an XDIGEST context
 *                   in its child, served by a-owner's mirror.  a-owner is
 *                   loaded first.  Handles are unloaded.
 *   cross-swap      As cross, b-holder is loaded first.
 */

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include "testutil.h"

enum role {
    ROLE_ORIG, /* keymgmt ORIG-KEY; RAND in the child on trigger */
    ROLE_RANDINIT, /* RAND in the child during init */
    ROLE_HMAC, /* XDIGEST; keeps HMAC(XDIGEST) created in the child */
    ROLE_OWNER, /* XDIGEST implemented with SHA2-256 from its own child */
    ROLE_HOLDER, /* keeps an XDIGEST EVP_MD_CTX created in its child */
    ROLE_PKEY, /* keymgmt XKEY; keeps an EVP_PKEY_CTX created in parent */
    ROLE_KEYNAME /* as ROLE_PKEY, teardown also uses the method's name */
};

static const char *role_names[] = {
    "orig-owner", "randinit-owner", "hmac-owner", "a-owner", "b-holder",
    "pkey-owner", "keyname-owner"
};

typedef struct {
    enum role role;
    OSSL_LIB_CTX *child;
    OSSL_LIB_CTX *parent; /* ROLE_PKEY/ROLE_KEYNAME only */
    EVP_MAC_CTX *mac; /* ROLE_HMAC */
    EVP_MD_CTX *mdctx; /* ROLE_HOLDER */
    EVP_PKEY_CTX *pkctx; /* ROLE_PKEY/ROLE_KEYNAME */
    EVP_KEYMGMT *keymgmt; /* ROLE_KEYNAME */
} PROV_CTX;

/* ------------------------------------------------------------------------ */
/* XDIGEST: trivial (ROLE_HMAC) or SHA2-256 from the owner's child (OWNER)   */

typedef struct {
    EVP_MD *md; /* ROLE_OWNER: fetched in the owner's child */
    EVP_MD_CTX *inner; /* ROLE_OWNER: lives in the owner's child */
    unsigned char acc;
} XDIGEST_CTX;

static void *xdigest_newctx(void *provctx)
{
    PROV_CTX *p = provctx;
    XDIGEST_CTX *x = OPENSSL_zalloc(sizeof(*x));

    if (x == NULL)
        return NULL;
    if (p->role == ROLE_OWNER) {
        x->md = EVP_MD_fetch(p->child, "SHA2-256", "provider=default");
        x->inner = EVP_MD_CTX_new();
        if (x->md == NULL || x->inner == NULL
            || !EVP_DigestInit_ex2(x->inner, x->md, NULL)) {
            EVP_MD_CTX_free(x->inner);
            EVP_MD_free(x->md);
            OPENSSL_free(x);
            return NULL;
        }
    }
    return x;
}

static void xdigest_freectx(void *vx)
{
    XDIGEST_CTX *x = vx;

    if (x == NULL)
        return;
    EVP_MD_CTX_free(x->inner);
    EVP_MD_free(x->md);
    OPENSSL_free(x);
}

static void *xdigest_dupctx(void *vx)
{
    XDIGEST_CTX *x = vx, *y = OPENSSL_memdup(x, sizeof(*x));

    if (y == NULL || x->inner == NULL)
        return y;
    y->inner = EVP_MD_CTX_dup(x->inner);
    if (y->inner == NULL || (y->md != NULL && !EVP_MD_up_ref(y->md))) {
        EVP_MD_CTX_free(y->inner);
        OPENSSL_free(y);
        return NULL;
    }
    return y;
}

static int xdigest_init(void *vx, const OSSL_PARAM params[])
{
    XDIGEST_CTX *x = vx;

    x->acc = 0;
    return x->inner == NULL || EVP_DigestInit_ex2(x->inner, x->md, NULL);
}

static int xdigest_update(void *vx, const unsigned char *in, size_t inl)
{
    XDIGEST_CTX *x = vx;

    if (x->inner != NULL)
        return EVP_DigestUpdate(x->inner, in, inl);
    while (inl-- > 0)
        x->acc ^= *in++;
    return 1;
}

static int xdigest_final(void *vx, unsigned char *out, size_t *outl,
    size_t outsz)
{
    XDIGEST_CTX *x = vx;
    unsigned int l = 0;

    if (outsz < 32)
        return 0;
    if (x->inner != NULL) {
        if (!EVP_DigestFinal_ex(x->inner, out, &l))
            return 0;
    } else {
        memset(out, x->acc, 32);
    }
    *outl = 32;
    return 1;
}

static int xdigest_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, 64))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, 32))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF)) != NULL
        && !OSSL_PARAM_set_int(p, 0))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT)) != NULL
        && !OSSL_PARAM_set_int(p, 0))
        return 0;
    return 1;
}

static const OSSL_PARAM *xdigest_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
        OSSL_PARAM_END
    };

    return table;
}

static const OSSL_DISPATCH xdigest_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))xdigest_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))xdigest_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))xdigest_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))xdigest_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))xdigest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))xdigest_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))xdigest_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
        (void (*)(void))xdigest_gettable_params },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM xdigest_algs[] = {
    { "XDIGEST", "provider=xdigest-owner", xdigest_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

/* ------------------------------------------------------------------------ */
/* Minimal key management (same shape as the PR's DUMMY-KEY)                */

static void *key_new(void *provctx)
{
    return provctx;
}

static void key_free(void *keydata)
{
}

static int key_has(const void *keydata, int selection)
{
    return 1;
}

static const OSSL_DISPATCH key_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))key_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))key_has },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM orig_keymgmt[] = {
    { "ORIG-KEY", "provider=orig-owner", key_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM x_keymgmt[] = {
    { "XKEY", "provider=pkey-owner", key_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

/* ------------------------------------------------------------------------ */
/* Provider                                                                  */

static const OSSL_ALGORITHM *prov_query(void *provctx, int operation_id,
    int *no_cache)
{
    PROV_CTX *p = provctx;

    *no_cache = 0;
    switch (p->role) {
    case ROLE_ORIG:
        return operation_id == OSSL_OP_KEYMGMT ? orig_keymgmt : NULL;
    case ROLE_HMAC:
    case ROLE_OWNER:
        return operation_id == OSSL_OP_DIGEST ? xdigest_algs : NULL;
    case ROLE_PKEY:
    case ROLE_KEYNAME:
        return operation_id == OSSL_OP_KEYMGMT ? x_keymgmt : NULL;
    default:
        return NULL;
    }
}

/*
 * OSSL_PROVIDER_get_params() is used as a hook that makes the provider create
 * the provider-internal state that a real provider would create lazily.
 */
static int prov_get_params(void *provctx, OSSL_PARAM params[])
{
    PROV_CTX *p = provctx;
    unsigned char buf[16];

    switch (p->role) {
    case ROLE_ORIG:
        return RAND_bytes_ex(p->child, buf, sizeof(buf), 0) > 0;

    case ROLE_HMAC:
        if (p->mac == NULL) {
            static unsigned char key[16];
            EVP_MAC *mac = EVP_MAC_fetch(p->child, "HMAC", "provider=default");
            OSSL_PARAM mp[] = {
                OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, "XDIGEST", 0),
                OSSL_PARAM_END
            };

            p->mac = mac == NULL ? NULL : EVP_MAC_CTX_new(mac);
            EVP_MAC_free(mac);
            if (p->mac == NULL || !EVP_MAC_init(p->mac, key, sizeof(key), mp))
                return 0;
            TEST_note("hmac-owner keeps an HMAC(XDIGEST) context in its child");
        }
        return 1;

    case ROLE_HOLDER:
        if (p->mdctx == NULL) {
            EVP_MD *md = EVP_MD_fetch(p->child, "XDIGEST", NULL);

            p->mdctx = EVP_MD_CTX_new();
            if (md == NULL || p->mdctx == NULL
                || !EVP_DigestInit_ex2(p->mdctx, md, NULL)) {
                EVP_MD_free(md);
                return 0;
            }
            EVP_MD_free(md);
            TEST_note("b-holder keeps an XDIGEST context in its child");
        }
        return 1;

    case ROLE_PKEY:
    case ROLE_KEYNAME:
        if (p->pkctx == NULL) {
            p->pkctx = EVP_PKEY_CTX_new_from_name(p->parent, "XKEY",
                "provider=pkey-owner");
            if (p->pkctx == NULL)
                return 0;
            if (p->role == ROLE_KEYNAME
                && (p->keymgmt = EVP_KEYMGMT_fetch(p->parent, "XKEY",
                        "provider=pkey-owner"))
                    == NULL)
                return 0;
            TEST_note("%s keeps an EVP_PKEY_CTX for its own key type",
                role_names[p->role]);
        }
        return 1;

    default:
        return 1;
    }
}

static void prov_teardown(void *provctx)
{
    PROV_CTX *p = provctx;

    TEST_note("teardown: %s", role_names[p->role]);
    if (p->keymgmt != NULL)
        TEST_note("teardown: %s key type is %s", role_names[p->role],
            EVP_KEYMGMT_get0_name(p->keymgmt));
    EVP_KEYMGMT_free(p->keymgmt);
    EVP_PKEY_CTX_free(p->pkctx);
    EVP_MAC_CTX_free(p->mac);
    EVP_MD_CTX_free(p->mdctx);
    OSSL_LIB_CTX_free(p->child);
    OPENSSL_free(p);
}

static const OSSL_DISPATCH prov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))prov_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))prov_teardown },
    OSSL_DISPATCH_END
};

static int prov_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx, enum role role)
{
    PROV_CTX *p = OPENSSL_zalloc(sizeof(*p));
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    const OSSL_DISPATCH *d;
    unsigned char buf[16];

    if (p == NULL)
        return 0;
    p->role = role;
    if (role == ROLE_PKEY || role == ROLE_KEYNAME) {
        /* Permitted for built-in providers only, see provider-base(7) */
        for (d = in; d->function_id != 0; d++)
            if (d->function_id == OSSL_FUNC_CORE_GET_LIBCTX)
                c_get_libctx = OSSL_FUNC_core_get_libctx(d);
        if (c_get_libctx == NULL)
            goto err;
        p->parent = (OSSL_LIB_CTX *)c_get_libctx(handle);
    }
    if ((p->child = OSSL_LIB_CTX_new_child(handle, in)) == NULL)
        goto err;
    if (role == ROLE_RANDINIT
        && RAND_bytes_ex(p->child, buf, sizeof(buf), 0) <= 0)
        goto err;
    *provctx = p;
    *out = prov_dispatch;
    return 1;
err:
    OSSL_LIB_CTX_free(p->child);
    OPENSSL_free(p);
    return 0;
}

#define DEFINE_INIT(name, role)                                          \
    static int name(const OSSL_CORE_HANDLE *handle,                      \
        const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **pctx) \
    {                                                                    \
        return prov_init(handle, in, out, pctx, role);                   \
    }

DEFINE_INIT(orig_init, ROLE_ORIG)
DEFINE_INIT(randinit_init, ROLE_RANDINIT)
DEFINE_INIT(hmac_init, ROLE_HMAC)
DEFINE_INIT(owner_init, ROLE_OWNER)
DEFINE_INIT(holder_init, ROLE_HOLDER)
DEFINE_INIT(pkey_init, ROLE_PKEY)
DEFINE_INIT(keyname_init, ROLE_KEYNAME)

/* ------------------------------------------------------------------------ */

/* Handles deliberately kept across OSSL_LIB_CTX_free() in the *-keep modes */
static OSSL_PROVIDER *kept_handles[4];

static int trigger(OSSL_PROVIDER *prov)
{
    int unused = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_int("repro-trigger", &unused),
        OSSL_PARAM_END
    };

    return OSSL_PROVIDER_get_params(prov, params);
}

static const char *mode;

static int test_child_owner_teardown(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt = NULL, *a = NULL, *b = NULL;
    EVP_KEYMGMT *keymgmt = NULL;
    int keep = 0;

    if (!TEST_ptr(libctx)
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "orig-owner",
            orig_init))
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "randinit-owner",
            randinit_init))
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "hmac-owner",
            hmac_init))
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "a-owner", owner_init))
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "b-holder",
            holder_init))
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "pkey-owner",
            pkey_init))
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "keyname-owner",
            keyname_init))
        || !TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto err;

    if (strcmp(mode, "orig") == 0) {
        /* Caches orig-owner's method in the parent */
        if (!TEST_ptr(a = OSSL_PROVIDER_load(libctx, "orig-owner"))
            || !TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(libctx, "ORIG-KEY", NULL))
            || !TEST_true(trigger(a)))
            goto err;
    } else if (strcmp(mode, "keep-rand") == 0) {
        if (!TEST_ptr(a = OSSL_PROVIDER_load(libctx, "randinit-owner")))
            goto err;
        keep = 1;
    } else if (strcmp(mode, "hmac-unload") == 0
        || strcmp(mode, "hmac-keep") == 0) {
        if (!TEST_ptr(a = OSSL_PROVIDER_load(libctx, "hmac-owner"))
            || !TEST_true(trigger(a)))
            goto err;
        keep = strcmp(mode, "hmac-keep") == 0;
    } else if (strcmp(mode, "pkeyctx-unload") == 0) {
        if (!TEST_ptr(a = OSSL_PROVIDER_load(libctx, "pkey-owner"))
            || !TEST_true(trigger(a)))
            goto err;
    } else if (strcmp(mode, "keyname-unload") == 0) {
        if (!TEST_ptr(a = OSSL_PROVIDER_load(libctx, "keyname-owner"))
            || !TEST_true(trigger(a)))
            goto err;
    } else if (strcmp(mode, "cross") == 0) {
        if (!TEST_ptr(a = OSSL_PROVIDER_load(libctx, "a-owner"))
            || !TEST_ptr(b = OSSL_PROVIDER_load(libctx, "b-holder"))
            || !TEST_true(trigger(b)))
            goto err;
    } else if (strcmp(mode, "cross-swap") == 0) {
        if (!TEST_ptr(b = OSSL_PROVIDER_load(libctx, "b-holder"))
            || !TEST_ptr(a = OSSL_PROVIDER_load(libctx, "a-owner"))
            || !TEST_true(trigger(b)))
            goto err;
    } else {
        TEST_error("unknown mode %s", mode);
        goto err;
    }
    EVP_KEYMGMT_free(keymgmt);

    if (keep) {
        /* Documented as unnecessary: OSSL_LIB_CTX_free() frees providers */
        kept_handles[0] = deflt;
        kept_handles[1] = a;
        kept_handles[2] = b;
    } else {
        OSSL_PROVIDER_unload(b);
        OSSL_PROVIDER_unload(a);
        OSSL_PROVIDER_unload(deflt);
    }
    TEST_note("OSSL_LIB_CTX_free(parent), provider handles %s",
        keep ? "kept" : "unloaded");
    OSSL_LIB_CTX_free(libctx);
    return 1;

err:
    EVP_KEYMGMT_free(keymgmt);
    OSSL_PROVIDER_unload(b);
    OSSL_PROVIDER_unload(a);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}

OPT_TEST_DECLARE_USAGE("mode\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!TEST_ptr(mode = test_get_argument(0)))
        return 0;
    ADD_TEST(test_child_owner_teardown);
    return 1;
}
