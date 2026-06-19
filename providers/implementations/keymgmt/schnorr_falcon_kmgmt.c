#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include <oqs/oqs.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/schnorr_falcon.h"

struct gen_ctx { PROV_CTX *provctx; char *propq; };

static void *sf_new(void *provctx) {
    SCHNORR_FALCON_KEY *k = OPENSSL_zalloc(sizeof(*k));
    if (k) k->libctx = PROV_LIBCTX_OF(provctx);
    return k;
}
static void sf_free(void *keydata) {
    SCHNORR_FALCON_KEY *k = keydata;
    if (k) { EC_KEY_free(k->schnorr_key); OPENSSL_free(k->falcon_pubkey);
             OPENSSL_free(k->falcon_privkey); OPENSSL_free(k->propq); OPENSSL_free(k); }
}
static int sf_has(const void *keydata, int sel) {
    const SCHNORR_FALCON_KEY *k = keydata;
    int ok = 0;
    if (sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) ok = k->has_pub && k->schnorr_key && k->falcon_pubkey;
    if (sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ok = k->has_priv && k->schnorr_key && k->falcon_privkey;
    return ok;
}
static void *sf_gen_init(void *provctx, int sel, const OSSL_PARAM params[]) {
    struct gen_ctx *g = OPENSSL_zalloc(sizeof(*g));
    if (g) g->provctx = provctx;
    return g;
}
static void *sf_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg) {
    struct gen_ctx *g = genctx;
    SCHNORR_FALCON_KEY *k = sf_new(g->provctx);
    if (!k) return NULL;
    k->schnorr_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!k->schnorr_key || !EC_KEY_generate_key(k->schnorr_key)) goto err;
    k->falcon_pubkey_len = OQS_SIG_falcon_1024_length_public_key;
    k->falcon_privkey_len = OQS_SIG_falcon_1024_length_secret_key;
    k->falcon_pubkey = OPENSSL_malloc(k->falcon_pubkey_len);
    k->falcon_privkey = OPENSSL_malloc(k->falcon_privkey_len);
    if (!k->falcon_pubkey || !k->falcon_privkey) goto err;
    if (OQS_SIG_falcon_1024_keypair(k->falcon_pubkey, k->falcon_privkey) != OQS_SUCCESS) goto err;
    k->has_pub = 1; k->has_priv = 1;
    OPENSSL_free(g);
    return k;
err:
    sf_free(k); OPENSSL_free(g);
    return NULL;
}
static void sf_gen_cleanup(void *g) { OPENSSL_free(g); }

/* DECLARE THE REALITY DIRECTLY */
static int sf_get_params(void *keydata, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) OSSL_PARAM_set_int(p, 256);
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) OSSL_PARAM_set_int(p, 230);
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) OSSL_PARAM_set_size_t(p, 8192);
    return 1;
}

static const OSSL_PARAM *sf_gettable_params(void *provctx) {
    static OSSL_PARAM t[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    return t;
}
static int sf_import(void *keydata, int sel, const OSSL_PARAM p[]) { return 1; }
static int sf_export(void *keydata, int sel, OSSL_CALLBACK *cb, void *cbarg) { return 1; }
static const OSSL_PARAM *sf_import_types(int sel) {
    static const OSSL_PARAM t[] = { OSSL_PARAM_END };
    return t;
}
static const OSSL_PARAM *sf_export_types(int sel) {
    static const OSSL_PARAM t[] = { OSSL_PARAM_END };
    return t;
}

const OSSL_DISPATCH ossl_schnorr_falcon_1024_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sf_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sf_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sf_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sf_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sf_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))sf_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sf_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sf_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))sf_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sf_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sf_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))sf_gettable_params },
    OSSL_DISPATCH_END
};
