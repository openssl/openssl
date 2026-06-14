/*
 * ML-DSA Provider for OpenSSL CLI
 * Para gumana ang `openssl genpkey -algorithm ML-DSA-87`
 */

#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/params.h>
#include <openssl/evp.h>

/* External declarations (galing sa ml_dsa_evp.c) */
extern int ml_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
extern int ml_dsa_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen);
extern int ml_dsa_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen);

/* Algorithm definition para sa signature */
static OSSL_ALGORITHM ml_dsa_sig_algs[] = {
    { "ML-DSA-87", "provider=ml-dsa", NULL },
    { "MLDSA87", "provider=ml-dsa", NULL },
    { NULL, NULL, NULL }
};

/* Algorithm definition para sa key management */
static OSSL_ALGORITHM ml_dsa_keymgmt_algs[] = {
    { "ML-DSA-87", "provider=ml-dsa", NULL },
    { NULL, NULL, NULL }
};

/* Provider query function */
static const OSSL_ALGORITHM *ml_dsa_query(OSSL_PROVIDER *prov,
                                           int operation_id,
                                           int *no_cache)
{
    *no_cache = 0;
    
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return ml_dsa_sig_algs;
    case OSSL_OP_KEYMGMT:
        return ml_dsa_keymgmt_algs;
    default:
        return NULL;
    }
}

/* Provider init function */
static int ml_dsa_provider_init(OSSL_PROVIDER *prov)
{
    return 1;
}

/* Provider teardown function */
static int ml_dsa_provider_teardown(OSSL_PROVIDER *prov)
{
    return 1;
}

/* Provider dispatch table */
static const OSSL_DISPATCH ml_dsa_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ml_dsa_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ml_dsa_provider_teardown },
    { 0, NULL }
};

/* Provider entry point */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                        const OSSL_DISPATCH *in,
                        const OSSL_DISPATCH **out,
                        void **provctx)
{
    *out = ml_dsa_dispatch;
    return ml_dsa_provider_init(NULL);
}
