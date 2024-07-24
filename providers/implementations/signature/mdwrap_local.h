/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is included by all signature algorithms that provide {key}-{hash}
 * signature implementations.
 */

/*
 * Internal hash function method.  For the non-sigalg implementation,
 * this is just a wrapper around EVP_MD functionality.  For sigalg
 * implementations, however, a more direct approach is taken, which
 * depends entirely on what hash algorithms are implemented in this
 * provider.
 */
#include <openssl/evp.h>
struct md_wrapper_st {
    int mdnid;                       /* Note: hard-coded by sigalg impl */
    char mdname[OSSL_MAX_NAME_SIZE]; /* Purely informational */
    size_t mdsize;                   /* Cached */

    /*
     * This is EVP_MD_CTX for non-sigalg signature implementations
     * This is the hash provider context for sigalg signature implementations
     */
    void *mdctx;

    /* |md| is reserved for non-sigalg impls */
    EVP_MD *md;

    /* The OSSL_FUNC_digest pointers are reserved for sigalg impls */
    OSSL_FUNC_digest_newctx_fn                  *newctx;
    OSSL_FUNC_digest_freectx_fn                 *freectx;
    OSSL_FUNC_digest_dupctx_fn                  *dupctx;
    OSSL_FUNC_digest_init_fn                    *init;
    OSSL_FUNC_digest_digest_fn                  *digest;
    OSSL_FUNC_digest_update_fn                  *update;
    OSSL_FUNC_digest_final_fn                   *final;
    OSSL_FUNC_digest_get_params_fn              *get_params;
    OSSL_FUNC_digest_settable_ctx_params_fn     *settable_ctx_params;
    OSSL_FUNC_digest_set_ctx_params_fn          *set_ctx_params;
    OSSL_FUNC_digest_gettable_ctx_params_fn     *gettable_ctx_params;
    OSSL_FUNC_digest_get_ctx_params_fn          *get_ctx_params;
};

static ossl_inline int wrap_md_is_set(struct md_wrapper_st *wrp)
{
    return (wrp->md != NULL || wrp->init != NULL);
}

static ossl_inline int wrap_md_newctx(struct md_wrapper_st *wrp, void *provctx)
{
    if (wrp->md != NULL)
        wrp->mdctx = EVP_MD_CTX_new();
    else if (wrp->newctx != NULL)
        wrp->mdctx = wrp->newctx(provctx);
    return wrp->mdctx != NULL;
}

static ossl_inline void wrap_md_freectx(struct md_wrapper_st *wrp)
{
    if (wrp->md != NULL)
        EVP_MD_CTX_free(wrp->mdctx);
    else if (wrp->newctx != NULL)
        wrp->freectx(wrp->mdctx);
    wrp->mdctx = NULL;
}

static ossl_inline int
wrap_md_init(struct md_wrapper_st *wrp, const OSSL_PARAM params[])
{
    if (wrp->mdctx == NULL)
        return 0;
    if (wrp->md != NULL)
        return EVP_DigestInit_ex2(wrp->mdctx, wrp->md, params);
    else if (wrp->init != NULL)
        return wrp->init(wrp->mdctx, params);
    return 0;
}

static ossl_inline int
wrap_md_update(struct md_wrapper_st *wrp, const unsigned char *in, size_t inl)
{
    if (wrp->mdctx == NULL)
        return 0;
    if (wrp->md != NULL)
        return EVP_DigestUpdate(wrp->mdctx, in, inl);
    else if (wrp->update != NULL)
        return wrp->update(wrp->mdctx, in, inl);
    return 0;
}

static ossl_inline int
wrap_md_final(struct md_wrapper_st *wrp, unsigned char *out, size_t *outl, size_t outsz)
{
    if (wrp->mdctx == NULL)
        return 0;
    if (wrp->md != NULL) {
        unsigned int outlen = (unsigned int)outsz;
        int ret = EVP_DigestFinal_ex(wrp->mdctx, out, &outlen);

        if (outl != NULL)
            *outl = (size_t)outlen;
        return ret;
    } else if (wrp->final != NULL) {
        return wrp->final(wrp->mdctx, out, outl, outsz);
    }
    return 0;
}

static ossl_inline size_t wrap_md_get_size(struct md_wrapper_st *wrp)
{
    if (wrp->mdsize > 0)
        return wrp->mdsize;

    if (wrp->md != NULL) {
        int md_size = EVP_MD_get_size(wrp->md);

        if (md_size <= 0)
            return 0;
        return md_size;
    } else if (wrp->get_params != NULL) {
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE,
                                                &wrp->mdsize);
        params[1] = OSSL_PARAM_construct_end();
        if (!wrp->get_params(params)) {
            wrp->mdsize = 0;
            return 0;
        }
        return wrp->mdsize;
    }
    return 0;
}

static ossl_inline int wrap_md_up_ref(struct md_wrapper_st *wrp)
{
    if (wrp->md != NULL)
        return EVP_MD_up_ref(wrp->md);

    /* Nothing to upref */
    return 1;
}

static ossl_inline int
wrap_md_is_a(const struct md_wrapper_st *wrp, const char *mdname, int mdnid)
{
    if (wrp->md != NULL)
        return EVP_MD_is_a(wrp->md, mdname);
    return wrp->mdnid == mdnid;
}

static ossl_inline int wrap_md_copy(struct md_wrapper_st *dstwrp,
                                    struct md_wrapper_st *srcwrp)
{
    *dstwrp = *srcwrp;
    dstwrp->md = NULL;
    dstwrp->mdctx = NULL;

    if (srcwrp->md != NULL) {
        if (!wrap_md_up_ref(srcwrp))
            return 0;
        dstwrp->md = srcwrp->md;

        if (srcwrp->mdctx != NULL
            && (dstwrp->mdctx = EVP_MD_CTX_dup(srcwrp->mdctx)) == NULL)
            return 0;
    } else if (srcwrp->dupctx != NULL) {
        if (srcwrp->mdctx != NULL
            && (dstwrp->mdctx = srcwrp->dupctx(srcwrp->mdctx)) == NULL)
            return 0;
    }
    return 1;
}

static ossl_inline const OSSL_PARAM *
wrap_md_settable_ctx_params(struct md_wrapper_st *wrp, void *provctx)
{
    if (wrp->mdctx == NULL)
        return NULL;
    if (wrp->md != NULL)
        return EVP_MD_CTX_settable_params(wrp->mdctx);
    else if (wrp->settable_ctx_params != NULL)
        return wrp->settable_ctx_params(wrp->mdctx, provctx);
    return NULL;
}

static ossl_inline int
wrap_md_set_ctx_params(struct md_wrapper_st *wrp, const OSSL_PARAM params[])
{
    if (wrp->mdctx == NULL)
        return 0;
    if (wrp->md != NULL)
        return EVP_MD_CTX_set_params(wrp->mdctx, params);
    else if (wrp->set_ctx_params != NULL)
        return wrp->set_ctx_params(wrp->mdctx, params);
    return 0;
}

static ossl_inline const OSSL_PARAM *
wrap_md_gettable_ctx_params(struct md_wrapper_st *wrp, void *provctx)
{
    if (wrp->mdctx == NULL)
        return NULL;
    if (wrp->md != NULL)
        return EVP_MD_CTX_gettable_params(wrp->mdctx);
    else if (wrp->gettable_ctx_params != NULL)
        return wrp->gettable_ctx_params(wrp->mdctx, provctx);
    return NULL;
}

static ossl_inline int
wrap_md_get_ctx_params(struct md_wrapper_st *wrp, OSSL_PARAM params[])
{
    if (wrp->mdctx == NULL)
        return 0;
    if (wrp->md != NULL)
        return EVP_MD_CTX_get_params(wrp->mdctx, params);
    else if (wrp->get_ctx_params != NULL)
        return wrp->get_ctx_params(wrp->mdctx, params);
    return 0;
}

static ossl_inline int wrap_md_cleanup(struct md_wrapper_st *wrp)
{
    if (wrp == NULL)
        return 1;

    if (wrp->md != NULL) {
        EVP_MD_CTX_free(wrp->mdctx);
        EVP_MD_free(wrp->md);
    } else if (wrp->freectx != NULL) {
        wrp->freectx(wrp->mdctx);
    }
    wrp->md = NULL;
    wrp->mdctx = NULL;
    return 1;
}

static ossl_inline int
wrap_md_setup(struct md_wrapper_st *wrp, OSSL_LIB_CTX *libctx,
              const char *mdname, const char *mdprops,
              const OSSL_DISPATCH *mddispatch, int mdnid)
{
    EVP_MD *md = NULL;

    if (mdname != NULL) {
        size_t mdname_len = strlen(mdname);

        if (mdname_len >= sizeof(wrp->mdname)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                           "%s exceeds name buffer length", mdname);
            goto err;
        }
    }

    if (mddispatch != NULL) {
        /*
         * Check that the sigalg is implemented correctly.
         * mdname and mdnid are mandatory!
         */
        if (!ossl_assert(mdname != NULL) || !ossl_assert(mdnid != NID_undef)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        for (; mddispatch->function_id != 0; mddispatch++) {
            switch (mddispatch->function_id) {
            case OSSL_FUNC_DIGEST_NEWCTX:
                wrp->newctx = OSSL_FUNC_digest_newctx(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_FREECTX:
                wrp->freectx = OSSL_FUNC_digest_freectx(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_INIT:
                wrp->init = OSSL_FUNC_digest_init(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_UPDATE:
                wrp->update = OSSL_FUNC_digest_update(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_FINAL:
                wrp->final = OSSL_FUNC_digest_final(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_DUPCTX:
                wrp->dupctx = OSSL_FUNC_digest_dupctx(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_DIGEST:
                wrp->digest = OSSL_FUNC_digest_digest(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_GET_PARAMS:
                wrp->get_params = OSSL_FUNC_digest_get_params(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS:
                wrp->settable_ctx_params
                    = OSSL_FUNC_digest_settable_ctx_params(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_SET_CTX_PARAMS:
                wrp->set_ctx_params
                    = OSSL_FUNC_digest_set_ctx_params(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS:
                wrp->gettable_ctx_params
                    = OSSL_FUNC_digest_gettable_ctx_params(mddispatch);
                break;
            case OSSL_FUNC_DIGEST_GET_CTX_PARAMS:
                wrp->get_ctx_params
                    = OSSL_FUNC_digest_get_ctx_params(mddispatch);
                break;
            }
        }
        /* We trust our own implementations, no function check needed */
    } else if (mdname != NULL) {
        md = EVP_MD_fetch(libctx, mdname, mdprops);

        if (md == NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                           "%s could not be fetched", mdname);
            goto err;
        }

        mdnid = NID_undef;       /* To be updated by the caller */
    }

    wrap_md_cleanup(wrp);
    wrp->mdctx = NULL;
    wrp->md = md;
    wrp->mdnid = mdnid;
    OPENSSL_strlcpy(wrp->mdname, mdname, sizeof(wrp->mdname));

    return 1;
err:
    EVP_MD_free(md);
    return 0;
}
