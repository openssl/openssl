/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "crypto/rsa.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/der_rsa.h"

static OSSL_OP_signature_newctx_fn rsa_newctx;
static OSSL_OP_signature_sign_init_fn rsa_signature_init;
static OSSL_OP_signature_verify_init_fn rsa_signature_init;
static OSSL_OP_signature_verify_recover_init_fn rsa_signature_init;
static OSSL_OP_signature_sign_fn rsa_sign;
static OSSL_OP_signature_verify_fn rsa_verify;
static OSSL_OP_signature_verify_recover_fn rsa_verify_recover;
static OSSL_OP_signature_digest_sign_init_fn rsa_digest_signverify_init;
static OSSL_OP_signature_digest_sign_update_fn rsa_digest_signverify_update;
static OSSL_OP_signature_digest_sign_final_fn rsa_digest_sign_final;
static OSSL_OP_signature_digest_verify_init_fn rsa_digest_signverify_init;
static OSSL_OP_signature_digest_verify_update_fn rsa_digest_signverify_update;
static OSSL_OP_signature_digest_verify_final_fn rsa_digest_verify_final;
static OSSL_OP_signature_freectx_fn rsa_freectx;
static OSSL_OP_signature_dupctx_fn rsa_dupctx;
static OSSL_OP_signature_get_ctx_params_fn rsa_get_ctx_params;
static OSSL_OP_signature_gettable_ctx_params_fn rsa_gettable_ctx_params;
static OSSL_OP_signature_set_ctx_params_fn rsa_set_ctx_params;
static OSSL_OP_signature_settable_ctx_params_fn rsa_settable_ctx_params;
static OSSL_OP_signature_get_ctx_md_params_fn rsa_get_ctx_md_params;
static OSSL_OP_signature_gettable_ctx_md_params_fn rsa_gettable_ctx_md_params;
static OSSL_OP_signature_set_ctx_md_params_fn rsa_set_ctx_md_params;
static OSSL_OP_signature_settable_ctx_md_params_fn rsa_settable_ctx_md_params;

static OSSL_ITEM padding_item[] = {
    { RSA_PKCS1_PADDING,        "pkcs1"  },
    { RSA_SSLV23_PADDING,       "sslv23" },
    { RSA_NO_PADDING,           "none"   },
    { RSA_PKCS1_OAEP_PADDING,   "oaep"   }, /* Correct spelling first */
    { RSA_PKCS1_OAEP_PADDING,   "oeap"   },
    { RSA_X931_PADDING,         "x931"   },
    { RSA_PKCS1_PSS_PADDING,    "pss"    },
    { 0,                        NULL     }
};

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes RSA structures, so
 * we use that here too.
 */

typedef struct {
    OPENSSL_CTX *libctx;
    RSA *rsa;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    /* The Algorithm Identifier of the combined signature agorithm */
    unsigned char aid_buf[128];
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int mdnid;
    char mdname[OSSL_MAX_NAME_SIZE]; /* Purely informational */

    /* RSA padding mode */
    int pad_mode;
    /* message digest for MGF1 */
    EVP_MD *mgf1_md;
    char mgf1_mdname[OSSL_MAX_NAME_SIZE]; /* Purely informational */
    /* PSS salt length */
    int saltlen;
    /* Minimum salt length or -1 if no PSS parameter restriction */
    int min_saltlen;

    /* Temp buffer */
    unsigned char *tbuf;

} PROV_RSA_CTX;

static size_t rsa_get_md_size(const PROV_RSA_CTX *prsactx)
{
    if (prsactx->md != NULL)
        return EVP_MD_size(prsactx->md);
    return 0;
}

static int rsa_get_md_nid(const EVP_MD *md)
{
    /*
     * Because the RSA library deals with NIDs, we need to translate.
     * We do so using EVP_MD_is_a(), and therefore need a name to NID
     * map.
     */
    static const OSSL_ITEM name_to_nid[] = {
        { NID_sha1,      OSSL_DIGEST_NAME_SHA1      },
        { NID_sha224,    OSSL_DIGEST_NAME_SHA2_224  },
        { NID_sha256,    OSSL_DIGEST_NAME_SHA2_256  },
        { NID_sha384,    OSSL_DIGEST_NAME_SHA2_384  },
        { NID_sha512,    OSSL_DIGEST_NAME_SHA2_512  },
        { NID_md5,       OSSL_DIGEST_NAME_MD5       },
        { NID_md5_sha1,  OSSL_DIGEST_NAME_MD5_SHA1  },
        { NID_md2,       OSSL_DIGEST_NAME_MD2       },
        { NID_md4,       OSSL_DIGEST_NAME_MD4       },
        { NID_mdc2,      OSSL_DIGEST_NAME_MDC2      },
        { NID_ripemd160, OSSL_DIGEST_NAME_RIPEMD160 },
        { NID_sha3_224,  OSSL_DIGEST_NAME_SHA3_224  },
        { NID_sha3_256,  OSSL_DIGEST_NAME_SHA3_256  },
        { NID_sha3_384,  OSSL_DIGEST_NAME_SHA3_384  },
        { NID_sha3_512,  OSSL_DIGEST_NAME_SHA3_512  },
    };
    size_t i;
    int mdnid = NID_undef;

    if (md == NULL)
        goto end;

    for (i = 0; i < OSSL_NELEM(name_to_nid); i++) {
        if (EVP_MD_is_a(md, name_to_nid[i].ptr)) {
            mdnid = (int)name_to_nid[i].id;
            break;
        }
    }

    if (mdnid == NID_undef)
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);

 end:
    return mdnid;
}

static int rsa_check_padding(int mdnid, int padding)
{
    if (padding == RSA_NO_PADDING) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE);
        return 0;
    }

    if (padding == RSA_X931_PADDING) {
        if (RSA_X931_hash_id(mdnid) == -1) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_X931_DIGEST);
            return 0;
        }
    }

    return 1;
}

static void *rsa_newctx(void *provctx)
{
    PROV_RSA_CTX *prsactx = OPENSSL_zalloc(sizeof(PROV_RSA_CTX));

    if (prsactx == NULL)
        return NULL;

    prsactx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    prsactx->flag_allow_md = 1;
    return prsactx;
}

/* True if PSS parameters are restricted */
#define rsa_pss_restricted(prsactx) (prsactx->min_saltlen != -1)

static int rsa_signature_init(void *vprsactx, void *vrsa)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx == NULL || vrsa == NULL || !RSA_up_ref(vrsa))
        return 0;

    RSA_free(prsactx->rsa);
    prsactx->rsa = vrsa;
    if (RSA_get0_pss_params(prsactx->rsa) != NULL)
        prsactx->pad_mode = RSA_PKCS1_PSS_PADDING;
    else
        prsactx->pad_mode = RSA_PKCS1_PADDING;
    /* Maximum for sign, auto for verify */
    prsactx->saltlen = RSA_PSS_SALTLEN_AUTO;
    prsactx->min_saltlen = -1;

    return 1;
}

static int rsa_setup_md(PROV_RSA_CTX *ctx, const char *mdname,
                        const char *mdprops)
{
    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        int md_nid = rsa_get_md_nid(md);
        WPACKET pkt;

        if (md == NULL
            || md_nid == NID_undef
            || !rsa_check_padding(md_nid, ctx->pad_mode)) {
            EVP_MD_free(md);
            return 0;
        }

        EVP_MD_CTX_free(ctx->mdctx);
        EVP_MD_free(ctx->md);

        /*
         * TODO(3.0) Should we care about DER writing errors?
         * All it really means is that for some reason, there's no
         * AlgorithmIdentifier to be had (consider RSA with MD5-SHA1),
         * but the operation itself is still valid, just as long as it's
         * not used to construct anything that needs an AlgorithmIdentifier.
         */
        ctx->aid_len = 0;
        if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
            && DER_w_algorithmIdentifier_RSA_with(&pkt, -1, ctx->rsa, md_nid)
            && WPACKET_finish(&pkt)) {
            WPACKET_get_total_written(&pkt, &ctx->aid_len);
            ctx->aid = WPACKET_get_curr(&pkt);
        }
        WPACKET_cleanup(&pkt);

        ctx->mdctx = NULL;
        ctx->md = md;
        ctx->mdnid = md_nid;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }

    return 1;
}

static int rsa_setup_mgf1_md(PROV_RSA_CTX *ctx, const char *mdname,
                             const char *props)
{
    if (ctx->mgf1_mdname[0] != '\0')
        EVP_MD_free(ctx->mgf1_md);

    if ((ctx->mgf1_md = EVP_MD_fetch(ctx->libctx, mdname, props)) == NULL)
        return 0;
    OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));

    return 1;
}

static int setup_tbuf(PROV_RSA_CTX *ctx)
{
    if (ctx->tbuf != NULL)
        return 1;
    if ((ctx->tbuf = OPENSSL_malloc(RSA_size(ctx->rsa))) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static void clean_tbuf(PROV_RSA_CTX *ctx)
{
    if (ctx->tbuf != NULL)
        OPENSSL_cleanse(ctx->tbuf, RSA_size(ctx->rsa));
}

static void free_tbuf(PROV_RSA_CTX *ctx)
{
    OPENSSL_clear_free(ctx->tbuf, RSA_size(ctx->rsa));
    ctx->tbuf = NULL;
}

static int rsa_sign(void *vprsactx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    int ret;
    size_t rsasize = RSA_size(prsactx->rsa);
    size_t mdsize = rsa_get_md_size(prsactx);

    if (sig == NULL) {
        *siglen = rsasize;
        return 1;
    }

    if (sigsize < (size_t)rsasize)
        return 0;

    if (mdsize != 0) {
        if (tbslen != mdsize) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH);
            return 0;
        }

#ifndef FIPS_MODE
        if (EVP_MD_is_a(prsactx->md, OSSL_DIGEST_NAME_MDC2)) {
            unsigned int sltmp;

            if (prsactx->pad_mode != RSA_PKCS1_PADDING) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                               "only PKCS#1 padding supported with MDC2");
                return 0;
            }
            ret = RSA_sign_ASN1_OCTET_STRING(0, tbs, tbslen, sig, &sltmp,
                                             prsactx->rsa);

            if (ret <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                return 0;
            }
            ret = sltmp;
            goto end;
        }
#endif
        switch (prsactx->pad_mode) {
        case RSA_X931_PADDING:
            if ((size_t)RSA_size(prsactx->rsa) < tbslen + 1) {
                ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
                return 0;
            }
            if (!setup_tbuf(prsactx)) {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(prsactx->tbuf, tbs, tbslen);
            prsactx->tbuf[tbslen] = RSA_X931_hash_id(prsactx->mdnid);
            ret = RSA_private_encrypt(tbslen + 1, prsactx->tbuf,
                                      sig, prsactx->rsa, RSA_X931_PADDING);
            clean_tbuf(prsactx);
            break;

        case RSA_PKCS1_PADDING:
            {
                unsigned int sltmp;

                ret = RSA_sign(prsactx->mdnid, tbs, tbslen, sig, &sltmp,
                               prsactx->rsa);
                if (ret <= 0) {
                    ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                    return 0;
                }
                ret = sltmp;
            }
            break;

        case RSA_PKCS1_PSS_PADDING:
            /* Check PSS restrictions */
            if (rsa_pss_restricted(prsactx)) {
                switch (prsactx->saltlen) {
                case RSA_PSS_SALTLEN_DIGEST:
                    if (prsactx->min_saltlen > EVP_MD_size(prsactx->md)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL);
                        return 0;
                    }
                    /* FALLTHRU */
                default:
                    if (prsactx->saltlen >= 0
                        && prsactx->saltlen < prsactx->min_saltlen) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL);
                        return 0;
                    }
                    break;
                }
            }
            if (!setup_tbuf(prsactx))
                return 0;
            if (!RSA_padding_add_PKCS1_PSS_mgf1(prsactx->rsa,
                                                prsactx->tbuf, tbs,
                                                prsactx->md, prsactx->mgf1_md,
                                                prsactx->saltlen)) {
                ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                return 0;
            }
            ret = RSA_private_encrypt(RSA_size(prsactx->rsa), prsactx->tbuf,
                                      sig, prsactx->rsa, RSA_NO_PADDING);
            clean_tbuf(prsactx);
            break;

        default:
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           "Only X.931, PKCS#1 v1.5 or PSS padding allowed");
            return 0;
        }
    } else {
        ret = RSA_private_encrypt(tbslen, tbs, sig, prsactx->rsa,
                                  prsactx->pad_mode);
    }

#ifndef FIPS_MODE
 end:
#endif
    if (ret <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
        return 0;
    }

    *siglen = ret;
    return 1;
}

static int rsa_verify_recover(void *vprsactx,
                              unsigned char *rout,
                              size_t *routlen,
                              size_t routsize,
                              const unsigned char *sig,
                              size_t siglen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    int ret;

    if (rout == NULL) {
        *routlen = RSA_size(prsactx->rsa);
        return 1;
    }

    if (prsactx->md != NULL) {
        switch (prsactx->pad_mode) {
        case RSA_X931_PADDING:
            if (!setup_tbuf(prsactx))
                return 0;
            ret = RSA_public_decrypt(siglen, sig, prsactx->tbuf, prsactx->rsa,
                                     RSA_X931_PADDING);
            if (ret < 1) {
                ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                return 0;
            }
            ret--;
            if (prsactx->tbuf[ret] != RSA_X931_hash_id(prsactx->mdnid)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH);
                return 0;
            }
            if (ret != EVP_MD_size(prsactx->md)) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                               "Should be %d, but got %d",
                               EVP_MD_size(prsactx->md), ret);
                return 0;
            }

            *routlen = ret;
            if (routsize < (size_t)ret) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            memcpy(rout, prsactx->tbuf, ret);
            break;

        case RSA_PKCS1_PADDING:
            {
                size_t sltmp;

                ret = int_rsa_verify(prsactx->mdnid, NULL, 0, rout, &sltmp,
                                     sig, siglen, prsactx->rsa);
                if (ret <= 0) {
                    ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                    return 0;
                }
                ret = sltmp;
            }
            break;

        default:
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           "Only X.931 or PKCS#1 v1.5 padding allowed");
            return 0;
        }
    } else {
        ret = RSA_public_decrypt(siglen, sig, rout, prsactx->rsa,
                                 prsactx->pad_mode);
        if (ret < 0) {
            ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
            return 0;
        }
    }
    *routlen = ret;
    return 1;
}

static int rsa_verify(void *vprsactx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    size_t rslen;

    if (prsactx->md != NULL) {
        switch (prsactx->pad_mode) {
        case RSA_PKCS1_PADDING:
            if (!RSA_verify(prsactx->mdnid, tbs, tbslen, sig, siglen,
                            prsactx->rsa)) {
                ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                return 0;
            }
            return 1;
        case RSA_X931_PADDING:
            if (rsa_verify_recover(prsactx, NULL, &rslen, 0, sig, siglen) <= 0)
                return 0;
            break;
        case RSA_PKCS1_PSS_PADDING:
            {
                int ret;
                size_t mdsize;

                /* Check PSS restrictions */
                if (rsa_pss_restricted(prsactx)) {
                    switch (prsactx->saltlen) {
                    case RSA_PSS_SALTLEN_AUTO:
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PSS_SALTLEN);
                        return 0;
                    case RSA_PSS_SALTLEN_DIGEST:
                        if (prsactx->min_saltlen > EVP_MD_size(prsactx->md)) {
                            ERR_raise(ERR_LIB_PROV,
                                      PROV_R_PSS_SALTLEN_TOO_SMALL);
                            return 0;
                        }
                        /* FALLTHRU */
                    default:
                        if (prsactx->saltlen >= 0
                            && prsactx->saltlen < prsactx->min_saltlen) {
                            ERR_raise(ERR_LIB_PROV, PROV_R_PSS_SALTLEN_TOO_SMALL);
                            return 0;
                        }
                        break;
                    }
                }

                /*
                 * We need to check this for the RSA_verify_PKCS1_PSS_mgf1()
                 * call
                 */
                mdsize = rsa_get_md_size(prsactx);
                if (tbslen != mdsize) {
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                                   "Should be %d, but got %d",
                                   mdsize, tbslen);
                    return 0;
                }

                if (!setup_tbuf(prsactx))
                    return 0;
                ret = RSA_public_decrypt(siglen, sig, prsactx->tbuf,
                                         prsactx->rsa, RSA_NO_PADDING);
                if (ret <= 0) {
                    ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                    return 0;
                }
                ret = RSA_verify_PKCS1_PSS_mgf1(prsactx->rsa, tbs,
                                                prsactx->md, prsactx->mgf1_md,
                                                prsactx->tbuf,
                                                prsactx->saltlen);
                if (ret <= 0) {
                    ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
                    return 0;
                }
                return 1;
            }
        default:
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           "Only X.931, PKCS#1 v1.5 or PSS padding allowed");
            return 0;
        }
    } else {
        if (!setup_tbuf(prsactx))
            return 0;
        rslen = RSA_public_decrypt(siglen, sig, prsactx->tbuf, prsactx->rsa,
                                   prsactx->pad_mode);
        if (rslen == 0) {
            ERR_raise(ERR_LIB_PROV, ERR_LIB_RSA);
            return 0;
        }
    }

    if ((rslen != tbslen) || memcmp(tbs, prsactx->tbuf, rslen))
        return 0;

    return 1;
}

static int rsa_digest_signverify_init(void *vprsactx, const char *mdname,
                                      const char *props, void *vrsa)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    prsactx->flag_allow_md = 0;
    if (!rsa_signature_init(vprsactx, vrsa)
        || !rsa_setup_md(prsactx, mdname, props))
        return 0;

    prsactx->mdctx = EVP_MD_CTX_new();
    if (prsactx->mdctx == NULL)
        goto error;

    if (!EVP_DigestInit_ex(prsactx->mdctx, prsactx->md, NULL))
        goto error;

    return 1;

 error:
    EVP_MD_CTX_free(prsactx->mdctx);
    EVP_MD_free(prsactx->md);
    prsactx->mdctx = NULL;
    prsactx->md = NULL;
    return 0;
}

int rsa_digest_signverify_update(void *vprsactx, const unsigned char *data,
                                 size_t datalen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx == NULL || prsactx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(prsactx->mdctx, data, datalen);
}

int rsa_digest_sign_final(void *vprsactx, unsigned char *sig, size_t *siglen,
                          size_t sigsize)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    prsactx->flag_allow_md = 1;
    if (prsactx == NULL || prsactx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to rsa_sign.
     */
    if (sig != NULL) {
        /*
         * TODO(3.0): There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just in RSA.
         */
        if (!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))
            return 0;
    }

    return rsa_sign(vprsactx, sig, siglen, sigsize, digest, (size_t)dlen);
}


int rsa_digest_verify_final(void *vprsactx, const unsigned char *sig,
                            size_t siglen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    prsactx->flag_allow_md = 1;
    if (prsactx == NULL || prsactx->mdctx == NULL)
        return 0;

    /*
     * TODO(3.0): There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just in RSA.
     */
    if (!EVP_DigestFinal_ex(prsactx->mdctx, digest, &dlen))
        return 0;

    return rsa_verify(vprsactx, sig, siglen, digest, (size_t)dlen);
}

static void rsa_freectx(void *vprsactx)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx == NULL)
        return;

    RSA_free(prsactx->rsa);
    EVP_MD_CTX_free(prsactx->mdctx);
    EVP_MD_free(prsactx->md);
    EVP_MD_free(prsactx->mgf1_md);
    free_tbuf(prsactx);

    OPENSSL_clear_free(prsactx, sizeof(prsactx));
}

static void *rsa_dupctx(void *vprsactx)
{
    PROV_RSA_CTX *srcctx = (PROV_RSA_CTX *)vprsactx;
    PROV_RSA_CTX *dstctx;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->rsa = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;
    dstctx->tbuf = NULL;

    if (srcctx->rsa != NULL && !RSA_up_ref(srcctx->rsa))
        goto err;
    dstctx->rsa = srcctx->rsa;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mgf1_md != NULL && !EVP_MD_up_ref(srcctx->mgf1_md))
        goto err;
    dstctx->mgf1_md = srcctx->mgf1_md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    return dstctx;
 err:
    rsa_freectx(dstctx);
    return NULL;
}

static int rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    OSSL_PARAM *p;

    if (prsactx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, prsactx->aid, prsactx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL)
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, prsactx->pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;
                const char *word = NULL;

                for (i = 0; padding_item[i].id != 0; i++) {
                    if (prsactx->pad_mode == (int)padding_item[i].id) {
                        word = padding_item[i].ptr;
                        break;
                    }
                }

                if (word != NULL) {
                    if (!OSSL_PARAM_set_utf8_string(p, word))
                        return 0;
                } else {
                    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                }
            }
            break;
        default:
            return 0;
        }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, prsactx->mdname))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, prsactx->mgf1_mdname))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            if (!OSSL_PARAM_set_int(p, prsactx->saltlen))
                return 0;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            switch (prsactx->saltlen) {
            case RSA_PSS_SALTLEN_DIGEST:
                if (!OSSL_PARAM_set_utf8_string(p, "digest"))
                    return 0;
                break;
            case RSA_PSS_SALTLEN_MAX:
                if (!OSSL_PARAM_set_utf8_string(p, "max"))
                    return 0;
                break;
            case RSA_PSS_SALTLEN_AUTO:
                if (!OSSL_PARAM_set_utf8_string(p, "auto"))
                    return 0;
                break;
            default:
                if (BIO_snprintf(p->data, p->data_size, "%d", prsactx->saltlen)
                    <= 0)
                    return 0;
                break;
            }
        }
    }

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rsa_gettable_ctx_params(void)
{
    return known_gettable_ctx_params;
}

static int rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    const OSSL_PARAM *p;

    if (prsactx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    /* Not allowed during certain operations */
    if (p != NULL && !prsactx->flag_allow_md)
        return 0;
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;

        /* TODO(3.0) PSS check needs more work */
        if (rsa_pss_restricted(prsactx)) {
            /* TODO(3.0) figure out what to do for prsactx->md == NULL */
            if (prsactx->md == NULL || EVP_MD_is_a(prsactx->md, mdname))
                return 1;
            ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
            return 0;
        }

        /* non-PSS code follows */
        if (!rsa_setup_md(prsactx, mdname, mdprops))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        int pad_mode = 0;

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            {
                int i;

                if (p->data == NULL)
                    return 0;

                for (i = 0; padding_item[i].id != 0; i++) {
                    if (strcmp(p->data, padding_item[i].ptr) == 0) {
                        pad_mode = padding_item[i].id;
                        break;
                    }
                }
            }
            break;
        default:
            return 0;
        }

        switch (pad_mode) {
        case RSA_PKCS1_OAEP_PADDING:
            /*
             * OAEP padding is for asymmetric cipher only so is not compatible
             * with signature use.
             */
            ERR_raise_data(ERR_LIB_PROV,
                           PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE,
                           "OAEP padding not allowed for signing / verifying");
            return 0;
        case RSA_PKCS1_PSS_PADDING:
            if (prsactx->mdname[0] == '\0')
                rsa_setup_md(prsactx, "SHA1", "");
            goto cont;
        case RSA_PKCS1_PADDING:
        case RSA_SSLV23_PADDING:
        case RSA_NO_PADDING:
        case RSA_X931_PADDING:
            if (RSA_get0_pss_params(prsactx->rsa) != NULL) {
                ERR_raise_data(ERR_LIB_PROV,
                               PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE,
                               "X.931 padding not allowed with RSA-PSS");
                return 0;
            }
        cont:
            if (!rsa_check_padding(prsactx->mdnid, pad_mode))
                return 0;
            break;
        default:
            return 0;
        }
        prsactx->pad_mode = pad_mode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        int saltlen;

        if (prsactx->pad_mode != RSA_PKCS1_PSS_PADDING) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "PSS saltlen can only be specified if "
                           "PSS padding has been specified first");
            return 0;
        }

        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
            if (!OSSL_PARAM_get_int(p, &saltlen))
                return 0;
            break;
        case OSSL_PARAM_UTF8_STRING:
            if (strcmp(p->data, "digest") == 0)
                saltlen = RSA_PSS_SALTLEN_DIGEST;
            else if (strcmp(p->data, "max") == 0)
                saltlen = RSA_PSS_SALTLEN_MAX;
            else if (strcmp(p->data, "auto") == 0)
                saltlen = RSA_PSS_SALTLEN_AUTO;
            else
                saltlen = atoi(p->data);
            break;
        default:
            return 0;
        }

        /*
         * RSA_PSS_SALTLEN_MAX seems curiously named in this check.
         * Contrary to what it's name suggests, it's the currently
         * lowest saltlen number possible.
         */
        if (saltlen < RSA_PSS_SALTLEN_MAX) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PSS_SALTLEN);
            return 0;
        }

        prsactx->saltlen = saltlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;

        if (prsactx->pad_mode != RSA_PKCS1_PSS_PADDING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
            return  0;
        }

        /* TODO(3.0) PSS check needs more work */
        if (rsa_pss_restricted(prsactx)) {
            /* TODO(3.0) figure out what to do for prsactx->md == NULL */
            if (prsactx->mgf1_md == NULL
                || EVP_MD_is_a(prsactx->mgf1_md, mdname))
                return 1;
            ERR_raise(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED);
            return 0;
        }

        /* non-PSS code follows */
        if (!rsa_setup_mgf1_md(prsactx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rsa_settable_ctx_params(void)
{
    /*
     * TODO(3.0): Should this function return a different set of settable ctx
     * params if the ctx is being used for a DigestSign/DigestVerify? In that
     * case it is not allowed to set the digest size/digest name because the
     * digest is explicitly set as part of the init.
     */
    return known_settable_ctx_params;
}

static int rsa_get_ctx_md_params(void *vprsactx, OSSL_PARAM *params)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(prsactx->mdctx, params);
}

static const OSSL_PARAM *rsa_gettable_ctx_md_params(void *vprsactx)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(prsactx->md);
}

static int rsa_set_ctx_md_params(void *vprsactx, const OSSL_PARAM params[])
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(prsactx->mdctx, params);
}

static const OSSL_PARAM *rsa_settable_ctx_md_params(void *vprsactx)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(prsactx->md);
}

const OSSL_DISPATCH rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))rsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))rsa_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))rsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))rsa_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))rsa_verify },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, (void (*)(void))rsa_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, (void (*)(void))rsa_verify_recover },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))rsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))rsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))rsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))rsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))rsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))rsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))rsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))rsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))rsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))rsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))rsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))rsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))rsa_settable_ctx_md_params },
    { 0, NULL }
};
