/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/crypto.h>
#include <opentls/evp.h>
#include <opentls/core_numbers.h>
#include <opentls/core_names.h>
#include <opentls/rsa.h>
#include <opentls/params.h>
#include <opentls/err.h>
/* Just for tls_MAX_MASTER_KEY_LENGTH */
#include <opentls/tls.h>
#include "internal/constant_time.h"
#include "crypto/rsa.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "prov/implementations.h"

#include <stdlib.h>

static Otls_OP_asym_cipher_newctx_fn rsa_newctx;
static Otls_OP_asym_cipher_encrypt_init_fn rsa_init;
static Otls_OP_asym_cipher_encrypt_fn rsa_encrypt;
static Otls_OP_asym_cipher_decrypt_init_fn rsa_init;
static Otls_OP_asym_cipher_decrypt_fn rsa_decrypt;
static Otls_OP_asym_cipher_freectx_fn rsa_freectx;
static Otls_OP_asym_cipher_dupctx_fn rsa_dupctx;
static Otls_OP_asym_cipher_get_ctx_params_fn rsa_get_ctx_params;
static Otls_OP_asym_cipher_gettable_ctx_params_fn rsa_gettable_ctx_params;
static Otls_OP_asym_cipher_set_ctx_params_fn rsa_set_ctx_params;
static Otls_OP_asym_cipher_settable_ctx_params_fn rsa_settable_ctx_params;


/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes RSA structures, so
 * we use that here too.
 */

typedef struct {
    OPENtls_CTX *libctx;
    RSA *rsa;
    int pad_mode;
    /* OAEP message digest */
    EVP_MD *oaep_md;
    /* message digest for MGF1 */
    EVP_MD *mgf1_md;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
    /* TLS padding */
    unsigned int client_version;
    unsigned int alt_version;
} PROV_RSA_CTX;

static void *rsa_newctx(void *provctx)
{
    PROV_RSA_CTX *prsactx =  OPENtls_zalloc(sizeof(PROV_RSA_CTX));

    if (prsactx == NULL)
        return NULL;
    prsactx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);

    return prsactx;
}

static int rsa_init(void *vprsactx, void *vrsa)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    if (prsactx == NULL || vrsa == NULL || !RSA_up_ref(vrsa))
        return 0;
    RSA_free(prsactx->rsa);
    prsactx->rsa = vrsa;
    prsactx->pad_mode = RSA_PKCS1_PADDING;
    return 1;
}

static int rsa_encrypt(void *vprsactx, unsigned char *out, size_t *outlen,
                       size_t outsize, const unsigned char *in, size_t inlen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    int ret;

    if (out == NULL) {
        size_t len = RSA_size(prsactx->rsa);

        if (len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }
        *outlen = len;
        return 1;
    }

    if (prsactx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
        int rsasize = RSA_size(prsactx->rsa);
        unsigned char *tbuf;

        if ((tbuf = OPENtls_malloc(rsasize)) == NULL) {
            PROVerr(0, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        ret = RSA_padding_add_PKCS1_OAEP_mgf1(tbuf, rsasize, in, inlen,
                                              prsactx->oaep_label,
                                              prsactx->oaep_labellen,
                                              prsactx->oaep_md,
                                              prsactx->mgf1_md);

        if (!ret) {
            OPENtls_free(tbuf);
            return 0;
        }
        ret = RSA_public_encrypt(rsasize, tbuf, out, prsactx->rsa,
                                 RSA_NO_PADDING);
        OPENtls_free(tbuf);
    } else {
        ret = RSA_public_encrypt(inlen, in, out, prsactx->rsa,
                                 prsactx->pad_mode);
    }
    /* A ret value of 0 is not an error */
    if (ret < 0)
        return ret;
    *outlen = ret;
    return 1;
}

static int rsa_decrypt(void *vprsactx, unsigned char *out, size_t *outlen,
                       size_t outsize, const unsigned char *in, size_t inlen)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    int ret;
    size_t len = RSA_size(prsactx->rsa);

    if (prsactx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING) {
        if (out == NULL) {
            *outlen = tls_MAX_MASTER_KEY_LENGTH;
            return 1;
        }
        if (outsize < tls_MAX_MASTER_KEY_LENGTH) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return 0;
        }
    } else {
        if (out == NULL) {
            if (len == 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return 0;
            }
            *outlen = len;
            return 1;
        }

        if (outsize < len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return 0;
        }
    }

    if (prsactx->pad_mode == RSA_PKCS1_OAEP_PADDING
            || prsactx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING) {
        unsigned char *tbuf;

        if ((tbuf = OPENtls_malloc(len)) == NULL) {
            PROVerr(0, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        ret = RSA_private_decrypt(inlen, in, tbuf, prsactx->rsa,
                                  RSA_NO_PADDING);
        /*
         * With no padding then, on success ret should be len, otherwise an
         * error occurred (non-constant time)
         */
        if (ret != (int)len) {
            OPENtls_free(tbuf);
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
            return 0;
        }
        if (prsactx->pad_mode == RSA_PKCS1_OAEP_PADDING) {
            ret = RSA_padding_check_PKCS1_OAEP_mgf1(out, outsize, tbuf,
                                                    len, len,
                                                    prsactx->oaep_label,
                                                    prsactx->oaep_labellen,
                                                    prsactx->oaep_md,
                                                    prsactx->mgf1_md);
        } else {
            /* RSA_PKCS1_WITH_TLS_PADDING */
            if (prsactx->client_version <= 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_TLS_CLIENT_VERSION);
                return 0;
            }
            ret = rsa_padding_check_PKCS1_type_2_TLS(out, outsize,
                                                     tbuf, len,
                                                     prsactx->client_version,
                                                     prsactx->alt_version);
        }
        OPENtls_free(tbuf);
    } else {
        ret = RSA_private_decrypt(inlen, in, out, prsactx->rsa,
                                  prsactx->pad_mode);
    }
    *outlen = constant_time_select_s(constant_time_msb_s(ret), *outlen, ret);
    ret = constant_time_select_int(constant_time_msb(ret), 0, 1);
    return ret;
}

static void rsa_freectx(void *vprsactx)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;

    RSA_free(prsactx->rsa);

    EVP_MD_free(prsactx->oaep_md);
    EVP_MD_free(prsactx->mgf1_md);

    OPENtls_free(prsactx);
}

static void *rsa_dupctx(void *vprsactx)
{
    PROV_RSA_CTX *srcctx = (PROV_RSA_CTX *)vprsactx;
    PROV_RSA_CTX *dstctx;

    dstctx = OPENtls_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->rsa != NULL && !RSA_up_ref(dstctx->rsa)) {
        OPENtls_free(dstctx);
        return NULL;
    }

    if (dstctx->oaep_md != NULL && !EVP_MD_up_ref(dstctx->oaep_md)) {
        RSA_free(dstctx->rsa);
        OPENtls_free(dstctx);
        return NULL;
    }

    if (dstctx->mgf1_md != NULL && !EVP_MD_up_ref(dstctx->mgf1_md)) {
        RSA_free(dstctx->rsa);
        EVP_MD_free(dstctx->oaep_md);
        OPENtls_free(dstctx);
        return NULL;
    }

    return dstctx;
}

static int rsa_get_ctx_params(void *vprsactx, Otls_PARAM *params)
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    Otls_PARAM *p;

    if (prsactx == NULL || params == NULL)
        return 0;

    p = Otls_PARAM_locate(params, Otls_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL && !Otls_PARAM_set_int(p, prsactx->pad_mode))
        return 0;

    p = Otls_PARAM_locate(params, Otls_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL && !Otls_PARAM_set_utf8_string(p, prsactx->oaep_md == NULL
                                                    ? ""
                                                    : EVP_MD_name(prsactx->oaep_md)))
        return 0;

    p = Otls_PARAM_locate(params, Otls_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        EVP_MD *mgf1_md = prsactx->mgf1_md == NULL ? prsactx->oaep_md
                                                   : prsactx->mgf1_md;

        if (!Otls_PARAM_set_utf8_string(p, mgf1_md == NULL
                                           ? ""
                                           : EVP_MD_name(mgf1_md)))
        return 0;
    }

    p = Otls_PARAM_locate(params, Otls_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL && !Otls_PARAM_set_octet_ptr(p, prsactx->oaep_label, 0))
        return 0;

    p = Otls_PARAM_locate(params, Otls_ASYM_CIPHER_PARAM_OAEP_LABEL_LEN);
    if (p != NULL && !Otls_PARAM_set_size_t(p, prsactx->oaep_labellen))
        return 0;

    p = Otls_PARAM_locate(params, Otls_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL && !Otls_PARAM_set_uint(p, prsactx->client_version))
        return 0;

    p = Otls_PARAM_locate(params, Otls_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL && !Otls_PARAM_set_uint(p, prsactx->alt_version))
        return 0;

    return 1;
}

static const Otls_PARAM known_gettable_ctx_params[] = {
    Otls_PARAM_utf8_string(Otls_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    Otls_PARAM_int(Otls_ASYM_CIPHER_PARAM_PAD_MODE, NULL),
    Otls_PARAM_utf8_string(Otls_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    Otls_PARAM_DEFN(Otls_ASYM_CIPHER_PARAM_OAEP_LABEL, Otls_PARAM_OCTET_PTR,
                    NULL, 0),
    Otls_PARAM_size_t(Otls_ASYM_CIPHER_PARAM_OAEP_LABEL_LEN, NULL),
    Otls_PARAM_uint(Otls_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    Otls_PARAM_uint(Otls_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    Otls_PARAM_END
};

static const Otls_PARAM *rsa_gettable_ctx_params(void)
{
    return known_gettable_ctx_params;
}

static int rsa_set_ctx_params(void *vprsactx, const Otls_PARAM params[])
{
    PROV_RSA_CTX *prsactx = (PROV_RSA_CTX *)vprsactx;
    const Otls_PARAM *p;
    /* Should be big enough */
    char mdname[80], mdprops[80] = { '\0' };
    char *str = mdname;
    int pad_mode;

    if (prsactx == NULL || params == NULL)
        return 0;

    p = Otls_PARAM_locate_const(params, Otls_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL) {
        if (!Otls_PARAM_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        str = mdprops;
        p = Otls_PARAM_locate_const(params,
                                    Otls_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
        if (p != NULL) {
            if (!Otls_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        }

        EVP_MD_free(prsactx->oaep_md);
        prsactx->oaep_md = EVP_MD_fetch(prsactx->libctx, mdname, mdprops);

        if (prsactx->oaep_md == NULL)
            return 0;
    }

    p = Otls_PARAM_locate_const(params, Otls_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        if (!Otls_PARAM_get_int(p, &pad_mode))
            return 0;
        /*
         * PSS padding is for signatures only so is not compatible with
         * asymmetric cipher use.
         */
        if (pad_mode == RSA_PKCS1_PSS_PADDING)
            return 0;
        if (pad_mode == RSA_PKCS1_OAEP_PADDING && prsactx->oaep_md == NULL) {
            prsactx->oaep_md = EVP_MD_fetch(prsactx->libctx, "SHA1", mdprops);
            if (prsactx->oaep_md == NULL)
                return 0;
        }
        prsactx->pad_mode = pad_mode;
    }

    p = Otls_PARAM_locate_const(params, Otls_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        if (!Otls_PARAM_get_utf8_string(p, &str, sizeof(mdname)))
            return 0;

        str = mdprops;
        p = Otls_PARAM_locate_const(params,
                                    Otls_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
        if (p != NULL) {
            if (!Otls_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return 0;
        } else {
            str = NULL;
        }

        EVP_MD_free(prsactx->mgf1_md);
        prsactx->mgf1_md = EVP_MD_fetch(prsactx->libctx, mdname, str);

        if (prsactx->mgf1_md == NULL)
            return 0;
    }

    p = Otls_PARAM_locate_const(params, Otls_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL) {
        void *tmp_label = NULL;
        size_t tmp_labellen;

        if (!Otls_PARAM_get_octet_string(p, &tmp_label, 0, &tmp_labellen))
            return 0;
        OPENtls_free(prsactx->oaep_label);
        prsactx->oaep_label = (unsigned char *)tmp_label;
        prsactx->oaep_labellen = tmp_labellen;
    }

    p = Otls_PARAM_locate_const(params, Otls_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL) {
        unsigned int client_version;

        if (!Otls_PARAM_get_uint(p, &client_version))
            return 0;
        prsactx->client_version = client_version;
    }

    p = Otls_PARAM_locate_const(params, Otls_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL) {
        unsigned int alt_version;

        if (!Otls_PARAM_get_uint(p, &alt_version))
            return 0;
        prsactx->alt_version = alt_version;
    }

    return 1;
}

static const Otls_PARAM known_settable_ctx_params[] = {
    Otls_PARAM_utf8_string(Otls_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    Otls_PARAM_int(Otls_ASYM_CIPHER_PARAM_PAD_MODE, NULL),
    Otls_PARAM_utf8_string(Otls_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    Otls_PARAM_utf8_string(Otls_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
    Otls_PARAM_octet_string(Otls_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    Otls_PARAM_uint(Otls_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    Otls_PARAM_uint(Otls_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    Otls_PARAM_END
};

static const Otls_PARAM *rsa_settable_ctx_params(void)
{
    return known_settable_ctx_params;
}

const Otls_DISPATCH rsa_asym_cipher_functions[] = {
    { Otls_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))rsa_newctx },
    { Otls_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))rsa_init },
    { Otls_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))rsa_encrypt },
    { Otls_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))rsa_init },
    { Otls_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))rsa_decrypt },
    { Otls_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))rsa_freectx },
    { Otls_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))rsa_dupctx },
    { Otls_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))rsa_get_ctx_params },
    { Otls_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))rsa_gettable_ctx_params },
    { Otls_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))rsa_set_ctx_params },
    { Otls_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))rsa_settable_ctx_params },
    { 0, NULL }
};
