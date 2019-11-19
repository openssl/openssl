/*
 * Copyright 2006-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "ec_local.h"
#include "curve448/curve448_local.h"

#define X25519_BITS          253
#define X25519_SECURITY_BITS 128

#define ED25519_KEYLEN       32
#define ED25519_SIGSIZE      64

#define X448_BITS            448
#define ED448_BITS           456
#define X448_SECURITY_BITS   224

#define ED448_SIGSIZE        114

#define ISX448(id)      ((id) == EVP_PKEY_X448)
#define IS25519(id)     ((id) == EVP_PKEY_X25519 || (id) == EVP_PKEY_ED25519)
#define KEYLENID(id)    (IS25519(id) ? X25519_KEYLEN \
                                     : ((id) == EVP_PKEY_X448 ? X448_KEYLEN \
                                                              : ED448_KEYLEN))
#define KEYLEN(p)       KEYLENID((p)->ameth->pkey_id)


typedef enum {
    KEY_OP_PUBLIC,
    KEY_OP_PRIVATE,
    KEY_OP_KEYGEN
} ecx_key_op_t;

/* Setup EVP_PKEY using public, private or generation */
static int ecx_key_op(EVP_PKEY *pkey, int id, const X509_ALGOR *palg,
                      const unsigned char *p, int plen, ecx_key_op_t op)
{
    ECX_KEY *key = NULL;
    unsigned char *privkey, *pubkey;

    if (op != KEY_OP_KEYGEN) {
        if (palg != NULL) {
            int ptype;

            /* Algorithm parameters must be absent */
            X509_ALGOR_get0(NULL, &ptype, NULL, palg);
            if (ptype != V_ASN1_UNDEF) {
                ECerr(EC_F_ECX_KEY_OP, EC_R_INVALID_ENCODING);
                return 0;
            }
        }

        if (p == NULL || plen != KEYLENID(id)) {
            ECerr(EC_F_ECX_KEY_OP, EC_R_INVALID_ENCODING);
            return 0;
        }
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ECerr(EC_F_ECX_KEY_OP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    pubkey = key->pubkey;

    if (op == KEY_OP_PUBLIC) {
        memcpy(pubkey, p, plen);
    } else {
        privkey = key->privkey = OPENSSL_secure_malloc(KEYLENID(id));
        if (privkey == NULL) {
            ECerr(EC_F_ECX_KEY_OP, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (op == KEY_OP_KEYGEN) {
            if (RAND_priv_bytes(privkey, KEYLENID(id)) <= 0) {
                OPENSSL_secure_free(privkey);
                key->privkey = NULL;
                goto err;
            }
            if (id == EVP_PKEY_X25519) {
                privkey[0] &= 248;
                privkey[X25519_KEYLEN - 1] &= 127;
                privkey[X25519_KEYLEN - 1] |= 64;
            } else if (id == EVP_PKEY_X448) {
                privkey[0] &= 252;
                privkey[X448_KEYLEN - 1] |= 128;
            }
        } else {
            memcpy(privkey, p, KEYLENID(id));
        }
        switch (id) {
        case EVP_PKEY_X25519:
            X25519_public_from_private(pubkey, privkey);
            break;
        case EVP_PKEY_ED25519:
            ED25519_public_from_private(pubkey, privkey);
            break;
        case EVP_PKEY_X448:
            X448_public_from_private(pubkey, privkey);
            break;
        case EVP_PKEY_ED448:
            ED448_public_from_private(pubkey, privkey);
            break;
        }
    }

    EVP_PKEY_assign(pkey, id, key);
    return 1;
 err:
    OPENSSL_free(key);
    return 0;
}

static int ecx_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    const ECX_KEY *ecxkey = pkey->pkey.ecx;
    unsigned char *penc;

    if (ecxkey == NULL) {
        ECerr(EC_F_ECX_PUB_ENCODE, EC_R_INVALID_KEY);
        return 0;
    }

    penc = OPENSSL_memdup(ecxkey->pubkey, KEYLEN(pkey));
    if (penc == NULL) {
        ECerr(EC_F_ECX_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                                V_ASN1_UNDEF, NULL, penc, KEYLEN(pkey))) {
        OPENSSL_free(penc);
        ECerr(EC_F_ECX_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static int ecx_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *palg;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    return ecx_key_op(pkey, pkey->ameth->pkey_id, palg, p, pklen,
                      KEY_OP_PUBLIC);
}

static int ecx_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const ECX_KEY *akey = a->pkey.ecx;
    const ECX_KEY *bkey = b->pkey.ecx;

    if (akey == NULL || bkey == NULL)
        return -2;

    return CRYPTO_memcmp(akey->pubkey, bkey->pubkey, KEYLEN(a)) == 0;
}

static int ecx_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    int rv;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8))
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    rv = ecx_key_op(pkey, pkey->ameth->pkey_id, palg, p, plen, KEY_OP_PRIVATE);
    ASN1_STRING_clear_free(oct);
    return rv;
}

static int ecx_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    const ECX_KEY *ecxkey = pkey->pkey.ecx;
    ASN1_OCTET_STRING oct;
    unsigned char *penc = NULL;
    int penclen;

    if (ecxkey == NULL || ecxkey->privkey == NULL) {
        ECerr(EC_F_ECX_PRIV_ENCODE, EC_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    oct.data = ecxkey->privkey;
    oct.length = KEYLEN(pkey);
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
        ECerr(EC_F_ECX_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_clear_free(penc, penclen);
        ECerr(EC_F_ECX_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

static int ecx_size(const EVP_PKEY *pkey)
{
    return KEYLEN(pkey);
}

static int ecx_bits(const EVP_PKEY *pkey)
{
    if (IS25519(pkey->ameth->pkey_id)) {
        return X25519_BITS;
    } else if(ISX448(pkey->ameth->pkey_id)) {
        return X448_BITS;
    } else {
        return ED448_BITS;
    }
}

static int ecx_security_bits(const EVP_PKEY *pkey)
{
    if (IS25519(pkey->ameth->pkey_id)) {
        return X25519_SECURITY_BITS;
    } else {
        return X448_SECURITY_BITS;
    }
}

static void ecx_free(EVP_PKEY *pkey)
{
    if (pkey->pkey.ecx != NULL)
        OPENSSL_secure_clear_free(pkey->pkey.ecx->privkey, KEYLEN(pkey));
    OPENSSL_free(pkey->pkey.ecx);
}

/* "parameters" are always equal */
static int ecx_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}

static int ecx_key_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx, ecx_key_op_t op)
{
    const ECX_KEY *ecxkey = pkey->pkey.ecx;
    const char *nm = OBJ_nid2ln(pkey->ameth->pkey_id);

    if (op == KEY_OP_PRIVATE) {
        if (ecxkey == NULL || ecxkey->privkey == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nm) <= 0)
            return 0;
        if (BIO_printf(bp, "%*spriv:\n", indent, "") <= 0)
            return 0;
        if (ASN1_buf_print(bp, ecxkey->privkey, KEYLEN(pkey),
                           indent + 4) == 0)
            return 0;
    } else {
        if (ecxkey == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Public-Key:\n", indent, "", nm) <= 0)
            return 0;
    }
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        return 0;

    if (ASN1_buf_print(bp, ecxkey->pubkey, KEYLEN(pkey),
                       indent + 4) == 0)
        return 0;
    return 1;
}

static int ecx_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return ecx_key_print(bp, pkey, indent, ctx, KEY_OP_PRIVATE);
}

static int ecx_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
    return ecx_key_print(bp, pkey, indent, ctx, KEY_OP_PUBLIC);
}

static int ecx_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {

    case ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
        return ecx_key_op(pkey, pkey->ameth->pkey_id, NULL, arg2, arg1,
                          KEY_OP_PUBLIC);

    case ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
        if (pkey->pkey.ecx != NULL) {
            unsigned char **ppt = arg2;

            *ppt = OPENSSL_memdup(pkey->pkey.ecx->pubkey, KEYLEN(pkey));
            if (*ppt != NULL)
                return KEYLEN(pkey);
        }
        return 0;

    default:
        return -2;

    }
}

static int ecd_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        /* We currently only support Pure EdDSA which takes no digest */
        *(int *)arg2 = NID_undef;
        return 2;

    default:
        return -2;

    }
}

static int ecx_set_priv_key(EVP_PKEY *pkey, const unsigned char *priv,
                            size_t len)
{
    return ecx_key_op(pkey, pkey->ameth->pkey_id, NULL, priv, len,
                       KEY_OP_PRIVATE);
}

static int ecx_set_pub_key(EVP_PKEY *pkey, const unsigned char *pub, size_t len)
{
    return ecx_key_op(pkey, pkey->ameth->pkey_id, NULL, pub, len,
                      KEY_OP_PUBLIC);
}

static int ecx_get_priv_key(const EVP_PKEY *pkey, unsigned char *priv,
                            size_t *len)
{
    const ECX_KEY *key = pkey->pkey.ecx;

    if (priv == NULL) {
        *len = KEYLENID(pkey->ameth->pkey_id);
        return 1;
    }

    if (key == NULL
            || key->privkey == NULL
            || *len < (size_t)KEYLENID(pkey->ameth->pkey_id))
        return 0;

    *len = KEYLENID(pkey->ameth->pkey_id);
    memcpy(priv, key->privkey, *len);

    return 1;
}

static int ecx_get_pub_key(const EVP_PKEY *pkey, unsigned char *pub,
                           size_t *len)
{
    const ECX_KEY *key = pkey->pkey.ecx;

    if (pub == NULL) {
        *len = KEYLENID(pkey->ameth->pkey_id);
        return 1;
    }

    if (key == NULL
            || *len < (size_t)KEYLENID(pkey->ameth->pkey_id))
        return 0;

    *len = KEYLENID(pkey->ameth->pkey_id);
    memcpy(pub, key->pubkey, *len);

    return 1;
}

const EVP_PKEY_ASN1_METHOD ecx25519_asn1_meth = {
    EVP_PKEY_X25519,
    EVP_PKEY_X25519,
    0,
    "X25519",
    "OpenSSL X25519 algorithm",

    ecx_pub_decode,
    ecx_pub_encode,
    ecx_pub_cmp,
    ecx_pub_print,

    ecx_priv_decode,
    ecx_priv_encode,
    ecx_priv_print,

    ecx_size,
    ecx_bits,
    ecx_security_bits,

    0, 0, 0, 0,
    ecx_cmp_parameters,
    0, 0,

    ecx_free,
    ecx_ctrl,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    ecx_set_priv_key,
    ecx_set_pub_key,
    ecx_get_priv_key,
    ecx_get_pub_key,
};

const EVP_PKEY_ASN1_METHOD ecx448_asn1_meth = {
    EVP_PKEY_X448,
    EVP_PKEY_X448,
    0,
    "X448",
    "OpenSSL X448 algorithm",

    ecx_pub_decode,
    ecx_pub_encode,
    ecx_pub_cmp,
    ecx_pub_print,

    ecx_priv_decode,
    ecx_priv_encode,
    ecx_priv_print,

    ecx_size,
    ecx_bits,
    ecx_security_bits,

    0, 0, 0, 0,
    ecx_cmp_parameters,
    0, 0,

    ecx_free,
    ecx_ctrl,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,

    ecx_set_priv_key,
    ecx_set_pub_key,
    ecx_get_priv_key,
    ecx_get_pub_key,
};

static int ecd_size25519(const EVP_PKEY *pkey)
{
    return ED25519_SIGSIZE;
}

static int ecd_size448(const EVP_PKEY *pkey)
{
    return ED448_SIGSIZE;
}

static int ecd_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                           X509_ALGOR *sigalg, ASN1_BIT_STRING *str,
                           EVP_PKEY *pkey)
{
    const ASN1_OBJECT *obj;
    int ptype;
    int nid;

    /* Sanity check: make sure it is ED25519/ED448 with absent parameters */
    X509_ALGOR_get0(&obj, &ptype, NULL, sigalg);
    nid = OBJ_obj2nid(obj);
    if ((nid != NID_ED25519 && nid != NID_ED448) || ptype != V_ASN1_UNDEF) {
        ECerr(EC_F_ECD_ITEM_VERIFY, EC_R_INVALID_ENCODING);
        return 0;
    }

    if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
        return 0;

    return 2;
}

static int ecd_item_sign25519(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                              X509_ALGOR *alg1, X509_ALGOR *alg2,
                              ASN1_BIT_STRING *str)
{
    /* Set algorithms identifiers */
    X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_ED25519), V_ASN1_UNDEF, NULL);
    if (alg2)
        X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_ED25519), V_ASN1_UNDEF, NULL);
    /* Algorithm identifiers set: carry on as normal */
    return 3;
}

static int ecd_sig_info_set25519(X509_SIG_INFO *siginf, const X509_ALGOR *alg,
                                 const ASN1_STRING *sig)
{
    X509_SIG_INFO_set(siginf, NID_undef, NID_ED25519, X25519_SECURITY_BITS,
                      X509_SIG_INFO_TLS);
    return 1;
}

static int ecd_item_sign448(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                            X509_ALGOR *alg1, X509_ALGOR *alg2,
                            ASN1_BIT_STRING *str)
{
    /* Set algorithm identifier */
    X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_ED448), V_ASN1_UNDEF, NULL);
    if (alg2 != NULL)
        X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_ED448), V_ASN1_UNDEF, NULL);
    /* Algorithm identifier set: carry on as normal */
    return 3;
}

static int ecd_sig_info_set448(X509_SIG_INFO *siginf, const X509_ALGOR *alg,
                               const ASN1_STRING *sig)
{
    X509_SIG_INFO_set(siginf, NID_undef, NID_ED448, X448_SECURITY_BITS,
                      X509_SIG_INFO_TLS);
    return 1;
}


const EVP_PKEY_ASN1_METHOD ed25519_asn1_meth = {
    EVP_PKEY_ED25519,
    EVP_PKEY_ED25519,
    0,
    "ED25519",
    "OpenSSL ED25519 algorithm",

    ecx_pub_decode,
    ecx_pub_encode,
    ecx_pub_cmp,
    ecx_pub_print,

    ecx_priv_decode,
    ecx_priv_encode,
    ecx_priv_print,

    ecd_size25519,
    ecx_bits,
    ecx_security_bits,

    0, 0, 0, 0,
    ecx_cmp_parameters,
    0, 0,

    ecx_free,
    ecd_ctrl,
    NULL,
    NULL,
    ecd_item_verify,
    ecd_item_sign25519,
    ecd_sig_info_set25519,

    NULL,
    NULL,
    NULL,

    ecx_set_priv_key,
    ecx_set_pub_key,
    ecx_get_priv_key,
    ecx_get_pub_key,
};

const EVP_PKEY_ASN1_METHOD ed448_asn1_meth = {
    EVP_PKEY_ED448,
    EVP_PKEY_ED448,
    0,
    "ED448",
    "OpenSSL ED448 algorithm",

    ecx_pub_decode,
    ecx_pub_encode,
    ecx_pub_cmp,
    ecx_pub_print,

    ecx_priv_decode,
    ecx_priv_encode,
    ecx_priv_print,

    ecd_size448,
    ecx_bits,
    ecx_security_bits,

    0, 0, 0, 0,
    ecx_cmp_parameters,
    0, 0,

    ecx_free,
    ecd_ctrl,
    NULL,
    NULL,
    ecd_item_verify,
    ecd_item_sign448,
    ecd_sig_info_set448,

    NULL,
    NULL,
    NULL,

    ecx_set_priv_key,
    ecx_set_pub_key,
    ecx_get_priv_key,
    ecx_get_pub_key,
};

static int pkey_ecx_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    return ecx_key_op(pkey, ctx->pmeth->pkey_id, NULL, NULL, 0, KEY_OP_KEYGEN);
}

static int validate_ecx_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                                          size_t *keylen,
                                          const unsigned char **privkey,
                                          const unsigned char **pubkey)
{
    const ECX_KEY *ecxkey, *peerkey;

    if (ctx->pkey == NULL || ctx->peerkey == NULL) {
        ECerr(EC_F_VALIDATE_ECX_DERIVE, EC_R_KEYS_NOT_SET);
        return 0;
    }
    ecxkey = ctx->pkey->pkey.ecx;
    peerkey = ctx->peerkey->pkey.ecx;
    if (ecxkey == NULL || ecxkey->privkey == NULL) {
        ECerr(EC_F_VALIDATE_ECX_DERIVE, EC_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    if (peerkey == NULL) {
        ECerr(EC_F_VALIDATE_ECX_DERIVE, EC_R_INVALID_PEER_KEY);
        return 0;
    }
    *privkey = ecxkey->privkey;
    *pubkey = peerkey->pubkey;

    return 1;
}

static int pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key,
                                size_t *keylen)
{
    const unsigned char *privkey, *pubkey;

    if (!validate_ecx_derive(ctx, key, keylen, &privkey, &pubkey)
            || (key != NULL
                && X25519(key, privkey, pubkey) == 0))
        return 0;
    *keylen = X25519_KEYLEN;
    return 1;
}

static int pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key,
                              size_t *keylen)
{
    const unsigned char *privkey, *pubkey;

    if (!validate_ecx_derive(ctx, key, keylen, &privkey, &pubkey)
            || (key != NULL
                && X448(key, privkey, pubkey) == 0))
        return 0;
    *keylen = X448_KEYLEN;
    return 1;
}

static int pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    /* Only need to handle peer key for derivation */
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;
    return -2;
}

const EVP_PKEY_METHOD ecx25519_pkey_meth = {
    EVP_PKEY_X25519,
    0, 0, 0, 0, 0, 0, 0,
    pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    pkey_ecx_derive25519,
    pkey_ecx_ctrl,
    0
};

const EVP_PKEY_METHOD ecx448_pkey_meth = {
    EVP_PKEY_X448,
    0, 0, 0, 0, 0, 0, 0,
    pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    pkey_ecx_derive448,
    pkey_ecx_ctrl,
    0
};

static int pkey_ecd_digestsign25519(EVP_MD_CTX *ctx, unsigned char *sig,
                                    size_t *siglen, const unsigned char *tbs,
                                    size_t tbslen)
{
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;

    if (sig == NULL) {
        *siglen = ED25519_SIGSIZE;
        return 1;
    }
    if (*siglen < ED25519_SIGSIZE) {
        ECerr(EC_F_PKEY_ECD_DIGESTSIGN25519, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ED25519_sign(sig, tbs, tbslen, edkey->pubkey, edkey->privkey) == 0)
        return 0;
    *siglen = ED25519_SIGSIZE;
    return 1;
}

static int pkey_ecd_digestsign448(EVP_MD_CTX *ctx, unsigned char *sig,
                                  size_t *siglen, const unsigned char *tbs,
                                  size_t tbslen)
{
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;

    if (sig == NULL) {
        *siglen = ED448_SIGSIZE;
        return 1;
    }
    if (*siglen < ED448_SIGSIZE) {
        ECerr(EC_F_PKEY_ECD_DIGESTSIGN448, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ED448_sign(sig, tbs, tbslen, edkey->pubkey, edkey->privkey, NULL,
                   0) == 0)
        return 0;
    *siglen = ED448_SIGSIZE;
    return 1;
}

static int pkey_ecd_digestverify25519(EVP_MD_CTX *ctx, const unsigned char *sig,
                                      size_t siglen, const unsigned char *tbs,
                                      size_t tbslen)
{
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;

    if (siglen != ED25519_SIGSIZE)
        return 0;

    return ED25519_verify(tbs, tbslen, sig, edkey->pubkey);
}

static int pkey_ecd_digestverify448(EVP_MD_CTX *ctx, const unsigned char *sig,
                                    size_t siglen, const unsigned char *tbs,
                                    size_t tbslen)
{
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;

    if (siglen != ED448_SIGSIZE)
        return 0;

    return ED448_verify(tbs, tbslen, sig, edkey->pubkey, NULL, 0);
}

static int pkey_ecd_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        /* Only NULL allowed as digest */
        if (p2 == NULL || (const EVP_MD *)p2 == EVP_md_null())
            return 1;
        ECerr(EC_F_PKEY_ECD_CTRL, EC_R_INVALID_DIGEST_TYPE);
        return 0;

    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;
    }
    return -2;
}

const EVP_PKEY_METHOD ed25519_pkey_meth = {
    EVP_PKEY_ED25519, EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    0, 0, 0, 0, 0, 0,
    pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    pkey_ecd_ctrl,
    0,
    pkey_ecd_digestsign25519,
    pkey_ecd_digestverify25519
};

const EVP_PKEY_METHOD ed448_pkey_meth = {
    EVP_PKEY_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    0, 0, 0, 0, 0, 0,
    pkey_ecx_keygen,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    pkey_ecd_ctrl,
    0,
    pkey_ecd_digestsign448,
    pkey_ecd_digestverify448
};

#ifdef S390X_EC_ASM
# include "s390x_arch.h"
# include "internal/constant_time.h"

static void s390x_x25519_mod_p(unsigned char u[32])
{
    unsigned char u_red[32];
    unsigned int c = 0;
    int i;

    memcpy(u_red, u, sizeof(u_red));

    c += (unsigned int)u_red[31] + 19;
    u_red[31] = (unsigned char)c;
    c >>= 8;

    for (i = 30; i >= 0; i--) {
        c += (unsigned int)u_red[i];
        u_red[i] = (unsigned char)c;
        c >>= 8;
    }

    c = (u_red[0] & 0x80) >> 7;
    u_red[0] &= 0x7f;
    constant_time_cond_swap_buff(0 - (unsigned char)c,
                                 u, u_red, sizeof(u_red));
}

static void s390x_x448_mod_p(unsigned char u[56])
{
    unsigned char u_red[56];
    unsigned int c = 0;
    int i;

    memcpy(u_red, u, sizeof(u_red));

    c += (unsigned int)u_red[55] + 1;
    u_red[55] = (unsigned char)c;
    c >>= 8;

    for (i = 54; i >= 28; i--) {
        c += (unsigned int)u_red[i];
        u_red[i] = (unsigned char)c;
        c >>= 8;
    }

    c += (unsigned int)u_red[27] + 1;
    u_red[27] = (unsigned char)c;
    c >>= 8;

    for (i = 26; i >= 0; i--) {
        c += (unsigned int)u_red[i];
        u_red[i] = (unsigned char)c;
        c >>= 8;
    }

    constant_time_cond_swap_buff(0 - (unsigned char)c,
                                 u, u_red, sizeof(u_red));
}

static int s390x_x25519_mul(unsigned char u_dst[32],
                            const unsigned char u_src[32],
                            const unsigned char d_src[32])
{
    union {
        struct {
            unsigned char u_dst[32];
            unsigned char u_src[32];
            unsigned char d_src[32];
        } x25519;
        unsigned long long buff[512];
    } param;
    int rc;

    memset(&param, 0, sizeof(param));

    s390x_flip_endian32(param.x25519.u_src, u_src);
    param.x25519.u_src[0] &= 0x7f;
    s390x_x25519_mod_p(param.x25519.u_src);

    s390x_flip_endian32(param.x25519.d_src, d_src);
    param.x25519.d_src[31] &= 248;
    param.x25519.d_src[0] &= 127;
    param.x25519.d_src[0] |= 64;

    rc = s390x_pcc(S390X_SCALAR_MULTIPLY_X25519, &param.x25519) ? 0 : 1;
    if (rc == 1)
        s390x_flip_endian32(u_dst, param.x25519.u_dst);

    OPENSSL_cleanse(param.x25519.d_src, sizeof(param.x25519.d_src));
    return rc;
}

static int s390x_x448_mul(unsigned char u_dst[56],
                          const unsigned char u_src[56],
                          const unsigned char d_src[56])
{
    union {
        struct {
            unsigned char u_dst[64];
            unsigned char u_src[64];
            unsigned char d_src[64];
        } x448;
        unsigned long long buff[512];
    } param;
    int rc;

    memset(&param, 0, sizeof(param));

    memcpy(param.x448.u_src, u_src, 56);
    memcpy(param.x448.d_src, d_src, 56);

    s390x_flip_endian64(param.x448.u_src, param.x448.u_src);
    s390x_x448_mod_p(param.x448.u_src + 8);

    s390x_flip_endian64(param.x448.d_src, param.x448.d_src);
    param.x448.d_src[63] &= 252;
    param.x448.d_src[8] |= 128;

    rc = s390x_pcc(S390X_SCALAR_MULTIPLY_X448, &param.x448) ? 0 : 1;
    if (rc == 1) {
        s390x_flip_endian64(param.x448.u_dst, param.x448.u_dst);
        memcpy(u_dst, param.x448.u_dst, 56);
    }

    OPENSSL_cleanse(param.x448.d_src, sizeof(param.x448.d_src));
    return rc;
}

static int s390x_ed25519_mul(unsigned char x_dst[32],
                             unsigned char y_dst[32],
                             const unsigned char x_src[32],
                             const unsigned char y_src[32],
                             const unsigned char d_src[32])
{
    union {
        struct {
            unsigned char x_dst[32];
            unsigned char y_dst[32];
            unsigned char x_src[32];
            unsigned char y_src[32];
            unsigned char d_src[32];
        } ed25519;
        unsigned long long buff[512];
    } param;
    int rc;

    memset(&param, 0, sizeof(param));

    s390x_flip_endian32(param.ed25519.x_src, x_src);
    s390x_flip_endian32(param.ed25519.y_src, y_src);
    s390x_flip_endian32(param.ed25519.d_src, d_src);

    rc = s390x_pcc(S390X_SCALAR_MULTIPLY_ED25519, &param.ed25519) ? 0 : 1;
    if (rc == 1) {
        s390x_flip_endian32(x_dst, param.ed25519.x_dst);
        s390x_flip_endian32(y_dst, param.ed25519.y_dst);
    }

    OPENSSL_cleanse(param.ed25519.d_src, sizeof(param.ed25519.d_src));
    return rc;
}

static int s390x_ed448_mul(unsigned char x_dst[57],
                           unsigned char y_dst[57],
                           const unsigned char x_src[57],
                           const unsigned char y_src[57],
                           const unsigned char d_src[57])
{
    union {
        struct {
            unsigned char x_dst[64];
            unsigned char y_dst[64];
            unsigned char x_src[64];
            unsigned char y_src[64];
            unsigned char d_src[64];
        } ed448;
        unsigned long long buff[512];
    } param;
    int rc;

    memset(&param, 0, sizeof(param));

    memcpy(param.ed448.x_src, x_src, 57);
    memcpy(param.ed448.y_src, y_src, 57);
    memcpy(param.ed448.d_src, d_src, 57);
    s390x_flip_endian64(param.ed448.x_src, param.ed448.x_src);
    s390x_flip_endian64(param.ed448.y_src, param.ed448.y_src);
    s390x_flip_endian64(param.ed448.d_src, param.ed448.d_src);

    rc = s390x_pcc(S390X_SCALAR_MULTIPLY_ED448, &param.ed448) ? 0 : 1;
    if (rc == 1) {
        s390x_flip_endian64(param.ed448.x_dst, param.ed448.x_dst);
        s390x_flip_endian64(param.ed448.y_dst, param.ed448.y_dst);
        memcpy(x_dst, param.ed448.x_dst, 57);
        memcpy(y_dst, param.ed448.y_dst, 57);
    }

    OPENSSL_cleanse(param.ed448.d_src, sizeof(param.ed448.d_src));
    return rc;
}

static int s390x_pkey_ecx_keygen25519(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    static const unsigned char generator[] = {
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ECX_KEY *key;
    unsigned char *privkey = NULL, *pubkey;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ECerr(EC_F_S390X_PKEY_ECX_KEYGEN25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pubkey = key->pubkey;

    privkey = key->privkey = OPENSSL_secure_malloc(X25519_KEYLEN);
    if (privkey == NULL) {
        ECerr(EC_F_S390X_PKEY_ECX_KEYGEN25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (RAND_priv_bytes(privkey, X25519_KEYLEN) <= 0)
        goto err;

    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;

    if (s390x_x25519_mul(pubkey, generator, privkey) != 1)
        goto err;

    EVP_PKEY_assign(pkey, ctx->pmeth->pkey_id, key);
    return 1;
 err:
    OPENSSL_secure_clear_free(privkey, X25519_KEYLEN);
    key->privkey = NULL;
    OPENSSL_free(key);
    return 0;
}

static int s390x_pkey_ecx_keygen448(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    static const unsigned char generator[] = {
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ECX_KEY *key;
    unsigned char *privkey = NULL, *pubkey;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ECerr(EC_F_S390X_PKEY_ECX_KEYGEN448, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pubkey = key->pubkey;

    privkey = key->privkey = OPENSSL_secure_malloc(X448_KEYLEN);
    if (privkey == NULL) {
        ECerr(EC_F_S390X_PKEY_ECX_KEYGEN448, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (RAND_priv_bytes(privkey, X448_KEYLEN) <= 0)
        goto err;

    privkey[0] &= 252;
    privkey[55] |= 128;

    if (s390x_x448_mul(pubkey, generator, privkey) != 1)
        goto err;

    EVP_PKEY_assign(pkey, ctx->pmeth->pkey_id, key);
    return 1;
 err:
    OPENSSL_secure_clear_free(privkey, X448_KEYLEN);
    key->privkey = NULL;
    OPENSSL_free(key);
    return 0;
}

static int s390x_pkey_ecd_keygen25519(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    static const unsigned char generator_x[] = {
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95,
        0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
        0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21
    };
    static const unsigned char generator_y[] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    };
    unsigned char x_dst[32], buff[SHA512_DIGEST_LENGTH];
    ECX_KEY *key;
    unsigned char *privkey = NULL, *pubkey;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ECerr(EC_F_S390X_PKEY_ECD_KEYGEN25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pubkey = key->pubkey;

    privkey = key->privkey = OPENSSL_secure_malloc(ED25519_KEYLEN);
    if (privkey == NULL) {
        ECerr(EC_F_S390X_PKEY_ECD_KEYGEN25519, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (RAND_priv_bytes(privkey, ED25519_KEYLEN) <= 0)
        goto err;

    SHA512(privkey, 32, buff);
    buff[0] &= 248;
    buff[31] &= 63;
    buff[31] |= 64;

    if (s390x_ed25519_mul(x_dst, pubkey,
                          generator_x, generator_y, buff) != 1)
        goto err;

    pubkey[31] |= ((x_dst[0] & 0x01) << 7);

    EVP_PKEY_assign(pkey, ctx->pmeth->pkey_id, key);
    return 1;
 err:
    OPENSSL_secure_clear_free(privkey, ED25519_KEYLEN);
    key->privkey = NULL;
    OPENSSL_free(key);
    return 0;
}

static int s390x_pkey_ecd_keygen448(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    static const unsigned char generator_x[] = {
        0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26, 0x8e, 0x93, 0x00, 0x8b,
        0xe1, 0x80, 0x3b, 0x43, 0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
        0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea, 0x67, 0x17, 0x0f, 0x47,
        0x70, 0x65, 0x14, 0x9e, 0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
        0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f, 0x00
    };
    static const unsigned char generator_y[] = {
        0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e,
        0x2c, 0x13, 0xbd, 0xfd, 0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
        0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87, 0x40, 0x98, 0xa3, 0x6c,
        0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
        0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69, 0x00
    };
    unsigned char x_dst[57], buff[114];
    ECX_KEY *key;
    unsigned char *privkey = NULL, *pubkey;
    EVP_MD_CTX *hashctx = NULL;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ECerr(EC_F_S390X_PKEY_ECD_KEYGEN448, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pubkey = key->pubkey;

    privkey = key->privkey = OPENSSL_secure_malloc(ED448_KEYLEN);
    if (privkey == NULL) {
        ECerr(EC_F_S390X_PKEY_ECD_KEYGEN448, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (RAND_priv_bytes(privkey, ED448_KEYLEN) <= 0)
        goto err;

    hashctx = EVP_MD_CTX_new();
    if (hashctx == NULL)
        goto err;
    if (EVP_DigestInit_ex(hashctx, EVP_shake256(), NULL) != 1)
        goto err;
    if (EVP_DigestUpdate(hashctx, privkey, 57) != 1)
        goto err;
    if (EVP_DigestFinalXOF(hashctx, buff, sizeof(buff)) != 1)
        goto err;

    buff[0] &= -4;
    buff[55] |= 0x80;
    buff[56] = 0;

    if (s390x_ed448_mul(x_dst, pubkey,
                        generator_x, generator_y, buff) != 1)
        goto err;

    pubkey[56] |= ((x_dst[0] & 0x01) << 7);

    EVP_PKEY_assign(pkey, ctx->pmeth->pkey_id, key);
    EVP_MD_CTX_free(hashctx);
    return 1;
 err:
    OPENSSL_secure_clear_free(privkey, ED448_KEYLEN);
    key->privkey = NULL;
    OPENSSL_free(key);
    EVP_MD_CTX_free(hashctx);
    return 0;
}

static int s390x_pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key,
                                      size_t *keylen)
{
    const unsigned char *privkey, *pubkey;

    if (!validate_ecx_derive(ctx, key, keylen, &privkey, &pubkey))
        return 0;

    if (key != NULL)
        return s390x_x25519_mul(key, pubkey, privkey);

    *keylen = X25519_KEYLEN;
    return 1;
}

static int s390x_pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key,
                                      size_t *keylen)
{
    const unsigned char *privkey, *pubkey;

    if (!validate_ecx_derive(ctx, key, keylen, &privkey, &pubkey))
        return 0;

    if (key != NULL)
        return s390x_x448_mul(key, pubkey, privkey);

    *keylen = X448_KEYLEN;
    return 1;
}

static int s390x_pkey_ecd_digestsign25519(EVP_MD_CTX *ctx,
                                          unsigned char *sig, size_t *siglen,
                                          const unsigned char *tbs,
                                          size_t tbslen)
{
    union {
        struct {
            unsigned char sig[64];
            unsigned char priv[32];
        } ed25519;
        unsigned long long buff[512];
    } param;
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;
    int rc;

    if (sig == NULL) {
        *siglen = ED25519_SIGSIZE;
        return 1;
    }

    if (*siglen < ED25519_SIGSIZE) {
        ECerr(EC_F_S390X_PKEY_ECD_DIGESTSIGN25519, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    memset(&param, 0, sizeof(param));
    memcpy(param.ed25519.priv, edkey->privkey, sizeof(param.ed25519.priv));

    rc = s390x_kdsa(S390X_EDDSA_SIGN_ED25519, &param.ed25519, tbs, tbslen);
    OPENSSL_cleanse(param.ed25519.priv, sizeof(param.ed25519.priv));
    if (rc != 0)
        return 0;

    s390x_flip_endian32(sig, param.ed25519.sig);
    s390x_flip_endian32(sig + 32, param.ed25519.sig + 32);

    *siglen = ED25519_SIGSIZE;
    return 1;
}

static int s390x_pkey_ecd_digestsign448(EVP_MD_CTX *ctx,
                                        unsigned char *sig, size_t *siglen,
                                        const unsigned char *tbs,
                                        size_t tbslen)
{
    union {
        struct {
            unsigned char sig[128];
            unsigned char priv[64];
        } ed448;
        unsigned long long buff[512];
    } param;
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;
    int rc;

    if (sig == NULL) {
        *siglen = ED448_SIGSIZE;
        return 1;
    }

    if (*siglen < ED448_SIGSIZE) {
        ECerr(EC_F_S390X_PKEY_ECD_DIGESTSIGN448, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    memset(&param, 0, sizeof(param));
    memcpy(param.ed448.priv + 64 - 57, edkey->privkey, 57);

    rc = s390x_kdsa(S390X_EDDSA_SIGN_ED448, &param.ed448, tbs, tbslen);
    OPENSSL_cleanse(param.ed448.priv, sizeof(param.ed448.priv));
    if (rc != 0)
        return 0;

    s390x_flip_endian64(param.ed448.sig, param.ed448.sig);
    s390x_flip_endian64(param.ed448.sig + 64, param.ed448.sig + 64);
    memcpy(sig, param.ed448.sig, 57);
    memcpy(sig + 57, param.ed448.sig + 64, 57);

    *siglen = ED448_SIGSIZE;
    return 1;
}

static int s390x_pkey_ecd_digestverify25519(EVP_MD_CTX *ctx,
                                            const unsigned char *sig,
                                            size_t siglen,
                                            const unsigned char *tbs,
                                            size_t tbslen)
{
    union {
        struct {
            unsigned char sig[64];
            unsigned char pub[32];
        } ed25519;
        unsigned long long buff[512];
    } param;
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;

    if (siglen != ED25519_SIGSIZE)
        return 0;

    memset(&param, 0, sizeof(param));
    s390x_flip_endian32(param.ed25519.sig, sig);
    s390x_flip_endian32(param.ed25519.sig + 32, sig + 32);
    s390x_flip_endian32(param.ed25519.pub, edkey->pubkey);

    return s390x_kdsa(S390X_EDDSA_VERIFY_ED25519,
                      &param.ed25519, tbs, tbslen) == 0 ? 1 : 0;
}

static int s390x_pkey_ecd_digestverify448(EVP_MD_CTX *ctx,
                                          const unsigned char *sig,
                                          size_t siglen,
                                          const unsigned char *tbs,
                                          size_t tbslen)
{
    union {
        struct {
            unsigned char sig[128];
            unsigned char pub[64];
        } ed448;
        unsigned long long buff[512];
    } param;
    const ECX_KEY *edkey = EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ecx;

    if (siglen != ED448_SIGSIZE)
        return 0;

    memset(&param, 0, sizeof(param));
    memcpy(param.ed448.sig, sig, 57);
    s390x_flip_endian64(param.ed448.sig, param.ed448.sig);
    memcpy(param.ed448.sig + 64, sig + 57, 57);
    s390x_flip_endian64(param.ed448.sig + 64, param.ed448.sig + 64);
    memcpy(param.ed448.pub, edkey->pubkey, 57);
    s390x_flip_endian64(param.ed448.pub, param.ed448.pub);

    return s390x_kdsa(S390X_EDDSA_VERIFY_ED448,
                      &param.ed448, tbs, tbslen) == 0 ? 1 : 0;
}

static const EVP_PKEY_METHOD ecx25519_s390x_pkey_meth = {
    EVP_PKEY_X25519,
    0, 0, 0, 0, 0, 0, 0,
    s390x_pkey_ecx_keygen25519,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    s390x_pkey_ecx_derive25519,
    pkey_ecx_ctrl,
    0
};

static const EVP_PKEY_METHOD ecx448_s390x_pkey_meth = {
    EVP_PKEY_X448,
    0, 0, 0, 0, 0, 0, 0,
    s390x_pkey_ecx_keygen448,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    s390x_pkey_ecx_derive448,
    pkey_ecx_ctrl,
    0
};
static const EVP_PKEY_METHOD ed25519_s390x_pkey_meth = {
    EVP_PKEY_ED25519, EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    0, 0, 0, 0, 0, 0,
    s390x_pkey_ecd_keygen25519,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    pkey_ecd_ctrl,
    0,
    s390x_pkey_ecd_digestsign25519,
    s390x_pkey_ecd_digestverify25519
};

static const EVP_PKEY_METHOD ed448_s390x_pkey_meth = {
    EVP_PKEY_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    0, 0, 0, 0, 0, 0,
    s390x_pkey_ecd_keygen448,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    pkey_ecd_ctrl,
    0,
    s390x_pkey_ecd_digestsign448,
    s390x_pkey_ecd_digestverify448
};
#endif

const EVP_PKEY_METHOD *ecx25519_pkey_method(void)
{
#ifdef S390X_EC_ASM
    if (OPENSSL_s390xcap_P.pcc[1] & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X25519))
        return &ecx25519_s390x_pkey_meth;
#endif
    return &ecx25519_pkey_meth;
}

const EVP_PKEY_METHOD *ecx448_pkey_method(void)
{
#ifdef S390X_EC_ASM
    if (OPENSSL_s390xcap_P.pcc[1] & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X448))
        return &ecx448_s390x_pkey_meth;
#endif
    return &ecx448_pkey_meth;
}

const EVP_PKEY_METHOD *ed25519_pkey_method(void)
{
#ifdef S390X_EC_ASM
    if (OPENSSL_s390xcap_P.pcc[1] & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_ED25519)
        && OPENSSL_s390xcap_P.kdsa[0] & S390X_CAPBIT(S390X_EDDSA_SIGN_ED25519)
        && OPENSSL_s390xcap_P.kdsa[0]
            & S390X_CAPBIT(S390X_EDDSA_VERIFY_ED25519))
        return &ed25519_s390x_pkey_meth;
#endif
    return &ed25519_pkey_meth;
}

const EVP_PKEY_METHOD *ed448_pkey_method(void)
{
#ifdef S390X_EC_ASM
    if (OPENSSL_s390xcap_P.pcc[1] & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_ED448)
        && OPENSSL_s390xcap_P.kdsa[0] & S390X_CAPBIT(S390X_EDDSA_SIGN_ED448)
        && OPENSSL_s390xcap_P.kdsa[0] & S390X_CAPBIT(S390X_EDDSA_VERIFY_ED448))
        return &ed448_s390x_pkey_meth;
#endif
    return &ed448_pkey_meth;
}
