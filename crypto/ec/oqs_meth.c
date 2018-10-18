/* OQS authentication methods.
 *
 * This file mimics ecx_meth.c. Compare the oqs* with the ecx* functions
 * to understand the code.
 *
 * TODO:
 *  - Improve error reporting. Define OQS specific error codes, using util/mkerr.pl?
 *    (or perhaps re-use EC_* values?
 *  - Add tests
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include <oqs/rand.h>
#include <oqs/common.h>
#include <oqs/sig.h>

/*
 * OQS context
 */
typedef struct
{
  OQS_SIG *s;
  uint8_t *pubkey;
  uint8_t *privkey;
  int security_bits;
} OQS_KEY;

/*
 * OQS key type
 */
typedef enum {
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} oqs_key_type_t;

/*
 * Maps OpenSSL NIDs to OQS IDs
 */
static char* get_oqs_alg_name(int openssl_nid)
{
  switch (openssl_nid)
    {
    case NID_picnicL1FS:
      return OQS_SIG_alg_picnic_L1_FS;
    case NID_qTESLA_I:
      return OQS_SIG_alg_qTESLA_I;
    case NID_qTESLA_III_size:
      return OQS_SIG_alg_qTESLA_III_size;
    case NID_qTESLA_III_speed:
      return OQS_SIG_alg_qTESLA_III_speed;
    /* ADD_MORE_OQS_SIG_HERE */
    default:
      return NULL;
    }
}

/*
 * Returns the security level in bits for an OQS alg.
 */
static int get_oqs_security_bits(int openssl_nid)
{
  switch (openssl_nid)
    {
    case NID_picnicL1FS:
      return 128;
    case NID_qTESLA_I:
      return 128;
    case NID_qTESLA_III_size:
      return 192;
    case NID_qTESLA_III_speed:
      return 192;
    /* ADD_MORE_OQS_SIG_HERE */
    default:
      return -1;
    }
}

/*
 * Frees the OQS_KEY, including its keys.
 */
static void oqs_pkey_ctx_free(OQS_KEY* key) {
  int privkey_len = 0;
  if (key == NULL) {
    return;
  }
  if (key->s) {
    privkey_len = key->s->length_secret_key;
    OQS_SIG_free(key->s);
  }
  if (key->privkey) {
    OPENSSL_secure_clear_free(key->privkey, privkey_len);
  }
  if (key->pubkey) {
    OPENSSL_free(key->pubkey);
  }
  OPENSSL_free(key);
}


/*
 * Initializes a OQS_KEY, given an OpenSSL NID.
 */
static int oqs_key_init(OQS_KEY **p_oqs_key, int nid, oqs_key_type_t keytype) {
    OQS_KEY *oqs_key = NULL;
    const char* oqs_alg_name = get_oqs_alg_name(nid);
    
    oqs_key = OPENSSL_zalloc(sizeof(*oqs_key));
    if (oqs_key == NULL) {
      OQSerr(0, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    oqs_key->s = OQS_SIG_new(oqs_alg_name);
    if (oqs_key->s == NULL) {
      /* TODO: provide a better error message for non-enabled OQS schemes.
	 Perhaps even check if the alg is available earlier in the stack. (FIXMEOQS) */
      OQSerr(0, ERR_R_FATAL);
      goto err;
    }
    oqs_key->pubkey = OPENSSL_malloc(oqs_key->s->length_public_key);
    if (oqs_key->pubkey == NULL) {
      OQSerr(0, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    /* Optionally allocate the private key */
    if (keytype == KEY_TYPE_PRIVATE) {
      oqs_key->privkey = OPENSSL_secure_malloc(oqs_key->s->length_secret_key);
      if (oqs_key->privkey == NULL) {
	OQSerr(0, ERR_R_MALLOC_FAILURE);
	goto err;
      }
    }
    oqs_key->security_bits = get_oqs_security_bits(nid);
    *p_oqs_key = oqs_key;
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
}

static int oqs_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    unsigned char *penc;
    if (!oqs_key || !oqs_key->s || !oqs_key->pubkey ) {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }

    penc = OPENSSL_memdup(oqs_key->pubkey, oqs_key->s->length_public_key);
    if (penc == NULL) {
        OQSerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                                V_ASN1_UNDEF, NULL, penc, oqs_key->s->length_public_key)) {
        OPENSSL_free(penc);
        OQSerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static int oqs_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;
    int id = pkey->ameth->pkey_id;
    
    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey)) {
        return 0;
    }
    if (p == NULL) {
      /* pklen is checked below, after we instantiate the oqs_key to
	 learn the expected len */
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }

    if (palg != NULL) {
      int ptype;
      
      /* Algorithm parameters must be absent */
      X509_ALGOR_get0(NULL, &ptype, NULL, palg);
      if (ptype != V_ASN1_UNDEF) {
	OQSerr(0, ERR_R_FATAL);
	return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, id, 0)) {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }
    
    if (pklen != oqs_key->s->length_public_key) {
      OQSerr(0, ERR_R_FATAL);
      oqs_pkey_ctx_free(oqs_key);
      return 0;
    }
    memcpy(oqs_key->pubkey, p, pklen);
    EVP_PKEY_assign(pkey, id, oqs_key);
    return 1;
}

static int oqs_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const OQS_KEY *akey = (OQS_KEY*) a->pkey.ptr;
    const OQS_KEY *bkey = (OQS_KEY*) b->pkey.ptr;
    if (akey == NULL || bkey == NULL)
        return -2;

    return CRYPTO_memcmp(akey->pubkey, bkey->pubkey, akey->s->length_public_key) == 0;
}

static int oqs_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;

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

    /* oct contains first the private key, then the public key */
    if (palg != NULL) {
      int ptype;
      
      /* Algorithm parameters must be absent */
      X509_ALGOR_get0(NULL, &ptype, NULL, palg);
      if (ptype != V_ASN1_UNDEF) {
	OQSerr(0, ERR_R_FATAL);
	return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, pkey->ameth->pkey_id, 1)) {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }
    if (plen != oqs_key->s->length_secret_key + oqs_key->s->length_public_key) {
      OQSerr(0, ERR_R_FATAL);
      oqs_pkey_ctx_free(oqs_key);
      return 0;
    }
    memcpy(oqs_key->privkey, p, oqs_key->s->length_secret_key);
    memcpy(oqs_key->pubkey, p + oqs_key->s->length_secret_key, oqs_key->s->length_public_key);
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, oqs_key);

    ASN1_OCTET_STRING_free(oct);
    return 1;
}

static int oqs_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqskey = (OQS_KEY*) pkey->pkey.ptr;
    ASN1_OCTET_STRING oct;
    unsigned char *buf = NULL, *penc = NULL;
    int buflen = oqskey->s->length_secret_key + oqskey->s->length_public_key, penclen;

    buf = OPENSSL_secure_malloc(buflen);
    if (buf == NULL) {
        OQSerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memcpy(buf, oqskey->privkey, oqskey->s->length_secret_key);
    memcpy(buf + oqskey->s->length_secret_key, oqskey->pubkey, oqskey->s->length_public_key);
    oct.data = buf;
    oct.length = buflen;
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
        OQSerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_secure_clear_free(buf, buflen);
        OPENSSL_clear_free(penc, penclen);
        OQSerr(0, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    OPENSSL_secure_clear_free(buf, buflen);
    return 1;
}

static int oqs_size(const EVP_PKEY *pkey)
{
    const OQS_KEY *oqskey = (OQS_KEY*) pkey->pkey.ptr;
    if (oqskey == NULL || oqskey->s == NULL) {
        OQSerr(0, ERR_R_FATAL);
        return 0;
    }
    return oqskey->s->length_signature;
}

static int oqs_bits(const EVP_PKEY *pkey)
{
    return ((OQS_KEY*) pkey->pkey.ptr)->s->length_public_key;
}

static int oqs_security_bits(const EVP_PKEY *pkey)
{
    return ((OQS_KEY*) pkey->pkey.ptr)->security_bits;
}

static void oqs_free(EVP_PKEY *pkey)
{
    oqs_pkey_ctx_free((OQS_KEY*) pkey->pkey.ptr);
}

/* "parameters" are always equal */
static int oqs_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}

static int oqs_key_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx, oqs_key_type_t keytype)
{
    const OQS_KEY *oqskey = (OQS_KEY*) pkey->pkey.ptr;
    const char *nm = OBJ_nid2ln(pkey->ameth->pkey_id);

    if (keytype == KEY_TYPE_PRIVATE) {
        if (oqskey == NULL || oqskey->privkey == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nm) <= 0)
            return 0;
        if (BIO_printf(bp, "%*spriv:\n", indent, "") <= 0)
            return 0;
        if (ASN1_buf_print(bp, oqskey->privkey, oqskey->s->length_secret_key,
                           indent + 4) == 0)
            return 0;
    } else {
        if (oqskey == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Public-Key:\n", indent, "", nm) <= 0)
            return 0;
    }
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        return 0;

    if (ASN1_buf_print(bp, oqskey->pubkey, oqskey->s->length_public_key,
                       indent + 4) == 0)
        return 0;
    return 1;
}

static int oqs_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
  return oqs_key_print(bp, pkey, indent, ctx, KEY_TYPE_PRIVATE);
}

static int oqs_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx)
{
  return oqs_key_print(bp, pkey, indent, ctx, KEY_TYPE_PUBLIC);
}

static int oqs_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                           X509_ALGOR *sigalg, ASN1_BIT_STRING *str,
                           EVP_PKEY *pkey)
{
    const ASN1_OBJECT *obj;
    int ptype;
    int nid;

    /* Sanity check: make sure it is an OQS scheme with absent parameters */
    X509_ALGOR_get0(&obj, &ptype, NULL, sigalg);
    nid = OBJ_obj2nid(obj);
    if (
	(nid != NID_picnicL1FS &&
	 nid != NID_qTESLA_I &&
	 nid != NID_qTESLA_III_size &&
	 nid != NID_qTESLA_III_speed
	 /* ADD_MORE_OQS_SIG_HERE */
	 ) || ptype != V_ASN1_UNDEF) {
        OQSerr(0, ERR_R_FATAL);
        return 0;
    }

    if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
        return 0;

    return 2;
}

#define DEFINE_OQS_ITEM_SIGN(ALG, NID_ALG) \
static int oqs_item_sign_##ALG(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,\
                         X509_ALGOR *alg1, X509_ALGOR *alg2,                   \
                         ASN1_BIT_STRING *str)                                 \
{                                                                              \
    /* Set algorithm identifier */                                             \
    X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_ALG), V_ASN1_UNDEF, NULL);           \
    if (alg2 != NULL)                                                          \
        X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_ALG), V_ASN1_UNDEF, NULL);       \
    /* Algorithm identifier set: carry on as normal */                         \
    return 3;                                                                  \
}

#define DEFINE_OQS_SIGN_INFO_SET(ALG, NID_ALG) \
static int oqs_sig_info_set_##ALG(X509_SIG_INFO *siginf, const X509_ALGOR *alg,  \
                            const ASN1_STRING *sig)                              \
{                                                                                \
    X509_SIG_INFO_set(siginf, NID_undef, NID_ALG, get_oqs_security_bits(NID_ALG),\
                      X509_SIG_INFO_TLS);                                        \
    return 1;                                                                    \
}

#define DEFINE_OQS_EVP_PKEY_ASN1_METHOD(ALG, NID_ALG, SHORT_NAME, LONG_NAME) \
const EVP_PKEY_ASN1_METHOD ALG##_asn1_meth = { \
    NID_ALG,                                   \
    NID_ALG,                                   \
    0,                                         \
    SHORT_NAME,                                \
    LONG_NAME,                                 \
    oqs_pub_decode,                            \
    oqs_pub_encode,                            \
    oqs_pub_cmp,                               \
    oqs_pub_print,                             \
    oqs_priv_decode,                           \
    oqs_priv_encode,                           \
    oqs_priv_print,                            \
    oqs_size,                                  \
    oqs_bits,                                  \
    oqs_security_bits,                         \
    0, 0, 0, 0,                                \
    oqs_cmp_parameters,                        \
    0, 0,                                      \
    oqs_free,                                  \
    0, 0, 0,                                   \
    oqs_item_verify,                           \
    oqs_item_sign_##ALG,                       \
    oqs_sig_info_set_##ALG,                    \
    0, 0, 0, 0, 0,                             \
};

static int pkey_oqs_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    OQS_KEY *oqs_key = NULL;
    int id = ctx->pmeth->pkey_id;

    if (!oqs_key_init(&oqs_key, id, 1)) {
      OQSerr(0, ERR_R_FATAL);
      goto err;
    }

    if (OQS_SIG_keypair(oqs_key->s, oqs_key->pubkey, oqs_key->privkey) != OQS_SUCCESS) {
      OQSerr(0, ERR_R_FATAL);
      goto err;
    }

    EVP_PKEY_assign(pkey, id, oqs_key);
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
  
}

static int pkey_oqs_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;
    if (!oqs_key || !oqs_key->s || !oqs_key->privkey ) {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }

    if (sig == NULL) {
      *siglen = oqs_key->s->length_signature;
      return 1;
    }
    if (*siglen < oqs_key->s->length_signature) {
        OQSerr(0, ERR_R_FATAL);
        return 0;
    }
    if (OQS_SIG_sign(oqs_key->s, sig, siglen, tbs, tbslen, oqs_key->privkey) != OQS_SUCCESS) {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }

    return 1;
}

static int pkey_oqs_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;
    
    if (!oqs_key || !oqs_key->s  || !oqs_key->pubkey || sig == NULL || tbs == NULL) {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }

    if (OQS_SIG_verify(oqs_key->s, tbs, tbslen, sig, siglen, oqs_key->pubkey) != OQS_SUCCESS) {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }

    return 1;
}

static int pkey_oqs_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        /* Only NULL allowed as digest */
        if (p2 == NULL)
            return 1;
        OQSerr(0, ERR_R_FATAL);
        return 0;

    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;
    }
    return -2;
}

#define DEFINE_OQS_EVP_PKEY_METHOD(ALG, NID_ALG)    \
const EVP_PKEY_METHOD ALG##_pkey_meth = {           \
    NID_ALG, EVP_PKEY_FLAG_SIGCTX_CUSTOM,           \
    0, 0, 0, 0, 0, 0,                               \
    pkey_oqs_keygen,                                \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
    pkey_oqs_ctrl,                                  \
    0,                                              \
    pkey_oqs_digestsign,                            \
    pkey_oqs_digestverify                           \
};

#define DEFINE_OQS_EVP_METHODS(ALG, NID_ALG, SHORT_NAME, LONG_NAME)   \
DEFINE_OQS_ITEM_SIGN(ALG, NID_ALG)                                    \
DEFINE_OQS_SIGN_INFO_SET(ALG, NID_ALG)                                \
DEFINE_OQS_EVP_PKEY_METHOD(ALG, NID_ALG)                              \
DEFINE_OQS_EVP_PKEY_ASN1_METHOD(ALG, NID_ALG, SHORT_NAME, LONG_NAME)

DEFINE_OQS_EVP_METHODS(picnicL1FS, NID_picnicL1FS, "picnicL1FS", "OpenSSL Picnic L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(qteslaI, NID_qTESLA_I, "qteslaI", "OpenSSL qTESLA-I algorithm")
DEFINE_OQS_EVP_METHODS(qteslaIIIsize, NID_qTESLA_III_size, "qteslaIIIsize", "OpenSSL qTESLA-III-size algorithm")
DEFINE_OQS_EVP_METHODS(qteslaIIIspeed, NID_qTESLA_III_speed, "qteslaIIIspeed", "OpenSSL qTESLA-III-speed algorithm")
