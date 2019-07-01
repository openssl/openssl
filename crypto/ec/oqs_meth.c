/* OQS authentication methods.
 *
 * This file mimics ecx_meth.c. Compare the oqs* with the ecx* functions
 * to understand the code.
 *
 * TODO:
 *  - Improve error reporting. Define OQS specific error codes, using util/mkerr.pl?
 *    (or perhaps re-use EC_* values?
 *  - Add tests
 *  - FIXMEOQS: which RSA NID should I use in hybrid sig? NID_rsaencryption is used by "req" when using "rsa"?
 */

/* OQS note:
   In addition to post-quantum (PQ) signatures; we also support classical/PQ hybrids. In that case, a classical and a PQ signature
   are generated on the same data, and the resulting signatures are concatenated; the classical and PQ keys are also concatenated
   when serialized. The signed data is first hashed using the SHA-2 hash function matching the security level of the OQS scheme
   (SHA256 for L1, SHA384 for L2/L3, SHA512 for L4/L5) before being signed by the classical algorithm (which can't support
   arbitrarily long messages), and is passed directly to the OQS signature API. The hybrid scheme is identified as a new combo
   scheme with a unique NID. Currently, ECDSA-p256 and RSA3072 hybrids are supported with L1 OQS schemes, and ECDSA-p384 hybrids
   are supported with L3 schemes. The public and private keys are also concatenated when serialized. Encoding of artefacts (keys
   and signatures) are as follow:
   - classical_artefact_length: 4 bytes encoding the size of the classical artefact
   - classical_artefact: the classical artefact of length classical_artefact_length
   - oqs_artefact: the post-quantum artefact, of length determined by the OQS signature context
*/

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include <oqs/oqs.h>

/* Only supports OQS's master branch signature API for now */
#if !defined(OQS_NIST_BRANCH)

#define SIZE_OF_UINT32 4
#define ENCODE_UINT32(pbuf, i)  (pbuf)[0] = (unsigned char)((i>>24) & 0xff); \
                                (pbuf)[1] = (unsigned char)((i>>16) & 0xff); \
				(pbuf)[2] = (unsigned char)((i>> 8) & 0xff); \
				(pbuf)[3] = (unsigned char)((i    ) & 0xff)
#define DECODE_UINT32(i, pbuf)  i  = ((uint32_t) (pbuf)[0]) << 24; \
                                i |= ((uint32_t) (pbuf)[1]) << 16; \
				i |= ((uint32_t) (pbuf)[2]) <<  8; \
				i |= ((uint32_t) (pbuf)[3])

/*
 * OQS context
 */
typedef struct
{
  /* OpenSSL NID */
  int nid;
  /* OQS signature context */
  OQS_SIG *s;
  /* OQS public key */
  uint8_t *pubkey;
  /* OQS private key */
  uint8_t *privkey;
  /* Classical key pair for hybrid schemes; either a private or public key depending on context */
  EVP_PKEY *classical_pkey;
  /* Security bits for the scheme */
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
    case NID_p256_picnicL1FS:
    case NID_rsa3072_picnicL1FS:
      return OQS_SIG_alg_picnic_L1_FS;
    case NID_qteslaI:
    case NID_p256_qteslaI:
    case NID_rsa3072_qteslaI:
      return OQS_SIG_alg_qTESLA_I;
    case NID_qteslaIIIsize:
    case NID_p384_qteslaIIIsize:
      return OQS_SIG_alg_qTESLA_III_size;
    case NID_qteslaIIIspeed:
    case NID_p384_qteslaIIIspeed:
      return OQS_SIG_alg_qTESLA_III_speed;
    /* ADD_MORE_OQS_SIG_HERE */
    default:
      return NULL;
    }
}

static int is_oqs_hybrid_alg(int openssl_nid)
{
  switch (openssl_nid)
    {
    case NID_p256_picnicL1FS:
    case NID_rsa3072_picnicL1FS:
    case NID_p256_qteslaI:
    case NID_rsa3072_qteslaI:
    case NID_p384_qteslaIIIsize:
    case NID_p384_qteslaIIIspeed:
    /* ADD_MORE_OQS_SIG_HERE hybrid only */
      return 1;
    default:
      return 0;
    }
}


static int get_classical_nid(int hybrid_id)
{
 switch (hybrid_id)
    {
    case NID_rsa3072_picnicL1FS:
    case NID_rsa3072_qteslaI:
      return NID_rsaEncryption;
    case NID_p256_picnicL1FS:
    case NID_p256_qteslaI:
      return NID_X9_62_prime256v1;
    case NID_p384_qteslaIIIsize:
    case NID_p384_qteslaIIIspeed:
      return NID_secp384r1;
    /* ADD_MORE_OQS_SIG_HERE hybrid only */
    default:
      return 0;
    }
}

static int get_oqs_nid(int hybrid_id)
{
 switch (hybrid_id)
    {
    case NID_rsa3072_picnicL1FS:
    case NID_p256_picnicL1FS:
      return NID_picnicL1FS;
    case NID_rsa3072_qteslaI:
    case NID_p256_qteslaI:
      return NID_qteslaI;
    case NID_p384_qteslaIIIsize:
      return NID_qteslaIIIsize;
    case NID_p384_qteslaIIIspeed:
      return NID_qteslaIIIspeed;
    /* ADD_MORE_OQS_SIG_HERE hybrid only */
    default:
      return 0;
    }
}

static int get_classical_key_len(oqs_key_type_t keytype, int classical_id) {
 switch (classical_id)
    {
    case NID_rsaEncryption:
      return (keytype == KEY_TYPE_PRIVATE) ? 1770 : 398;
    case NID_X9_62_prime256v1:
      return (keytype == KEY_TYPE_PRIVATE) ? 121 : 65;
    case NID_secp384r1:
      return (keytype == KEY_TYPE_PRIVATE) ? 167 : 97;
    default:
      return -1;
    }
}

static int get_classical_sig_len(int classical_id)
{
 switch (classical_id)
    {
    case NID_rsaEncryption:
      return 384;
    case NID_X9_62_prime256v1:
      return 72;
    case NID_secp384r1:
      return 104;
    default:
      return -1;
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
    case NID_qteslaI:
      return 128;
    case NID_qteslaIIIsize:
      return 192;
    case NID_qteslaIIIspeed:
      return 192;
    /* hybrid schemes */
    case NID_p256_picnicL1FS:
      return 128;
    case NID_rsa3072_picnicL1FS:
      return 192;
    case NID_p256_qteslaI:
      return 128;
    case NID_rsa3072_qteslaI:
      return 128;
    case NID_p384_qteslaIIIsize:
      return 192;
    case NID_p384_qteslaIIIspeed:
      return 192;
    /* ADD_MORE_OQS_SIG_HERE */
    default:
      return -1;
    }
}

static int is_EC_nid(int nid) {
  return (nid == NID_X9_62_prime256v1 || nid == NID_secp384r1);
}

static int decode_EC_key(oqs_key_type_t keytype, int nid, const unsigned char* encoded_key, int key_len, OQS_KEY* oqs_key) {
  EC_GROUP *ecgroup = NULL;
  EC_KEY *ec_key = NULL;
  const unsigned char* p_encoded_key = encoded_key;
  int rv = 0;

  /* I can't figure out how to import the EC key with the high-level EVP API: the d2i_* functions complain
     that the EC group is missing. If I set it manually (creating a group and using EC_KEY_set_group to set
     it on a EC_KEY and assign it to a EVP_PKEY, the group gets erased by EVP_PKEY_set_type inside the d2i_*
     functions. I therefore use lower-level functions for EC algs.
  */
  if ((ecgroup = EC_GROUP_new_by_curve_name(nid)) == NULL) {
    ECerr(0, ERR_R_FATAL);
    goto end;
  }

  if ((ec_key = EC_KEY_new()) == NULL ||
      !EC_KEY_set_group(ec_key, ecgroup)){
    ECerr(0, ERR_R_FATAL);
    goto end;
  }

  if (keytype == KEY_TYPE_PRIVATE) {
    if (d2i_ECPrivateKey(&ec_key, &p_encoded_key, key_len) == NULL) {
      ECerr(0, ERR_R_FATAL);
      goto end;
    }
  } else {
    if (o2i_ECPublicKey(&ec_key, &p_encoded_key, key_len) == NULL) {
      ECerr(0, ERR_R_FATAL);
      goto end;
    }
  }

  if ((oqs_key->classical_pkey = EVP_PKEY_new()) == NULL ||
      !EVP_PKEY_set_type(oqs_key->classical_pkey, NID_X9_62_id_ecPublicKey) ||
      !EVP_PKEY_assign_EC_KEY(oqs_key->classical_pkey, ec_key)) {
    ECerr(0, ERR_R_FATAL);
    goto end;
  }

  rv = 1; /* success */

 end:
  if (rv == 0 && ecgroup) EC_GROUP_free(ecgroup);
  if (rv == 0 && ec_key) EC_KEY_free(ec_key);
  return rv;
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
  if (key->classical_pkey) {
    EVP_PKEY_free(key->classical_pkey);
  }
  OPENSSL_free(key);
}


/*
 * Initializes a OQS_KEY, given an OpenSSL NID. This function only initializes
 * the post-quantum key, not the classical one (for hybrid schemes)
 */
static int oqs_key_init(OQS_KEY **p_oqs_key, int nid, oqs_key_type_t keytype) {
    OQS_KEY *oqs_key = NULL;
    const char* oqs_alg_name = get_oqs_alg_name(nid);

    oqs_key = OPENSSL_zalloc(sizeof(*oqs_key));
    if (oqs_key == NULL) {
      ECerr(0, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    oqs_key->nid = nid;
    oqs_key->s = OQS_SIG_new(oqs_alg_name);
    if (oqs_key->s == NULL) {
      /* TODO: Perhaps even check if the alg is available earlier in the stack. */
      ECerr(EC_F_OQS_KEY_INIT, EC_R_NO_SUCH_OQS_ALGORITHM);
      goto err;
    }
    oqs_key->pubkey = OPENSSL_malloc(oqs_key->s->length_public_key);
    if (oqs_key->pubkey == NULL) {
      ECerr(0, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    /* Optionally allocate the private key */
    if (keytype == KEY_TYPE_PRIVATE) {
      oqs_key->privkey = OPENSSL_secure_malloc(oqs_key->s->length_secret_key);
      if (oqs_key->privkey == NULL) {
        ECerr(EC_F_OQS_KEY_INIT, ERR_R_MALLOC_FAILURE);
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
    uint32_t pubkey_len = 0, max_classical_pubkey_len = 0, classical_pubkey_len = 0, index = 0;
    if (!oqs_key || !oqs_key->s || !oqs_key->pubkey ) {
      ECerr(EC_F_OQS_PUB_ENCODE, EC_R_KEY_NOT_SET);
      return 0;
    }
    int is_hybrid = (oqs_key->classical_pkey != NULL);

    /* determine the length of the key */
    pubkey_len = oqs_key->s->length_public_key;
    if (is_hybrid) {
      max_classical_pubkey_len = get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(oqs_key->nid));
      pubkey_len += (SIZE_OF_UINT32 + max_classical_pubkey_len);
    }
    penc = OPENSSL_malloc(pubkey_len);
    if (penc == NULL) {
      ECerr(EC_F_OQS_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
      return 0;
    }

    /* if hybrid, encode classical public key */
    if (is_hybrid) {
      unsigned char *classical_pubkey = penc + SIZE_OF_UINT32; /* i2d moves target pointer, so we copy into a temp var (leaving space for key len) */
      uint32_t actual_classical_pubkey_len = i2d_PublicKey(oqs_key->classical_pkey, &classical_pubkey);
      if (actual_classical_pubkey_len < 0 || actual_classical_pubkey_len > max_classical_pubkey_len) {
	/* something went wrong, or we didn't allocate enough space */
	OPENSSL_free(penc);
        ECerr(EC_F_OQS_PUB_ENCODE, ERR_R_FATAL);
        return 0;
      }
      ENCODE_UINT32(penc, actual_classical_pubkey_len);
      classical_pubkey_len = SIZE_OF_UINT32 + actual_classical_pubkey_len;
      index += classical_pubkey_len;
    }

    /* encode the pqc public key */
    memcpy(penc + index, oqs_key->pubkey, oqs_key->s->length_public_key);

    /* recalculate pub key len using actual classical key len */
    pubkey_len = classical_pubkey_len + oqs_key->s->length_public_key;

    if (!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id),
                                V_ASN1_UNDEF, NULL, penc, pubkey_len)) {
        OPENSSL_free(penc);
        ECerr(EC_F_OQS_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static int oqs_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen, max_pubkey_len;
    X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;
    int id = pkey->ameth->pkey_id;
    int is_hybrid = is_oqs_hybrid_alg(id);
    int index = 0;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey)) {
        return 0;
    }
    if (p == NULL) {
      /* pklen is checked below, after we instantiate the oqs_key to
	 learn the max len */
      ECerr(EC_F_OQS_PUB_DECODE, ERR_R_FATAL);
      return 0;
    }

    if (palg != NULL) {
      int ptype;

      /* Algorithm parameters must be absent */
      X509_ALGOR_get0(NULL, &ptype, NULL, palg);
      if (ptype != V_ASN1_UNDEF) {
        ECerr(EC_F_OQS_PUB_DECODE, EC_R_PARAMETERS_MUST_BE_ABSENT);
        return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, id, 0)) {
      ECerr(EC_F_OQS_PUB_DECODE, EC_R_KEY_INIT_FAILED);
      return 0;
    }

    max_pubkey_len = oqs_key->s->length_public_key;
    if (is_hybrid) {
      max_pubkey_len += (SIZE_OF_UINT32 + get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(id)));
    }

    if (pklen > max_pubkey_len) {
      ECerr(EC_F_OQS_PUB_DECODE, EC_R_WRONG_LENGTH);
      goto err;
    }

    /* if hybrid, decode classical public key */
    if (is_hybrid) {
      int classical_id = get_classical_nid(id);
      int actual_classical_pubkey_len;
      DECODE_UINT32(actual_classical_pubkey_len, p);
      if (is_EC_nid(classical_id)) {
	if (!decode_EC_key(KEY_TYPE_PUBLIC, classical_id, p + SIZE_OF_UINT32, actual_classical_pubkey_len, oqs_key)) {
	  ECerr(EC_F_OQS_PUB_DECODE, ERR_R_FATAL);
	  goto err;
	}
      } else {
	const unsigned char* pubkey_temp = p + SIZE_OF_UINT32;
	oqs_key->classical_pkey = d2i_PublicKey(classical_id, &oqs_key->classical_pkey, &pubkey_temp, actual_classical_pubkey_len);
	if (oqs_key->classical_pkey == NULL) {
	  ECerr(EC_F_OQS_PUB_DECODE, ERR_R_FATAL);
	  goto err;
	}
      }

      index += (SIZE_OF_UINT32 + actual_classical_pubkey_len);
    }
    /* decode PQC public key */
    memcpy(oqs_key->pubkey, p + index, oqs_key->s->length_public_key);

    EVP_PKEY_assign(pkey, id, oqs_key);
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
}

static int oqs_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const OQS_KEY *akey = (OQS_KEY*) a->pkey.ptr;
    const OQS_KEY *bkey = (OQS_KEY*) b->pkey.ptr;
    if (akey == NULL || bkey == NULL)
        return -2;

    /* compare hybrid classical key if present */
    if (akey->classical_pkey != NULL) {
      if (bkey->classical_pkey == NULL) {
	return 0; /* both should be hybrid or not */
      }
      if (!EVP_PKEY_cmp(akey->classical_pkey, bkey->classical_pkey)) {
	return 0;
      }
    }

    /* compare PQC key */
    return CRYPTO_memcmp(akey->pubkey, bkey->pubkey, akey->s->length_public_key) == 0;
}

static int oqs_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int plen, max_privkey_len;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;
    int id = pkey->ameth->pkey_id;
    int is_hybrid = is_oqs_hybrid_alg(id);
    int index = 0;

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
        ECerr(EC_F_OQS_PRIV_DECODE, ERR_R_FATAL);
        return 0;
      }
    }

    if (!oqs_key_init(&oqs_key, id, 1)) {
      ECerr(EC_F_OQS_PRIV_DECODE, EC_R_KEY_INIT_FAILED);
      return 0;
    }

    max_privkey_len = oqs_key->s->length_secret_key + oqs_key->s->length_public_key;
    if (is_hybrid) {
      max_privkey_len += (SIZE_OF_UINT32 + get_classical_key_len(KEY_TYPE_PRIVATE, get_classical_nid(oqs_key->nid)));
    }

    if (plen > max_privkey_len) {
      ECerr(EC_F_OQS_PRIV_DECODE, EC_R_KEY_LENGTH_WRONG);
      goto err;
    }

    /* if hybrid, decode classical private key */
    if (is_hybrid) {
      int classical_id = get_classical_nid(id);
      int actual_classical_privkey_len;
      DECODE_UINT32(actual_classical_privkey_len, p);
      if (is_EC_nid(classical_id)) {
	if (!decode_EC_key(KEY_TYPE_PRIVATE, classical_id, p + SIZE_OF_UINT32, actual_classical_privkey_len, oqs_key)) {
	  ECerr(EC_F_OQS_PRIV_DECODE, ERR_R_FATAL);
	  goto err;
	}
      } else {
	const unsigned char* privkey_temp = p + SIZE_OF_UINT32;
	oqs_key->classical_pkey = d2i_PrivateKey(classical_id, &oqs_key->classical_pkey, &privkey_temp, actual_classical_privkey_len);
	if (oqs_key->classical_pkey == NULL) {
	  ECerr(EC_F_OQS_PRIV_DECODE, ERR_R_FATAL);
	  goto err;
	}
      }
      index += (SIZE_OF_UINT32 + actual_classical_privkey_len);
    }
    /* decode private key */
    memcpy(oqs_key->privkey, p + index, oqs_key->s->length_secret_key);
    index += oqs_key->s->length_secret_key;

    /* decode public key */
    memcpy(oqs_key->pubkey, p + index, oqs_key->s->length_public_key);

    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, oqs_key);

    ASN1_OCTET_STRING_free(oct);
    return 1;

 err:
    oqs_pkey_ctx_free(oqs_key);
    return 0;
}

static int oqs_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    ASN1_OCTET_STRING oct;
    unsigned char *buf = NULL, *penc = NULL;
    uint32_t max_classical_privkey_len = 0, classical_privkey_len = 0;
    int buflen, penclen, index = 0;
    int rv = 0;

    if (!oqs_key || !oqs_key->s || !oqs_key->privkey ) {
      ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_FATAL);
      return rv;
    }
    int is_hybrid = (oqs_key->classical_pkey != NULL);

    /* determine the length of key */
    buflen = oqs_key->s->length_secret_key + oqs_key->s->length_public_key;
    if (is_hybrid) {
      max_classical_privkey_len = get_classical_key_len(KEY_TYPE_PRIVATE, get_classical_nid(oqs_key->nid));
      buflen += (SIZE_OF_UINT32 + max_classical_privkey_len);
    }
    buf = OPENSSL_secure_malloc(buflen);
    if (buf == NULL) {
      ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
      return rv;
    }

    /* if hybrid, encode classical private key */
    if (is_hybrid) {
      unsigned char *classical_privkey = buf + SIZE_OF_UINT32; /* i2d moves the target pointer, so we copy into a temp var (leaving space for key len) */
      int actual_classical_privkey_len = i2d_PrivateKey(oqs_key->classical_pkey, &classical_privkey);
      if (actual_classical_privkey_len < 0 || (uint32_t) actual_classical_privkey_len > max_classical_privkey_len) {
	/* something went wrong, or we didn't allocate enough space */
	OPENSSL_free(buf);
        ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_FATAL);
        goto end;
      }
      ENCODE_UINT32(buf, actual_classical_privkey_len);
      classical_privkey_len = SIZE_OF_UINT32 + actual_classical_privkey_len;
      index += classical_privkey_len;
    }

    /* encode the pqc private key */
    memcpy(buf + index, oqs_key->privkey, oqs_key->s->length_secret_key);
    index += oqs_key->s->length_secret_key;

    /* encode the pqc public key */
    memcpy(buf + index, oqs_key->pubkey, oqs_key->s->length_public_key);

    /* recalculate pub key len using acutal classical len */
    buflen = classical_privkey_len + oqs_key->s->length_secret_key + oqs_key->s->length_public_key;

    oct.data = buf;
    oct.length = buflen;
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
        ECerr(EC_F_OQS_PRIV_ENCODE, ERR_R_FATAL);
        goto end;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_secure_clear_free(buf, buflen);
        OPENSSL_clear_free(penc, penclen);
        ECerr(EC_F_OQS_PRIV_ENCODE, EC_R_SETTING_PARAMETERS_FAILED);
        goto end;
    }
    rv = 1; /* success */

 end:
    OPENSSL_secure_clear_free(buf, buflen);
    return rv;
}

static int oqs_size(const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    if (oqs_key == NULL || oqs_key->s == NULL) {
        ECerr(EC_F_OQS_SIZE, EC_R_NOT_INITIALIZED);
        return 0;
    }
    int sig_len = oqs_key->s->length_signature;
    if (is_oqs_hybrid_alg(oqs_key->nid)) {
      int classical_nid = get_classical_nid(oqs_key->nid);
      sig_len += (SIZE_OF_UINT32 + get_classical_sig_len(classical_nid));
    }
    return sig_len;
}

static int oqs_bits(const EVP_PKEY *pkey)
{
  OQS_KEY* oqs_key = (OQS_KEY*) pkey->pkey.ptr;
  int pubkey_len = oqs_key->s->length_public_key;
  if (is_oqs_hybrid_alg(oqs_key->nid)) {
    pubkey_len += (SIZE_OF_UINT32 + get_classical_key_len(KEY_TYPE_PUBLIC, get_classical_nid(oqs_key->nid)));
  }
  /* return size in bits */
  return CHAR_BIT * pubkey_len;
}

static int oqs_security_bits(const EVP_PKEY *pkey)
{
    return ((OQS_KEY*) pkey->pkey.ptr)->security_bits; /* already accounts for hybrid */
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
    const OQS_KEY *oqs_key = (OQS_KEY*) pkey->pkey.ptr;
    int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
    /* alg name to print, just keep the oqs part for hybrid */
    const char *nm = OBJ_nid2ln(is_hybrid ? get_oqs_nid(oqs_key->nid) : pkey->ameth->pkey_id);
    int classical_id;

    if (is_hybrid) {
      classical_id = get_classical_nid(oqs_key->nid);
    }

    if (keytype == KEY_TYPE_PRIVATE) {
        if (oqs_key == NULL || oqs_key->privkey == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
	if (is_hybrid) {
	  /* print classical private key */
	  if (is_EC_nid(classical_id)) {
	    eckey_asn1_meth.priv_print(bp, oqs_key->classical_pkey, indent, ctx);
	  } else if (classical_id == EVP_PKEY_RSA) {
	    rsa_asn1_meths[0].priv_print(bp, oqs_key->classical_pkey, indent, ctx);
	  }
	}

        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nm) <= 0)
            return 0;
        if (BIO_printf(bp, "%*spriv:\n", indent, "") <= 0)
            return 0;
        if (ASN1_buf_print(bp, oqs_key->privkey, oqs_key->s->length_secret_key,
                           indent + 4) == 0)
            return 0;
    } else {
        if (oqs_key == NULL) {
            if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
	if (is_hybrid) {
	  /* print classical public key */
	  if (is_EC_nid(classical_id)) {
	    eckey_asn1_meth.pub_print(bp, oqs_key->classical_pkey, indent, ctx);
	  } else if (classical_id == EVP_PKEY_RSA) {
	    rsa_asn1_meths[0].pub_print(bp, oqs_key->classical_pkey, indent, ctx);
	  }
	}
        if (BIO_printf(bp, "%*s%s Public-Key:\n", indent, "", nm) <= 0)
            return 0;
    }
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        return 0;

    if (ASN1_buf_print(bp, oqs_key->pubkey, oqs_key->s->length_public_key,
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
	 nid != NID_p256_picnicL1FS &&
	 nid != NID_rsa3072_picnicL1FS &&
	 nid != NID_qteslaI &&
	 nid != NID_p256_qteslaI &&
	 nid != NID_rsa3072_qteslaI &&
	 nid != NID_qteslaIIIsize &&
	 nid != NID_p384_qteslaIIIsize &&
	 nid != NID_qteslaIIIspeed &&
	 nid != NID_p384_qteslaIIIspeed
	 /* ADD_MORE_OQS_SIG_HERE */
	 ) || ptype != V_ASN1_UNDEF) {
        ECerr(EC_F_OQS_ITEM_VERIFY, EC_R_UNKNOWN_NID);
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
    int is_hybrid = is_oqs_hybrid_alg(id);
    int classical_id = 0;
    EVP_PKEY_CTX *param_ctx = NULL, *keygen_ctx = NULL;
    EVP_PKEY *param_pkey = NULL;
    const int rsa_size = 3072;
    int rv = 0;

    if (!oqs_key_init(&oqs_key, id, 1)) {
      ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
      goto end;
    }

    /* generate the classical key pair */
    if (is_hybrid) {
      classical_id = get_classical_nid(id);
      if (is_EC_nid(classical_id)) {
	if(!(param_ctx = EVP_PKEY_CTX_new_id(NID_X9_62_id_ecPublicKey, NULL)) ||
	   !EVP_PKEY_paramgen_init(param_ctx) ||
	   !EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, classical_id) ||
	   !EVP_PKEY_paramgen(param_ctx, &param_pkey)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
	  goto end;
	}
      }
      /* Generate key */
      if (param_pkey != NULL) {
	keygen_ctx = EVP_PKEY_CTX_new( param_pkey, NULL );
	EVP_PKEY_free(param_pkey);
      } else {
	keygen_ctx = EVP_PKEY_CTX_new_id( classical_id, NULL );
      }
      if (!keygen_ctx ||
	  !EVP_PKEY_keygen_init(keygen_ctx)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, EC_R_KEY_INIT_FAILED);
	  goto end;
      };

      if ( classical_id == EVP_PKEY_RSA ) {
	if(!EVP_PKEY_CTX_set_rsa_keygen_bits(keygen_ctx, rsa_size)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
	  goto end;
	}
      }
      if(!EVP_PKEY_keygen(keygen_ctx, &oqs_key->classical_pkey)) {
	  ECerr(EC_F_PKEY_OQS_KEYGEN, ERR_R_FATAL);
	  goto end;
      }
      EVP_PKEY_CTX_free(keygen_ctx);
      keygen_ctx = NULL;
    }

    /* generate PQC key pair */
    if (OQS_SIG_keypair(oqs_key->s, oqs_key->pubkey, oqs_key->privkey) != OQS_SUCCESS) {
      ECerr(EC_F_PKEY_OQS_KEYGEN, EC_R_KEYGEN_FAILED);
      goto end;
    }

    EVP_PKEY_assign(pkey, id, oqs_key);
    rv = 1; /* success */

 end:
    if (keygen_ctx) EVP_PKEY_CTX_free(keygen_ctx);
    if (oqs_key && rv == 0) oqs_pkey_ctx_free(oqs_key);
    return rv;
}

static int pkey_oqs_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;
    EVP_PKEY_CTX *classical_ctx_sign = NULL;

    int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
    int classical_id = 0;
    size_t max_sig_len = oqs_key->s->length_signature;
    size_t classical_sig_len = 0, oqs_sig_len = 0;
    size_t actual_classical_sig_len = 0;
    size_t index = 0;
    int rv = 0;

    if (!oqs_key || !oqs_key->s || !oqs_key->privkey || (is_hybrid && !oqs_key->classical_pkey)) {
      ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_NO_PRIVATE_KEY);
      return rv;
    }
    if (is_hybrid) {
      classical_id = get_classical_nid(oqs_key->nid);
      actual_classical_sig_len = get_classical_sig_len(classical_id);
      max_sig_len += (SIZE_OF_UINT32 + actual_classical_sig_len);
    }

    if (sig == NULL) {
      /* we only return the sig len */
      *siglen = max_sig_len;
      return 1;
    }
    if (*siglen < max_sig_len) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_BUFFER_LENGTH_WRONG);
        return rv;
    }

    if (is_hybrid) {
      const EVP_MD *classical_md;
      int digest_len;
      unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

      if ((classical_ctx_sign = EVP_PKEY_CTX_new(oqs_key->classical_pkey, NULL)) == NULL ||
	  EVP_PKEY_sign_init(classical_ctx_sign) <= 0) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, ERR_R_FATAL);
        goto end;
      }
      if (classical_id == EVP_PKEY_RSA) {
	if (EVP_PKEY_CTX_set_rsa_padding(classical_ctx_sign, RSA_PKCS1_PADDING) <= 0) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, ERR_R_FATAL);
        goto end;
	}
      }

      /* classical schemes can't sign arbitrarily large data; we hash it first */
      switch (oqs_key->s->claimed_nist_level) {
      case 1:
	classical_md = EVP_sha256();
	digest_len = SHA256_DIGEST_LENGTH;
	SHA256(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 2:
      case 3:
	classical_md = EVP_sha384();
	digest_len = SHA384_DIGEST_LENGTH;
	SHA384(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 4:
      case 5:
      default:
	classical_md = EVP_sha512();
	digest_len = SHA512_DIGEST_LENGTH;
	SHA512(tbs, tbslen, (unsigned char*) &digest);
	break;
      }
      if (EVP_PKEY_CTX_set_signature_md(classical_ctx_sign, classical_md) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTSIGN, ERR_R_FATAL);
	goto end;
      }
      if (EVP_PKEY_sign(classical_ctx_sign, sig + SIZE_OF_UINT32, &actual_classical_sig_len, digest, digest_len) <= 0) {
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_SIGNING_FAILED);
        goto end;
      }
      if (actual_classical_sig_len > (size_t) get_classical_sig_len(classical_id)) {
	/* sig is bigger than expected! */
        ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_BUFFER_LENGTH_WRONG);
        goto end;
      }
      ENCODE_UINT32(sig, actual_classical_sig_len);
      classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
      index += classical_sig_len;
    }

    if (OQS_SIG_sign(oqs_key->s, sig + index, &oqs_sig_len, tbs, tbslen, oqs_key->privkey) != OQS_SUCCESS) {
      ECerr(EC_F_PKEY_OQS_DIGESTSIGN, EC_R_SIGNING_FAILED);
      return 0;
    }
    *siglen = classical_sig_len + oqs_sig_len;

    rv = 1; /* success */

 end:
    if (classical_ctx_sign) {
      EVP_PKEY_CTX_free(classical_ctx_sign);
    }
    return rv;
}

static int pkey_oqs_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;
    int is_hybrid = is_oqs_hybrid_alg(oqs_key->nid);
    int classical_id = 0;
    size_t classical_sig_len = 0;
    size_t index = 0;

    if (!oqs_key || !oqs_key->s  || !oqs_key->pubkey || (is_hybrid && !oqs_key->classical_pkey) ||
	sig == NULL || tbs == NULL) {
      ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, EC_R_WRONG_PARAMETERS);
      return 0;
    }

    if (is_hybrid) {
      classical_id = get_classical_nid(oqs_key->nid);
    }

    if (is_hybrid) {
      EVP_PKEY_CTX *ctx_verify = NULL;
      const EVP_MD *classical_md;
      size_t actual_classical_sig_len = 0;
      int digest_len;
      unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max length */

      if ((ctx_verify = EVP_PKEY_CTX_new(oqs_key->classical_pkey, NULL)) == NULL ||
	  EVP_PKEY_verify_init(ctx_verify) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, ERR_R_FATAL);
	EVP_PKEY_CTX_free(ctx_verify);
	return 0;
      }
      if (classical_id == EVP_PKEY_RSA) {
	if (EVP_PKEY_CTX_set_rsa_padding(ctx_verify, RSA_PKCS1_PADDING) <= 0) {
	  ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, ERR_R_FATAL);
	  EVP_PKEY_CTX_free(ctx_verify);
	  return 0;
	}
      }
      DECODE_UINT32(actual_classical_sig_len, sig);
      /* classical schemes can't sign arbitrarily large data; we hash it first */
      switch (oqs_key->s->claimed_nist_level) {
      case 1:
	classical_md = EVP_sha256();
	digest_len = SHA256_DIGEST_LENGTH;
	SHA256(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 2:
      case 3:
	classical_md = EVP_sha384();
	digest_len = SHA384_DIGEST_LENGTH;
	SHA384(tbs, tbslen, (unsigned char*) &digest);
	break;
      case 4:
      case 5:
      default:
	classical_md = EVP_sha512();
	digest_len = SHA512_DIGEST_LENGTH;
	SHA512(tbs, tbslen, (unsigned char*) &digest);
	break;
      }
      if (EVP_PKEY_CTX_set_signature_md(ctx_verify, classical_md) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, ERR_R_FATAL);
	return 0;
      }
      if (EVP_PKEY_verify(ctx_verify, sig + SIZE_OF_UINT32, actual_classical_sig_len, digest, digest_len) <= 0) {
	ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, EC_R_VERIFICATION_FAILED);
	return 0;
      }
      classical_sig_len = SIZE_OF_UINT32 + actual_classical_sig_len;
      index += classical_sig_len;
      EVP_PKEY_CTX_free(ctx_verify);
    }

    if (OQS_SIG_verify(oqs_key->s, tbs, tbslen, sig + index, siglen - classical_sig_len, oqs_key->pubkey) != OQS_SUCCESS) {
      ECerr(EC_F_PKEY_OQS_DIGESTVERIFY, EC_R_VERIFICATION_FAILED);
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
        ECerr(EC_F_PKEY_OQS_CTRL, EC_R_WRONG_DIGEST);
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
DEFINE_OQS_EVP_METHODS(qteslaI, NID_qteslaI, "qteslaI", "OpenSSL qTESLA-I algorithm")
DEFINE_OQS_EVP_METHODS(qteslaIIIsize, NID_qteslaIIIsize, "qteslaIIIsize", "OpenSSL qTESLA-III-size algorithm")
DEFINE_OQS_EVP_METHODS(qteslaIIIspeed, NID_qteslaIIIspeed, "qteslaIIIspeed", "OpenSSL qTESLA-III-speed algorithm")
/* ADD_MORE_OQS_SIG_HERE */
/* hybrid schemes */
DEFINE_OQS_EVP_METHODS(p256_picnicL1FS, NID_p256_picnicL1FS, "p256_picnicL1FS", "OpenSSL hybrid p256 Picnic L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(rsa3072_picnicL1FS, NID_rsa3072_picnicL1FS, "rsa3072_picnicL1FS", "OpenSSL hybrid RSA3072 Picnic L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(p256_qteslaI, NID_p256_qteslaI, "p256_qteslaI", "OpenSSL hybrid p256 qTESLA-I algorithm")
DEFINE_OQS_EVP_METHODS(rsa3072_qteslaI, NID_rsa3072_qteslaI, "rsa3072_qteslaI", "OpenSSL hybrid RSA3072 qTESLA-I algorithm")
DEFINE_OQS_EVP_METHODS(p384_qteslaIIIsize, NID_p384_qteslaIIIsize, "p384_qteslaIIIsize", "OpenSSL hybrid p384 qTESLA-III-size algorithm")
DEFINE_OQS_EVP_METHODS(p384_qteslaIIIspeed, NID_p384_qteslaIIIspeed, "p384_qteslaIIIspeed", "OpenSSL hybrid p384 qTESLA-III-speed algorithm")
/* ADD_MORE_OQS_SIG_HERE hybrid only */

#endif /* !defined(OQS_NIST_BRANCH) */
