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
#include "crypto/asn1.h"
#include "crypto/evp.h"

#include <openssl/cms.h>

#include <oqs/oqs.h>

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
  /* digest engine for CMS: */
  EVP_MD_CTX * digest;
} OQS_KEY;

/*
 * OQS key type
 */
typedef enum {
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} oqs_key_type_t;

int oqssl_sig_nids_list[] = {
///// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_NIDS_START
        NID_oqs_sig_default,
        NID_p256_oqs_sig_default,
        NID_rsa3072_oqs_sig_default,
        NID_dilithium2,
        NID_p256_dilithium2,
        NID_rsa3072_dilithium2,
        NID_dilithium3,
        NID_dilithium4,
        NID_p384_dilithium4,
        NID_picnicl1fs,
        NID_p256_picnicl1fs,
        NID_rsa3072_picnicl1fs,
        NID_picnic2l1fs,
        NID_p256_picnic2l1fs,
        NID_rsa3072_picnic2l1fs,
        NID_qteslapi,
        NID_p256_qteslapi,
        NID_rsa3072_qteslapi,
        NID_qteslapiii,
        NID_p384_qteslapiii
/////// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_NIDS_END
};

int oqssl_kem_nids_list[] = {
///// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_KEM_NIDS_START
        NID_frodo640aes,
        NID_frodo640shake,
        NID_frodo976aes,
        NID_frodo976shake,
        NID_frodo1344aes,
        NID_frodo1344shake,
        NID_bike1l1cpa,
        NID_bike1l3cpa,
        NID_bike1l1fo,
        NID_bike1l3fo,
        NID_kyber512,
        NID_kyber768,
        NID_kyber1024,
        NID_newhope512cca,
        NID_newhope1024cca,
        NID_ntru_hps2048509,
        NID_ntru_hps2048677,
        NID_ntru_hps4096821,
        NID_ntru_hrss701,
        NID_lightsaber,
        NID_saber,
        NID_firesaber,
        NID_sidhp434,
        NID_sidhp503,
        NID_sidhp610,
        NID_sidhp751,
        NID_sikep434,
        NID_sikep503,
        NID_sikep610,
        NID_sikep751,
        NID_ledacryptkemlt12,
        NID_ledacryptkemlt32,
        NID_ledacryptkemlt52,
        NID_kyber90s512,
        NID_kyber90s768,
        NID_kyber90s1024,
        NID_babybear,
        NID_mamabear,
        NID_papabear,
        NID_babybearephem,
        NID_mamabearephem,
        NID_papabearephem,
/////// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_KEM_NIDS_END
};

static int* sig_nid_list = NULL;
static int* kem_nid_list = NULL;

int* get_oqssl_sig_nids() {
   if (!sig_nid_list) {
      sig_nid_list = OPENSSL_malloc(sizeof(oqssl_sig_nids_list));
      memcpy(sig_nid_list, oqssl_sig_nids_list, sizeof(oqssl_sig_nids_list));
   }
   return sig_nid_list;
}

int* get_oqssl_kem_nids() {
   if (!kem_nid_list) {
      kem_nid_list = OPENSSL_malloc(sizeof(oqssl_kem_nids_list));
      memcpy(kem_nid_list, oqssl_kem_nids_list, sizeof(oqssl_kem_nids_list));
   }
   return kem_nid_list;
}

/*
 * Maps OpenSSL NIDs to OQS IDs
 */
char* get_oqs_alg_name(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_START
    case NID_oqs_sig_default:
    case NID_p256_oqs_sig_default:
    case NID_rsa3072_oqs_sig_default:
      return OQS_SIG_alg_default;
    case NID_dilithium2:
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
      return OQS_SIG_alg_dilithium_2;
    case NID_dilithium3:
      return OQS_SIG_alg_dilithium_3;
    case NID_dilithium4:
    case NID_p384_dilithium4:
      return OQS_SIG_alg_dilithium_4;
    case NID_picnicl1fs:
    case NID_p256_picnicl1fs:
    case NID_rsa3072_picnicl1fs:
      return OQS_SIG_alg_picnic_L1_FS;
    case NID_picnic2l1fs:
    case NID_p256_picnic2l1fs:
    case NID_rsa3072_picnic2l1fs:
      return OQS_SIG_alg_picnic2_L1_FS;
    case NID_qteslapi:
    case NID_p256_qteslapi:
    case NID_rsa3072_qteslapi:
      return OQS_SIG_alg_qTesla_p_I;
    case NID_qteslapiii:
    case NID_p384_qteslapiii:
      return OQS_SIG_alg_qTesla_p_III;
    case NID_oqs_kem_default:
      return OQS_KEM_alg_default;
    case NID_frodo640aes:
    case NID_p256_frodo640aes:
      return OQS_KEM_alg_frodokem_640_aes;
    case NID_frodo640shake:
    case NID_p256_frodo640shake:
      return OQS_KEM_alg_frodokem_640_shake;
    case NID_frodo976aes:
    case NID_p256_frodo976aes:
      return OQS_KEM_alg_frodokem_976_aes;
    case NID_frodo976shake:
    case NID_p256_frodo976shake:
      return OQS_KEM_alg_frodokem_976_shake;
    case NID_frodo1344aes:
    case NID_p256_frodo1344aes:
      return OQS_KEM_alg_frodokem_1344_aes;
    case NID_frodo1344shake:
    case NID_p256_frodo1344shake:
      return OQS_KEM_alg_frodokem_1344_shake;
    case NID_bike1l1cpa:
    case NID_p256_bike1l1cpa:
      return OQS_KEM_alg_bike1_l1_cpa;
    case NID_bike1l3cpa:
    case NID_p256_bike1l3cpa:
      return OQS_KEM_alg_bike1_l3_cpa;
    case NID_bike1l1fo:
    case NID_p256_bike1l1fo:
      return OQS_KEM_alg_bike1_l1_fo;
    case NID_bike1l3fo:
    case NID_p256_bike1l3fo:
      return OQS_KEM_alg_bike1_l3_fo;
    case NID_kyber512:
    case NID_p256_kyber512:
      return OQS_KEM_alg_kyber_512;
    case NID_kyber768:
    case NID_p256_kyber768:
      return OQS_KEM_alg_kyber_768;
    case NID_kyber1024:
    case NID_p256_kyber1024:
      return OQS_KEM_alg_kyber_1024;
    case NID_newhope512cca:
    case NID_p256_newhope512cca:
      return OQS_KEM_alg_newhope_512cca;
    case NID_newhope1024cca:
    case NID_p256_newhope1024cca:
      return OQS_KEM_alg_newhope_1024cca;
    case NID_ntru_hps2048509:
    case NID_p256_ntru_hps2048509:
      return OQS_KEM_alg_ntru_hps2048509;
    case NID_ntru_hps2048677:
    case NID_p256_ntru_hps2048677:
      return OQS_KEM_alg_ntru_hps2048677;
    case NID_ntru_hps4096821:
    case NID_p256_ntru_hps4096821:
      return OQS_KEM_alg_ntru_hps4096821;
    case NID_ntru_hrss701:
    case NID_p256_ntru_hrss701:
      return OQS_KEM_alg_ntru_hrss701;
    case NID_lightsaber:
    case NID_p256_lightsaber:
      return OQS_KEM_alg_saber_lightsaber;
    case NID_saber:
    case NID_p256_saber:
      return OQS_KEM_alg_saber_saber;
    case NID_firesaber:
    case NID_p256_firesaber:
      return OQS_KEM_alg_saber_firesaber;
    case NID_sidhp434:
    case NID_p256_sidhp434:
      return OQS_KEM_alg_sidh_p434;
    case NID_sidhp503:
    case NID_p256_sidhp503:
      return OQS_KEM_alg_sidh_p503;
    case NID_sidhp610:
    case NID_p256_sidhp610:
      return OQS_KEM_alg_sidh_p610;
    case NID_sidhp751:
    case NID_p256_sidhp751:
      return OQS_KEM_alg_sidh_p751;
    case NID_sikep434:
    case NID_p256_sikep434:
      return OQS_KEM_alg_sike_p434;
    case NID_sikep503:
    case NID_p256_sikep503:
      return OQS_KEM_alg_sike_p503;
    case NID_sikep610:
    case NID_p256_sikep610:
      return OQS_KEM_alg_sike_p610;
    case NID_sikep751:
    case NID_p256_sikep751:
      return OQS_KEM_alg_sike_p751;
    case NID_ledacryptkemlt12:
    case NID_p256_ledacryptkemlt12:
      return OQS_KEM_alg_ledacrypt_ledakemlt12;
    case NID_ledacryptkemlt32:
    case NID_p256_ledacryptkemlt32:
      return OQS_KEM_alg_ledacrypt_ledakemlt32;
    case NID_ledacryptkemlt52:
    case NID_p256_ledacryptkemlt52:
      return OQS_KEM_alg_ledacrypt_ledakemlt52;
    case NID_kyber90s512:
    case NID_p256_kyber90s512:
      return OQS_KEM_alg_kyber_512_90s;
    case NID_kyber90s768:
    case NID_p256_kyber90s768:
      return OQS_KEM_alg_kyber_768_90s;
    case NID_kyber90s1024:
    case NID_p256_kyber90s1024:
      return OQS_KEM_alg_kyber_1024_90s;
    case NID_babybear:
    case NID_p256_babybear:
      return OQS_KEM_alg_threebears_babybear;
    case NID_mamabear:
    case NID_p256_mamabear:
      return OQS_KEM_alg_threebears_mamabear;
    case NID_papabear:
    case NID_p256_papabear:
      return OQS_KEM_alg_threebears_papabear;
    case NID_babybearephem:
    case NID_p256_babybearephem:
      return OQS_KEM_alg_threebears_babybear_ephem;
    case NID_mamabearephem:
    case NID_p256_mamabearephem:
      return OQS_KEM_alg_threebears_mamabear_ephem;
    case NID_papabearephem:
    case NID_p256_papabearephem:
      return OQS_KEM_alg_threebears_papabear_ephem;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_END
    default:
      return NULL;
  }
}

static int is_oqs_hybrid_alg(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_START
    case NID_p256_oqs_sig_default:
    case NID_rsa3072_oqs_sig_default:
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
    case NID_p384_dilithium4:
    case NID_p256_picnicl1fs:
    case NID_rsa3072_picnicl1fs:
    case NID_p256_picnic2l1fs:
    case NID_rsa3072_picnic2l1fs:
    case NID_p256_qteslapi:
    case NID_rsa3072_qteslapi:
    case NID_p384_qteslapiii:
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_NIDS_END
      return 1;
    default:
      return 0;
  }
}


static int get_classical_nid(int hybrid_id)
{
  switch (hybrid_id)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_START
    case NID_rsa3072_oqs_sig_default:
    case NID_rsa3072_dilithium2:
    case NID_rsa3072_picnicl1fs:
    case NID_rsa3072_picnic2l1fs:
    case NID_rsa3072_qteslapi:
      return NID_rsaEncryption;
    case NID_p256_oqs_sig_default:
    case NID_p256_dilithium2:
    case NID_p256_picnicl1fs:
    case NID_p256_picnic2l1fs:
    case NID_p256_qteslapi:
      return NID_X9_62_prime256v1;
    case NID_p384_dilithium4:
    case NID_p384_qteslapiii:
      return NID_secp384r1;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_CLASSICAL_NIDS_END
    default:
      return 0;
  }
}

static int get_oqs_nid(int hybrid_id)
{
  switch (hybrid_id)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_OQS_NID_START
    case NID_p256_oqs_sig_default:
    case NID_rsa3072_oqs_sig_default:
      return NID_oqs_sig_default;
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
      return NID_dilithium2;
      return NID_dilithium3;
    case NID_p384_dilithium4:
      return NID_dilithium4;
    case NID_p256_picnicl1fs:
    case NID_rsa3072_picnicl1fs:
      return NID_picnicl1fs;
    case NID_p256_picnic2l1fs:
    case NID_rsa3072_picnic2l1fs:
      return NID_picnic2l1fs;
    case NID_p256_qteslapi:
    case NID_rsa3072_qteslapi:
      return NID_qteslapi;
    case NID_p384_qteslapiii:
      return NID_qteslapiii;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_OQS_NID_END
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
      return 0;
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
      return 0;
    }
}

/*
 * Returns options when running OQS KEM, e.g., in openssl speed
 */
const char *OQSKEM_options(void)
{
    int offset;
// TODO: Revisit which OQS_COMPILE_FLAGS to show
#ifdef OQS_COMPILE_CFLAGS
    const char* OQSKEMALGS = "OQS KEM build : ";
    char* result =  OPENSSL_zalloc(strlen(OQS_COMPILE_CFLAGS)+OQS_OPENSSL_KEM_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSKEMALGS, offset = strlen(OQSKEMALGS));
    memcpy(result+offset, OQS_COMPILE_CFLAGS, strlen(OQS_COMPILE_CFLAGS));
    offset += strlen(OQS_COMPILE_CFLAGS);
#else 
    const char* OQSKEMALGS = "";
    char* result =  OPENSSL_zalloc(OQS_OPENSSL_KEM_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSKEMALGS, offset = strlen(OQSKEMALGS));
#endif

    result[offset++]='-';
    int i;
    for (i=0; i<OQS_OPENSSL_KEM_algs_length;i++) {
       const char* name = OBJ_nid2sn(oqssl_kem_nids_list[i]);
       if (OQS_KEM_alg_is_enabled(get_oqs_alg_name(oqssl_kem_nids_list[i]))) {
           int l = strlen(name);
           memcpy(result+offset, name, l);
           if (i<OQS_OPENSSL_KEM_algs_length-1) {
              result[offset+l]=',';
              offset = offset+l+1;
           }
       }
    }
    return result;
}

/*
 * Returns options when running OQS SIG, e.g., in openssl speed
 */
const char *OQSSIG_options(void)
{
    int offset;
// TODO: Revisit which OQS_COMPILE_FLAGS to show
#ifdef OQS_COMPILE_CFLAGS
    const char* OQSSIGALGS = "OQS SIG build : ";
    char* result =  OPENSSL_zalloc(strlen(OQS_COMPILE_CFLAGS)+OQS_OPENSSL_SIG_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSSIGALGS, offset = strlen(OQSSIGALGS));
    memcpy(result+offset, OQS_COMPILE_CFLAGS, strlen(OQS_COMPILE_CFLAGS));
    offset += strlen(OQS_COMPILE_CFLAGS);
#else
    const char* OQSSIGALGS = "";
    char* result =  OPENSSL_zalloc(OQS_OPENSSL_SIG_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSSIGALGS, offset = strlen(OQSSIGALGS));
#endif

    result[offset++]='-';
    int i;
    for (i=0; i<OQS_OPENSSL_SIG_algs_length;i++) {
       const char* name = OBJ_nid2sn(oqssl_sig_nids_list[i]);
       if (OQS_SIG_alg_is_enabled(get_oqs_alg_name(oqssl_sig_nids_list[i]))) {
           int l = strlen(name);
           memcpy(result+offset, name, l);
           if (i<OQS_OPENSSL_SIG_algs_length-1) {
              result[offset+l]=',';
              offset = offset+l+1;
           }
       }
    }
    return result;
}

/*
 * Returns the security level in bits for an OQS alg.
 */
static int get_oqs_security_bits(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_GET_SIG_SECURITY_BITS_START
    case NID_oqs_sig_default:
    case NID_p256_oqs_sig_default:
    case NID_rsa3072_oqs_sig_default:
      return 128;
    case NID_dilithium2:
    case NID_p256_dilithium2:
    case NID_rsa3072_dilithium2:
      return 128;
    case NID_dilithium3:
      return 128;
    case NID_dilithium4:
    case NID_p384_dilithium4:
      return 192;
    case NID_picnicl1fs:
    case NID_p256_picnicl1fs:
    case NID_rsa3072_picnicl1fs:
      return 128;
    case NID_picnic2l1fs:
    case NID_p256_picnic2l1fs:
    case NID_rsa3072_picnic2l1fs:
      return 128;
    case NID_qteslapi:
    case NID_p256_qteslapi:
    case NID_rsa3072_qteslapi:
      return 128;
    case NID_qteslapiii:
    case NID_p384_qteslapiii:
      return 192;
///// OQS_TEMPLATE_FRAGMENT_GET_SIG_SECURITY_BITS_END
    default:
      return 0;
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
    if (!OQS_SIG_alg_is_enabled(oqs_alg_name))
      fprintf(stderr, "Warning: OQS algorithm '%s' not enabled.\n", oqs_alg_name);
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

int oqs_size(const EVP_PKEY *pkey)
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
    (
///// OQS_TEMPLATE_FRAGMENT_CHECK_IF_KNOWN_NID_START
        nid != NID_oqs_sig_default &&
        nid != NID_p256_oqs_sig_default &&
        nid != NID_rsa3072_oqs_sig_default &&
        nid != NID_dilithium2 &&
        nid != NID_p256_dilithium2 &&
        nid != NID_rsa3072_dilithium2 &&
        nid != NID_dilithium3 &&
        nid != NID_dilithium4 &&
        nid != NID_p384_dilithium4 &&
        nid != NID_picnicl1fs &&
        nid != NID_p256_picnicl1fs &&
        nid != NID_rsa3072_picnicl1fs &&
        nid != NID_picnic2l1fs &&
        nid != NID_p256_picnic2l1fs &&
        nid != NID_rsa3072_picnic2l1fs &&
        nid != NID_qteslapi &&
        nid != NID_p256_qteslapi &&
        nid != NID_rsa3072_qteslapi &&
        nid != NID_qteslapiii &&
        nid != NID_p384_qteslapiii
///// OQS_TEMPLATE_FRAGMENT_CHECK_IF_KNOWN_NID_END
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
    X509_SIG_INFO_set(siginf, NID_sha512, NID_ALG, get_oqs_security_bits(NID_ALG),\
                      X509_SIG_INFO_TLS);                                        \
    return 1;                                                                    \
}

int oqs_ameth_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2) {
   switch (op) {
   case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
	*(int *)arg2 = NID_sha512;
	return 1;
   case ASN1_PKEY_CTRL_CMS_SIGN:
      if (arg1 == 0) {
            int snid, hnid;
            X509_ALGOR *alg1, *alg2;
            CMS_SignerInfo_get0_algs(arg2, NULL, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL) {
                return -1;
	    }
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef) {
                return -1;
            }
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey))) {
                return -1;
            }
            X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
      }

      return 1;
   }
   ECerr(EC_F_PKEY_OQS_CTRL, ERR_R_FATAL);
   return 0;
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
    oqs_ameth_pkey_ctrl,                       \
    0, 0,                                      \
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
        /* NULL allowed as digest */
        if (p2 == NULL)
            return 1;
        /* accept SHA512 as digest for CMS */
        if (*(int*)p2 == NID_sha512) {
               return 1;
        }
        ECerr(EC_F_PKEY_OQS_CTRL, EC_R_WRONG_DIGEST);
        return 0;

    case EVP_PKEY_CTRL_DIGESTINIT:
        return 1;

    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;
    }
    ECerr(EC_F_PKEY_OQS_CTRL, ERR_R_FATAL);
    return -2;
}

static int pkey_oqs_sign_init(EVP_PKEY_CTX *ctx) {
   return 1;
}

static int pkey_oqs_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen)
{
   return 1;
}

static int oqs_int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(ctx)->pkey->pkey.ptr;

    if (oqs_key->digest == NULL) {
        if ((oqs_key->digest = EVP_MD_CTX_create()) == NULL) {
           return 0;
        }

        if (EVP_DigestInit_ex(oqs_key->digest, EVP_sha512(), NULL) <= 0) {
           return 0;
        }
    }

    if(EVP_DigestUpdate(oqs_key->digest, data, count)<=0) {
	return 0;
    }
    return 1;
}

static int pkey_oqs_signctx_init (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {

    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_update_fn(mctx, oqs_int_update);

    return 1;
}

static int pkey_oqs_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx) {
    OQS_KEY *oqs_key = (OQS_KEY*) EVP_MD_CTX_pkey_ctx(mctx)->pkey->pkey.ptr;
    unsigned char* tbs = NULL;
    unsigned int tbslen = 0;


    if (sig != NULL) {
       tbslen = 512/8; // as per https://tools.ietf.org/id/draft-ietf-lamps-cms-shakes-08.html
       // Finalize SHAKE:
       if (oqs_key->digest == NULL) {
         return 0;
       }

       if((tbs = (unsigned char *)OPENSSL_malloc(tbslen)) == NULL) {
         return 0;
       }

       if(EVP_DigestFinal(oqs_key->digest, tbs, &tbslen) <= 0) {
         return 0;
       }

    }
    int ret = pkey_oqs_digestsign(mctx, sig, siglen, tbs, tbslen);
    if (sig != NULL) { // cleanup only if it's not the empty setup call
       OPENSSL_free(tbs);
       EVP_MD_CTX_destroy(oqs_key->digest);
       oqs_key->digest = NULL;
    }
    if (ret <= 0) {
    }
    else {
       EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE); // don't go around again...
    }

   return ret;
}

static int pkey_oqs_digestcustom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
   return 1;
}

static int pkey_oqs_verify_init(EVP_PKEY_CTX *ctx) {
   return 1;
}

static int pkey_oqs_verify(EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen) {
   return 1;
}
static int pkey_oqs_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {

   EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
   EVP_MD_CTX_set_update_fn(mctx, oqs_int_update);
   EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE); // don't go around again...
   return 1;
}

static int pkey_oqs_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx) {
   return 1;
}

#define DEFINE_OQS_EVP_PKEY_METHOD(ALG, NID_ALG)    \
const EVP_PKEY_METHOD ALG##_pkey_meth = {           \
    NID_ALG, EVP_PKEY_FLAG_SIGCTX_CUSTOM,           \
    0, 0, 0, 0, 0, 0,                               \
    pkey_oqs_keygen,                                \
    pkey_oqs_sign_init, pkey_oqs_sign,              \
    pkey_oqs_verify_init, pkey_oqs_verify,          \
    0, 0,                                           \
    pkey_oqs_signctx_init, pkey_oqs_signctx,        \
    pkey_oqs_verifyctx_init, pkey_oqs_verifyctx,    \
    0, 0, 0, 0, 0, 0,                               \
    pkey_oqs_ctrl,                                  \
    0,                                              \
    pkey_oqs_digestsign,                            \
    pkey_oqs_digestverify,                          \
    0, 0, 0,                                        \
    pkey_oqs_digestcustom                           \
};

#define DEFINE_OQS_EVP_METHODS(ALG, NID_ALG, SHORT_NAME, LONG_NAME)   \
DEFINE_OQS_ITEM_SIGN(ALG, NID_ALG)                                    \
DEFINE_OQS_SIGN_INFO_SET(ALG, NID_ALG)                                \
DEFINE_OQS_EVP_PKEY_METHOD(ALG, NID_ALG)                              \
DEFINE_OQS_EVP_PKEY_ASN1_METHOD(ALG, NID_ALG, SHORT_NAME, LONG_NAME)
///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_EVP_METHS_START
DEFINE_OQS_EVP_METHODS(oqs_sig_default, NID_oqs_sig_default, "oqs_sig_default", "OpenSSL OQS Default Signature Algorithm algorithm")
DEFINE_OQS_EVP_METHODS(p256_oqs_sig_default, NID_p256_oqs_sig_default, "p256_oqs_sig_default", "OpenSSL ECDSA p256 OQS Default Signature Algorithm algorithm")
DEFINE_OQS_EVP_METHODS(rsa3072_oqs_sig_default, NID_rsa3072_oqs_sig_default, "rsa3072_oqs_sig_default", "OpenSSL RSA3072 OQS Default Signature Algorithm algorithm")
DEFINE_OQS_EVP_METHODS(dilithium2, NID_dilithium2, "dilithium2", "OpenSSL Dilithium-2 algorithm")
DEFINE_OQS_EVP_METHODS(p256_dilithium2, NID_p256_dilithium2, "p256_dilithium2", "OpenSSL ECDSA p256 Dilithium-2 algorithm")
DEFINE_OQS_EVP_METHODS(rsa3072_dilithium2, NID_rsa3072_dilithium2, "rsa3072_dilithium2", "OpenSSL RSA3072 Dilithium-2 algorithm")
DEFINE_OQS_EVP_METHODS(dilithium3, NID_dilithium3, "dilithium3", "OpenSSL Dilithium-3 algorithm")
DEFINE_OQS_EVP_METHODS(dilithium4, NID_dilithium4, "dilithium4", "OpenSSL Dilithium-4 algorithm")
DEFINE_OQS_EVP_METHODS(p384_dilithium4, NID_p384_dilithium4, "p384_dilithium4", "OpenSSL ECDSA p384 Dilithium-4 algorithm")
DEFINE_OQS_EVP_METHODS(picnicl1fs, NID_picnicl1fs, "picnicl1fs", "OpenSSL Picnic L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(p256_picnicl1fs, NID_p256_picnicl1fs, "p256_picnicl1fs", "OpenSSL ECDSA p256 Picnic L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(rsa3072_picnicl1fs, NID_rsa3072_picnicl1fs, "rsa3072_picnicl1fs", "OpenSSL RSA3072 Picnic L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(picnic2l1fs, NID_picnic2l1fs, "picnic2l1fs", "OpenSSL Picnic2 L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(p256_picnic2l1fs, NID_p256_picnic2l1fs, "p256_picnic2l1fs", "OpenSSL ECDSA p256 Picnic2 L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(rsa3072_picnic2l1fs, NID_rsa3072_picnic2l1fs, "rsa3072_picnic2l1fs", "OpenSSL RSA3072 Picnic2 L1 FS algorithm")
DEFINE_OQS_EVP_METHODS(qteslapi, NID_qteslapi, "qteslapi", "OpenSSL qTesla-I-p algorithm")
DEFINE_OQS_EVP_METHODS(p256_qteslapi, NID_p256_qteslapi, "p256_qteslapi", "OpenSSL ECDSA p256 qTesla-I-p algorithm")
DEFINE_OQS_EVP_METHODS(rsa3072_qteslapi, NID_rsa3072_qteslapi, "rsa3072_qteslapi", "OpenSSL RSA3072 qTesla-I-p algorithm")
DEFINE_OQS_EVP_METHODS(qteslapiii, NID_qteslapiii, "qteslapiii", "OpenSSL qTESLA-p-III algorithm")
DEFINE_OQS_EVP_METHODS(p384_qteslapiii, NID_p384_qteslapiii, "p384_qteslapiii", "OpenSSL ECDSA p384 qTESLA-p-III algorithm")
///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_EVP_METHS_END
