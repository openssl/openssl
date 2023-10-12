#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/packet.h"
#include "crypto/lms.h"

#define MAX_DIGEST_SIZE 32
#define HSS_MIN_L 1
#define HSS_MAX_L 8

/*
 * OpenSSL does not have a "SHAKE256-192" algorithm, so we have to check the
 * digest size as well as the name.
 */
#define HASH_NOT_MATCHED(a, b) \
    a->n != b->n || (strcmp(a->digestname, b->digestname) != 0)

static ossl_inline int PACKET_get_bytes_shallow(PACKET *pkt,
                                                unsigned char **out,
                                                size_t len)
{
    const unsigned char **data = (const unsigned char **)out;

    if (!PACKET_peek_bytes(pkt, data, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

static ossl_inline int PACKET_get_4_len(PACKET *pkt, uint32_t *data)
{
    size_t i = 0;
    int ret = PACKET_get_net_4_len(pkt, &i);

    if (ret)
        *data = (uint32_t)i;
    return ret;
}

/*
 * Create a LMS_SIG object from a HSS signature byte array in |pkt|.
 * An error is returned if the passed in public key |pub| is not compatible
 * with the decoded LMS_SIG object,
 *
 * This function may be called multiple times when parsing a HSS signature.
 * See RFC 8554 Algorithm 6a: Steps 1 and 2
 */
static LMS_SIG *lms_sig_from_pkt(PACKET *pkt, const LMS_KEY *pub)
{
    uint32_t sig_ots_type = 0, sig_lms_type = 0;
    const LM_OTS_PARAMS *pub_ots_params = pub->ots_params;
    const LM_OTS_PARAMS *sig_params;
    const LMS_PARAMS *lparams;
    LMS_SIG *lsig = NULL;

    lsig = ossl_lms_sig_new();
    if (lsig == NULL)
        return NULL;

    if (!PACKET_get_4_len(pkt, &lsig->q))    /* q = Leaf Index */
        goto err;
    if (!PACKET_get_4_len(pkt, &sig_ots_type))
        goto err;
    if (pub_ots_params->lm_ots_type != sig_ots_type)
        goto err;
    sig_params = pub_ots_params;
    lsig->sig.params = sig_params;

    /* The C, y and paths pointers are just pointers to existing data */
    if (!PACKET_get_bytes_shallow(pkt, &lsig->sig.C, sig_params->n)) /* Random bytes of size n */
        goto err;
    if (!PACKET_get_bytes_shallow(pkt, &lsig->sig.y, sig_params->p * sig_params->n)) /* Y[P] hash values */
        goto err;

    if (!PACKET_get_4_len(pkt, &sig_lms_type))
        goto err;;
    if (pub->lms_params->lms_type != sig_lms_type)
        goto err;
    lparams = pub->lms_params;
    /* The digest used must be the same */
    if (HASH_NOT_MATCHED(pub->lms_params, sig_params))
        goto err;
    if (lsig->q >= (uint32_t)(1 << lparams->h))
        goto err;
    if (!PACKET_get_bytes_shallow(pkt, &lsig->paths, lparams->h * lparams->n)) /* path[h] hash values */
        goto err;
    return lsig;
err:
    ossl_lms_sig_free(lsig);
    return NULL;
}

/*
 * This function is used when LMS_SIGNATURES is defined.
 * HSS signatures use lms_sig_from_pkt().
 */
LMS_SIG *ossl_lms_sig_from_data(const unsigned char *sig, size_t siglen,
                                const LMS_KEY *pub)
{
    PACKET pkt;
    LMS_SIG *ret;

    if (!PACKET_buf_init(&pkt, sig, siglen))
        return 0;
    ret = lms_sig_from_pkt(&pkt, pub);
    if (ret == NULL
        || PACKET_remaining(&pkt) != 0) {
        ossl_lms_sig_free(ret);
        ret = NULL;
    }
    return ret;
}

/*
 * RFC 8554 Algorithm 6: Steps 1 & 2.
 * Steps that involve checking the size of the public key data are
 * done indirectly by checking the return result of PACKET_get API's.
 * This function may be called multiple times when parsing a HSS signature.
 * It is also used by ossl_lms_pubkey_from_data() to load a pubkey.
 */
int ossl_lms_pubkey_from_pkt(PACKET *pkt, LMS_KEY *key)
{
    uint32_t lms_type;
    uint32_t ots_type;

    if (key == NULL)
        goto err;
    key->pub = (unsigned char *)pkt->curr;
    if (!PACKET_get_4_len(pkt, &lms_type))
        goto err;
    key->lms_params = ossl_lms_params_get(lms_type);
    if (key->lms_params == NULL)
        goto err;

    if (!PACKET_get_4_len(pkt, &ots_type))
        goto err;
    key->ots_params = ossl_lm_ots_params_get(ots_type);
    if (key->ots_params == NULL)
        goto err;

    /* The digest used must be the same */
    if (HASH_NOT_MATCHED(key->ots_params, key->lms_params))
        goto err;
    /* The I and K pointers are just pointers to existing data */
    if (!PACKET_get_bytes_shallow(pkt, &key->I, LMS_ISIZE)) /* 16 byte Id */
        goto err;
    if (!PACKET_get_bytes_shallow(pkt, &key->K, key->lms_params->n))
        goto err;
    key->publen = pkt->curr - key->pub;
    return 1;
err:
    return 0;
}

/*
 * Load a public LMS_KEY from a |pub| byte array of size |publen|.
 * An error is returned if either |pub| is invalid or |publen| is
 * not the correct size (i.e. trailing data is not allowed
 */
int ossl_lms_pubkey_from_data(const unsigned char *pub, size_t publen,
                              LMS_KEY *key)
{
    PACKET pkt;

    key->pub = OPENSSL_memdup(pub, publen);
    if (key->pub == NULL)
        return 0;

    key->publen = publen;
    key->pub_allocated = 1;

    if (!PACKET_buf_init(&pkt, key->pub, key->publen)
        || !ossl_lms_pubkey_from_pkt(&pkt, key)
        || (PACKET_remaining(&pkt) > 0))
        goto err;
    return 1;
err:
    OPENSSL_free(key->pub);
    key->pub = NULL;
    return 0;
}

int ossl_hss_pubkey_from_data(const unsigned char *pub, size_t publen,
                              LMS_KEY *key)
{
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, pub, publen))
        return 0;
    if (!PACKET_get_4_len(&pkt, &key->L))
        return 0;
    if (key->L < HSS_MIN_L || key->L > HSS_MAX_L)
        return 0;

    return ossl_lms_pubkey_from_data(pkt.curr, pkt.remaining, key);
}

static int add_decoded_sig(PACKET *pkt, LMS_KEY *key,
                           STACK_OF(LMS_SIG) *siglist)
{
    LMS_SIG *s;

    s = lms_sig_from_pkt(pkt, key);
    if (s == NULL)
        return 0;

    if (sk_LMS_SIG_push(siglist, s) <= 0) {
        ossl_lms_sig_free(s);
        return 0;
    }
    return 1;
}

static LMS_KEY *add_decoded_pubkey(PACKET *pkt, LMS_KEY *pub,
                                   STACK_OF(LMS_KEY) *keylist)
{
    LMS_KEY *key;

    key = ossl_lms_key_new(pub->libctx, pub->propq);
    if (key == NULL)
        return NULL;

    if (!ossl_lms_pubkey_from_pkt(pkt, key)
        || (sk_LMS_KEY_push(keylist, key) <= 0)) {
            ossl_lms_key_free(key);
            key = NULL;
    }
    return key;
}

int ossl_hss_decode(LMS_KEY *pub,
                    const unsigned char *sig, size_t siglen,
                    STACK_OF(LMS_KEY) *publist,
                    STACK_OF(LMS_SIG) *siglist)
{
    int ret = 0;
    uint32_t Nspk, i;
    LMS_KEY *key = pub;
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, sig, siglen))
        return 0;
    if (!PACKET_get_4_len(&pkt, &Nspk)) /* Number of signed public keys */
        return 0;
    if (Nspk != (pub->L - 1))
        return 0;

    for (i = 0; i < Nspk; ++i) {
        if (!add_decoded_sig(&pkt, key, siglist))
            goto err;
        key = add_decoded_pubkey(&pkt, key, publist);
        if (key == NULL)
            goto err;
    }
    if (!add_decoded_sig(&pkt, key, siglist))
        goto err;
    if (PACKET_remaining(&pkt) > 0)
        goto err;
    ret = 1;
err:
    return ret;
}

int ossl_lms_key_fromdata(const OSSL_PARAM params[], LMS_KEY *key)
{
    const OSSL_PARAM *p = NULL;
    int ok = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data == NULL
            || p->data_type != OSSL_PARAM_OCTET_STRING
            || !ossl_lms_pubkey_from_data(p->data, p->data_size, key))
            goto err;
    }
    ok = 1;
 err:
    return ok;
}

int ossl_hss_key_fromdata(const OSSL_PARAM params[], LMS_KEY *key)
{
    const OSSL_PARAM *p = NULL;
    int ok = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data == NULL
            || p->data_type != OSSL_PARAM_OCTET_STRING
            || !ossl_hss_pubkey_from_data(p->data, p->data_size, key))
            goto err;
    }
    ok = 1;
 err:
    return ok;
}

