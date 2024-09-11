#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/packet.h"
#include "crypto/hss.h"
#include "lms_local.h"

/**
 * @brief Decode a byte array of signature data and add it to list.
 * A new LMS_SIG object is created to store the signature data into.
 *
 * @param pkt Contains the signature data to decode. There may still be data
 *            remaining in pkt after decoding.
 * @param key A public key that contains LMS_PARAMS and LM_OTS_PARAMS associated
 *            with the signature.
 * @param siglist A list to add the decoded signature to.
 * @returns 1 if the LMS_SIG object is successfully added to the list,
 *          or 0 on failure.
 */
static int add_decoded_sig(PACKET *pkt, const LMS_KEY *key,
                           STACK_OF(LMS_SIG) *siglist)
{
    LMS_SIG *s;

    s = ossl_lms_sig_from_pkt(pkt, key);
    if (s == NULL)
        return 0;

    if (sk_LMS_SIG_push(siglist, s) <= 0) {
        ossl_lms_sig_free(s);
        return 0;
    }
    return 1;
}

/**
 * @brief Decode a byte array of public key data and add it to list.
 * A new LMS_KEY object is created to store the public key into.
 *
 * @param pkt Contains the public key data to decode. There may still be data
 *            remaining in pkt after decoding.
 * @param keylist A list to add the decoded public key to.
 * @returns 1 if the LMS_KEY object is successfully added to the list,
 *          or 0 on failure.
 */
static LMS_KEY *add_decoded_pubkey(PACKET *pkt, STACK_OF(LMS_KEY) *keylist)
{
    LMS_KEY *key;

    key = ossl_lms_key_new();
    if (key == NULL)
        return NULL;

    if (!ossl_lms_pubkey_from_pkt(pkt, key)
            || (sk_LMS_KEY_push(keylist, key) <= 0)) {
        ossl_lms_key_free(key);
        key = NULL;
    }
    return key;
}

/**
 * @brief Decode a byte array of HSS signature data.
 * The signature is decoded into lists of LMS_KEY and LMS_SIG objects.
 *
 * This function does not duplicate any of the byte data contained within
 * sig. So it is expected that sig will exist for the duration of the hsskey.
 *
 * @param hsskey Must contain a public key on entry, and is used to store
 *               lists of LMS_KEY and LMS_SIG objects.
 * @param sig A input byte array of signature data.
 * @param siglen The size of sig.
 * @returns 1 if the signature is successfully decoded and added,
 *          otherwise it returns 0.
 */
int ossl_hss_sig_decode(HSS_KEY *hsskey,
                        const unsigned char *sig, size_t siglen)
{
    int ret = 0;
    uint32_t Nspk, i;
    LMS_KEY *key;
    PACKET pkt;

    /*
     * This assumes that the HSS public key has been set up already
     * and there is only the public key in the list.
     */
    if (sk_LMS_KEY_num(hsskey->lmskeys) != 1)
        return 0;
    key = sk_LMS_KEY_value(hsskey->lmskeys, 0);
    if (key == NULL)
        return 0;
    /* Check that the signature list is empty */
    if (sk_LMS_SIG_num(hsskey->lmssigs) > 0)
        return 0;

    /*
     * Decode the number of signed public keys
     * and check that it is one less than the number of HSS levels L
     */
    if (!PACKET_buf_init(&pkt, sig, siglen)
            || !PACKET_get_4_len(&pkt, &Nspk)
            || Nspk != (hsskey->L - 1))
        return 0;

    /*
     * Decode the LMS signature and public key for each subsequent level.
     *
     * The signature uses the parents private key to sign the encoded
     * public key of the next level).
     */
    for (i = 0; i < Nspk; ++i) {
        /* Decode signature for the public key */
        if (!add_decoded_sig(&pkt, key, hsskey->lmssigs))
            goto err;
        /* Decode the public key */
        key = add_decoded_pubkey(&pkt, hsskey->lmskeys);
        if (key == NULL)
            goto err;
    }
    /*
     * Decode the final signature
     * (This signature used the private key of the leaf tree to sign
     * an actual message).
     */
    if (!add_decoded_sig(&pkt, key, hsskey->lmssigs))
        goto err;
    /* Fail if there are trailing bytes */
    if (PACKET_remaining(&pkt) > 0)
        goto err;
    ret = 1;
err:
    return ret;
}
