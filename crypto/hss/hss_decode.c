#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/packet.h"
#include "crypto/hss.h"
#include "lms_local.h"

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

static LMS_KEY *add_decoded_pubkey(PACKET *pkt, const LMS_KEY *pub,
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

/*
 * Create lists of LMS_KEY and LMS_SIG objects by decoding a HSS signature in
 * |sig| of size |siglen| bytes.
 */
int ossl_hss_decode(const HSS_KEY *pub,
                    const unsigned char *sig, size_t siglen,
                    STACK_OF(LMS_KEY) *publist,
                    STACK_OF(LMS_SIG) *siglist)
{
    int ret = 0;
    uint32_t Nspk, i;
    LMS_KEY *key = (LMS_KEY *)&pub->lms_pub;
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, sig, siglen)
            || !PACKET_get_4_len(&pkt, &Nspk)
            || Nspk != (pub->L - 1))
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
