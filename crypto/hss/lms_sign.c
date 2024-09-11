#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/packet.h"
#include "internal/common.h"
#include "crypto/hss.h"
#include "lms_local.h"

#ifndef OPENSSL_NO_HSS_GEN

/*
 * @brief LMS signature generation.
 * See RFC 8554 Section 5.4.1 & Appendix D
 *
 * A LMS signature is given by
 * u32str(q) || lmots_signature || u32str(type) || path[0] || ... || path[h-1]
 * This code calculates the lmots_signature and builds the path[] and stores
 * these into a LMS_SIG object.
 * The algorithm is broken into 3 parts to handle streaming.
 * Note that q is not updated by this layer, this is handled by the caller.
 *
 * @param key The private key used to sign the msg
 * @param msg The input message buffer
 * @param msglen The size of msg
 * @param sig A LMS_SIG object used to store the LMS signature data
 * @returns 1 on success or 0 otherwise.
 */
int ossl_lms_signature_gen(LMS_KEY *key, const unsigned char *msg, size_t msglen,
                           LMS_SIG *sig)
{
    return ossl_lms_signature_gen_init(key, sig)
        && ossl_lms_signature_gen_update(key, msg, msglen)
        && ossl_lms_signature_gen_final(key, sig);
}

/**
 * @brief The initial phase for the streaming variant of ossl_lms_signature_gen().
 */
int ossl_lms_signature_gen_init(LMS_KEY *key, LMS_SIG *sig)
{
    if (sig->paths == NULL) {
        sig->paths = OPENSSL_malloc(key->lms_params->h * key->ots_params->n);
        if (sig->paths == NULL)
            return 0;
        sig->paths_allocated = 1;
    }
    sig->q = key->q;
    return ossl_lm_ots_signature_gen_init(key, &sig->sig);
}

/**
 * @brief The middle phase of the streaming variant of ossl_lms_signature_gen().
 * This may be called multiple times.
 */
int ossl_lms_signature_gen_update(LMS_KEY *key,
                                  const unsigned char *msg, size_t msglen)
{
    return ossl_lm_ots_signature_gen_update(key, msg, msglen);
}

/**
 * @brief The final phase of the streaming variant of ossl_lms_signature_gen().
 */
int ossl_lms_signature_gen_final(LMS_KEY *key, LMS_SIG *sig)
{
    unsigned char *path;
    uint32_t nodeid, i, h = key->lms_params->h, n = key->ots_params->n;

    if (!ossl_lm_ots_signature_gen_final(key, &sig->sig))
        return 0;

    path = sig->paths;
    nodeid = key->q + (1 << h); /* Work from the leaf upwards */
    for (i = 0; i < h; ++i, nodeid = nodeid >> 1) {
        /* Get the other child */
        if (!ossl_lms_key_get_pubkey_from_nodeid(key, nodeid ^ 1, path))
            return 0;
        path += n;
    }
    return 1;
}
#endif
