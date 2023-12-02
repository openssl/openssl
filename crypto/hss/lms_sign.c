#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/packet.h"
#include "crypto/hss.h"
#include "lms_local.h"

int ossl_lms_signature_gen(LMS_KEY *key, const unsigned char *msg, size_t msglen,
                           LMS_SIG *sig)
{
    unsigned char *path;
    uint32_t nodeid, i, h = key->lms_params->h, n = key->ots_params->n;

    if (sig->paths == NULL) {
        sig->paths = OPENSSL_malloc(h * n);
        if (sig->paths == NULL)
            return 0;
    }
    sig->q = key->q;
/*
    if (!ossl_lms_key_reset(key))
        return 0;
    if (!ossl_lms_pub_key_compute(key))
        return 0;
*/
    if (!ossl_lm_ots_signature_gen(key, msg, msglen, &sig->sig))
        return 0;

    path = sig->paths;
    nodeid = key->q + (1 << h); /* Work from the leaf upwards */
    for (i = 0; i < h; ++i, nodeid = nodeid >> 1) {
        /* Get the other child */
        if (!ossl_lms_key_get_pubkey_from_nodeid(key, nodeid ^ 1, path))
            return 0;
        path += n;
    }
    key->q++;
    return 1;
}
