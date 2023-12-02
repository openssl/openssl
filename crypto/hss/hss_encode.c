#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/packet.h"
#include "crypto/hss.h"
#include "lms_local.h"

static int print_hex(BIO *out, const unsigned char *buf, size_t buflen)
{
    size_t i;

    for (i = 0; i < buflen; i++) {
        if (BIO_printf(out, "%02x", buf[i]) <= 0)
            return 0;
    }
    if (BIO_printf(out, "\n") <= 0)
        return 0;
    return 1;
}

static int print_labeled_hex(BIO *out, const char *label,
                             const unsigned char *buf, size_t buflen)
{
    if (BIO_printf(out, "%s", label) <= 0)
        return 0;
    return print_hex(out, buf, buflen);
}


int ossl_lms_params_to_text(BIO *out, const LMS_PARAMS *prms)
{
    return BIO_printf(out, "LMS type:   %d     # LM_%s_M%d_H%d\n",
                      prms->lms_type, prms->digestname, prms->n, prms->h) > 0;
}

int ossl_lm_ots_params_to_text(BIO *out, const LM_OTS_PARAMS *prms)
{
    return BIO_printf(out, "LMOTS type: %d     # LMOTS_%s_N%d_W%d (P%d)\n",
                      prms->lm_ots_type, prms->digestname,
                      prms->n, prms->w, prms->p) > 0;
}

int ossl_lms_key_to_text(BIO *out, LMS_KEY *lmskey, int height, int selection)
{
    int ret = 0;

    if (lmskey == NULL)
        return 0;

    if (!ossl_lms_params_to_text(out, lmskey->lms_params)
            || !ossl_lm_ots_params_to_text(out, lmskey->ots_params))
        goto err;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (lmskey->I != NULL
                && !print_labeled_hex(out, "I:", lmskey->I, LMS_SIZE_I))
            goto err;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (lmskey->pub.K != NULL
                && !print_labeled_hex(out, "K:", lmskey->pub.K,
                                      lmskey->lms_params->n))
            goto err;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (lmskey->priv.seed != NULL
                && !print_labeled_hex(out, "SEED:", lmskey->priv.seed,
                                      lmskey->lms_params->n))
            goto err;
        if (BIO_printf(out, "q: %d (%d remaining)\n", lmskey->q,
                       (1 << height) - lmskey->q) <= 0)
            goto err;
    }

    ret = 1;
err:
    return ret;
}

int ossl_lms_sig_to_text(BIO *out, LMS_SIG *lmssig)
{
    int ret = 0;
    uint32_t i;

    if (BIO_printf(out, "q: %d\n", lmssig->q) <= 0)
        goto err;
    if (!ossl_lm_ots_params_to_text(out, lmssig->sig.params))
        goto err;
    if (!print_labeled_hex(out, "C: ", lmssig->sig.C, lmssig->sig.params->n))
        goto err;

    for (i = 0; i < lmssig->sig.params->p; i++) {
        if (BIO_printf(out, "y[%d]: ", i) <= 0)
            goto err;
        if (!print_hex(out, lmssig->sig.y + i * lmssig->sig.params->n,
                       lmssig->sig.params->n))
            goto err;
    }
    if (!ossl_lms_params_to_text(out, lmssig->params))
        goto err;
    for (i = 0; i < lmssig->params->h; i++) {
        if (BIO_printf(out, "path[%d]: ", i) <= 0)
            goto err;
        if (!print_hex(out, lmssig->paths + i * lmssig->sig.params->n,
                       lmssig->sig.params->n))
            goto err;
    }
    ret = 1;
err:
    return ret;
}

int ossl_hss_sig_to_text(BIO *out, HSS_KEY *hsskey, int selection)
{
    LMS_SIG *sig;
    LMS_KEY *key;
    int height = 0;
    uint32_t i;

    if (BIO_printf(out, "Nspk: %d\n", hsskey->L - 1) <= 0)
        return 0;

    for (i = 0; i < hsskey->L; ++i) {
        sig = sk_LMS_SIG_value(hsskey->lmssigs, i);
        key = sk_LMS_KEY_value(hsskey->lmskeys, i);
        if (key == NULL || sig == NULL)
            return 0;
        height += key->lms_params->h;
        if (i != 0) {
            /* The root HSS public key is not part of the signature */
            if (!ossl_lms_key_to_text(out, key, height, selection))
                return 0;
        }
        if (BIO_printf(out, "\nSig[%d]:\n", i) <= 0)
            return 0;
        if (!ossl_lms_sig_to_text(out, sig))
            return 0;
    }
    return 1;
}
