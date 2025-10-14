#include <openssl/crypto.h>
#include "crypto/hqc_kem.h"

HQC_KEY *ossl_hqc_kem_key_new(const HQC_VARIANT_INFO *info, void *ctx)
{
    HQC_KEY *new = OPENSSL_zalloc(sizeof(HQC_KEY));

    if (new != NULL) {
        new->ctx = ctx;
        new->info = info;
        new->ek = OPENSSL_malloc(new->info->ek_size);
        new->dk = OPENSSL_secure_malloc(new->info->dk_size);
        if (new->ek == NULL || new->dk == NULL) {
            OPENSSL_free(new->ek);
            OPENSSL_secure_free(new->dk);
            OPENSSL_free(new);
            new = NULL;
        }
    }
    return new;
}

void ossl_hqc_kem_key_free(HQC_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_free(key->ek);
    OPENSSL_secure_free(key->dk);
    OPENSSL_free(key);
}
