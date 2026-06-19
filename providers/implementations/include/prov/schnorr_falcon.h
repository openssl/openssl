#ifndef PROV_SCHNORR_FALCON_H
#define PROV_SCHNORR_FALCON_H

#include <openssl/ec.h>
#include <oqs/oqs.h>

typedef struct {
    EC_KEY *schnorr_key;
    uint8_t *falcon_pubkey;
    uint8_t *falcon_privkey;
    size_t falcon_pubkey_len;
    size_t falcon_privkey_len;
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned int has_priv : 1;
    unsigned int has_pub : 1;
} SCHNORR_FALCON_KEY;

#endif
