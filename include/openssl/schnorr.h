#ifndef OSSL_CRYPTO_SCHNORR_H
#define OSSL_CRYPTO_SCHNORR_H

#include <openssl/evp.h>

int schnorr_sign(const unsigned char *msg, size_t msg_len,
                  const unsigned char *priv_key,
                  unsigned char *sig, size_t *sig_len);

int schnorr_verify(const unsigned char *msg, size_t msg_len,
                    const unsigned char *pub_key,
                    const unsigned char *sig, size_t sig_len);

#endif
