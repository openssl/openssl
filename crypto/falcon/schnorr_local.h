#ifndef OSSL_FALCON_SCHNORR_LOCAL_H
#define OSSL_FALCON_SCHNORR_LOCAL_H

#include <openssl/ec.h>
#include <openssl/bn.h>

int schnorr_sign_raw(const unsigned char *msg, size_t msg_len,
                      const unsigned char *priv_key, size_t priv_key_len,
                      unsigned char *sig, size_t *sig_len);

int schnorr_verify_raw(const unsigned char *msg, size_t msg_len,
                        const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *sig, size_t sig_len);

#endif
