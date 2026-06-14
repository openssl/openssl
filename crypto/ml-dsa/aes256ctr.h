#ifndef AES256CTR_H
#define AES256CTR_H

#include <stddef.h>
#include <stdint.h>

#define AES256CTR_BLOCKBYTES 64

#define AES256CTR_NAMESPACE(s) pqcrystals_aes256ctr_ref##s

typedef struct {
  uint64_t sk_exp[120];
  uint32_t ivw[16];
} aes256ctr_ctx;

#define aes256ctr_prf AES256CTR_NAMESPACE(_prf)
void aes256ctr_prf(uint8_t *out,
                   size_t outlen,
                   const uint8_t key[32],
                   const uint8_t nonce[12]);

#define aes256ctr_init AES256CTR_NAMESPACE(_init)
void aes256ctr_init(aes256ctr_ctx *state,
                    const uint8_t key[32],
                    const uint8_t nonce[12]);

#define aes256ctr_squeezeblocks AES256CTR_NAMESPACE(_squeezeblocks)
void aes256ctr_squeezeblocks(uint8_t *out,
                             size_t nblocks,
                             aes256ctr_ctx *state);

#endif
