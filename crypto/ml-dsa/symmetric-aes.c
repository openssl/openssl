#include <stdint.h>
#include "symmetric.h"
#include "aes256ctr.h"

void dilithium_aes256ctr_init(aes256ctr_ctx *state,
                              const uint8_t key[32],
                              uint16_t nonce)
{
  uint8_t expnonce[12] = {0};
  expnonce[0] = nonce;
  expnonce[1] = nonce >> 8;
  aes256ctr_init(state, key, expnonce);
}
