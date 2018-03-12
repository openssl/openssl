#include "../kdf_shake.h"

int main(void) {
  const uint8_t key[] = {0xab, 0xcd};

  kdf_shake_t ctx;
  Keccak_HashInitialize_SHAKE256(&ctx);
  kdf_shake_update_key(&ctx, key, sizeof(key));
  kdf_shake_finalize_key(&ctx);

  const uint8_t expected_output[32] = {0xc3, 0x1f, 0xcb, 0xe0, 0x76, 0x48, 0x87, 0x58,
                                       0x73, 0x0d, 0xa7, 0xe5, 0xf8, 0x96, 0x4a, 0xfe,
                                       0xfa, 0x65, 0x9a, 0x6f, 0x52, 0x6b, 0x6f, 0x9c,
                                       0xa6, 0x7e, 0x59, 0x9f, 0x31, 0x8a, 0x7e, 0xa1};
  uint8_t output[2 * sizeof(expected_output)];
  kdf_shake_get_randomness(&ctx, output, sizeof(output));
  kdf_shake_clear(&ctx);

  return (memcmp(expected_output, output, sizeof(expected_output)) == 0 &&
          memcmp(expected_output, output + sizeof(expected_output), sizeof(expected_output)) != 0)
             ? 0
             : 1;
}
