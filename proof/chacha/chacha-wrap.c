#include <internal/chacha.h>
#include <sym-api.h>

int main() {
  uint32_t *key = lss_fresh_array_uint32(8, 0, NULL);
  const size_t s = 100;
  unsigned char *in = lss_fresh_array_uint8(s, 0, NULL);
  uint32_t *ctr = lss_fresh_array_uint32(4, 0, NULL);
  unsigned char *out = malloc(s);
  ChaCha20_ctr32(out, in, s, key, ctr);
  lss_write_aiger_array_uint8(out, s, "chacha/chacha.aig");
}
