#include <openssl/sha.h>
#include <sym-api.h>

int main() {
  const size_t s = 100;
  const unsigned char *in = lss_fresh_array_uint8(s, 0, NULL);
  unsigned char out[SHA_DIGEST_LENGTH];
  SHA256(in, s, out);
  lss_write_aiger_array_uint8(out, SHA_DIGEST_LENGTH, "sha1.aig");
}
