#include <openssl/aes.h>
#include "sym-api.h"

// A wrapper to make OpenSSL's AES work in one pass, like the Cryptol
// specification.
int aes_encrypt(const unsigned char *in,
                unsigned char *out,
                const unsigned char *key) {
  AES_KEY rkey;
  int r = AES_set_encrypt_key(key, 128, &rkey);
  AES_encrypt(in, out, &rkey);
  return r;
}

int main() {

  // There are two fresh, unconstrained inputs: the plain text and the
  // key.
  unsigned char *in = lss_fresh_array_uint8(16, 0, NULL);
  unsigned char *key = lss_fresh_array_uint8(16, 0, NULL);

  // The output is written to space allocated by the caller.
  unsigned char *out = malloc(16 * sizeof(unsigned char));

  // Run the encryption.
  aes_encrypt(in, out, key);

  // Write the symbolic representation of the result into an
  // And-Inverter Graph.
  lss_write_aiger_array_uint8(out, 16, "aes128enc.aig");
}
