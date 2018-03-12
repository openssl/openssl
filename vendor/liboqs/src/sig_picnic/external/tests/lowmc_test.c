#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../io.h"
#include "../lowmc.h"
#include "../picnic_impl.h"

#include <m4ri/m4ri.h>
#include <stdint.h>

#include "utils.c.i"

static int lowmc_enc_str(const picnic_params_t param, const char* key, const char* plaintext,
                         const char* expected) {
  picnic_instance_t* pp = oqs_sig_picnic_get_instance(param);
  if (!pp) {
    return -1;
  }

  mzd_t* sk = mzd_from_str(1, pp->lowmc.k, key);
  mzd_t* pt = mzd_from_str(1, pp->lowmc.n, plaintext);
  mzd_t* ct = mzd_from_str(1, pp->lowmc.n, expected);

  mzd_local_t* skl = mzd_convert(sk);
  mzd_local_t* ptl = mzd_convert(pt);
  mzd_local_t* ctl = mzd_convert(ct);

  int ret          = 0;
  mzd_local_t* ctr = oqs_sig_picnic_lowmc_call(&pp->lowmc, skl, ptl);
  if (!ctr) {
    ret = 1;
    goto end;
  }

  if (!oqs_sig_picnic_mzd_local_equal(ctr, ctl)) {
    ret = 2;
  }

end:
  oqs_sig_picnic_mzd_local_free(ctr);
  oqs_sig_picnic_mzd_local_free(ctl);
  oqs_sig_picnic_mzd_local_free(ptl);
  oqs_sig_picnic_mzd_local_free(skl);
  mzd_free(ct);
  mzd_free(pt);
  mzd_free(sk);

  return ret;
}

static int lowmc_enc(const picnic_params_t param, const uint8_t* key, const uint8_t* plaintext,
                     const uint8_t* expected) {
  picnic_instance_t* pp = oqs_sig_picnic_get_instance(param);
  if (!pp) {
    return -1;
  }

  mzd_local_t* sk = oqs_sig_picnic_mzd_local_init(1, pp->lowmc.k);
  mzd_local_t* pt = oqs_sig_picnic_mzd_local_init(1, pp->lowmc.n);
  mzd_local_t* ct = oqs_sig_picnic_mzd_local_init(1, pp->lowmc.n);

  oqs_sig_picnic_mzd_from_char_array(sk, key, pp->input_size);
  oqs_sig_picnic_mzd_from_char_array(pt, plaintext, pp->output_size);
  oqs_sig_picnic_mzd_from_char_array(ct, expected, pp->output_size);

  int ret          = 0;
  mzd_local_t* ctr = oqs_sig_picnic_lowmc_call(&pp->lowmc, sk, pt);
  if (!ctr) {
    ret = 1;
    goto end;
  }

  if (!oqs_sig_picnic_mzd_local_equal(ctr, ct)) {
    ret = 2;
  }

end:
  oqs_sig_picnic_mzd_local_free(ctr);
  oqs_sig_picnic_mzd_local_free(ct);
  oqs_sig_picnic_mzd_local_free(pt);
  oqs_sig_picnic_mzd_local_free(sk);

  return ret;
}

static const char key_L1_1[] = "0000000000000000000000000000000000000000000000000000000000000000000"
                               "0000100100011010001010110011110001001101010111100110111101111";
static const char plaintext_L1_1[] = "0000000000000000000000000000000000000000000000000000000000000"
                                     "0001111111011011100101110101001100001110110010101000011001000"
                                     "010000";
static const char expected_L1_1[] = "01111000101001001001011000101001011010110110010000111100000011"
                                    "10101010100100000011100110110000111000011110110111011000001100"
                                    "0000";

static const char key_L1_2[] = "0000000000000000000000000000000000000000000000000000000000000000111"
                               "1111011011100101110101001100001110110010101000011001000010000";
static const char plaintext_L1_2[] = "0000000000000000000000000000000000000000000000000000000000000"
                                     "0000000000100100011010001010110011110001001101010111100110111"
                                     "101111";
static const char expected_L1_2[] = "10110010110111000100101000011101111111111100001010100110111000"
                                    "11011011010110001001100001111010111000010011000110001110101000"
                                    "1001";

static const uint8_t key_L1_3[] = {0x08, 0x4c, 0x2a, 0x6e, 0x19, 0x5d, 0x3b, 0x7f,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t plaintext_L1_3[] = {0xf7, 0xb3, 0xd5, 0x91, 0xe6, 0xa2, 0xc4, 0x80,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t expected_L1_3[] = {0x91, 0x5c, 0x63, 0x21, 0xd7, 0x86, 0x46, 0xb6,
                                        0xc7, 0x65, 0x43, 0xff, 0xb8, 0x52, 0x3b, 0x4d};

static const char key_256_256_10_38[] =
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000001";
static const char expected_256_256_10_38[] =
    "1010001100111111101000101100011100101000011100101100111101110110111001111011101010001001100010"
    "1101110110101000100101101001100010010010000110101001110000000100010000011111000001111110010001"
    "01100100011111110011111011000110100001110000001111001010110111001000";

static const char key_192_192_10_30[] = "0000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000"
                                        "0000000000000000000000000000000000000000000000000000000000"
                                        "000000000000000001";
static const char expected_192_192_10_30[] = "10111000100100100001101010010110000100011010000111101"
                                             "00001011011100111100010101000010100001010001110000100"
                                             "00011011001000000010110000010010010110011001110110111"
                                             "011101100111000011111001000111110";

static const struct {
  picnic_params_t param;
  const char* key;
  const char* plaintext;
  const char* expected;
} str_tests[] = {{Picnic_L1_FS, key_L1_1, plaintext_L1_1, expected_L1_1},
                 {Picnic_L1_FS, key_L1_2, plaintext_L1_2, expected_L1_2},
                 {Picnic_L3_FS, key_192_192_10_30, key_192_192_10_30, expected_192_192_10_30},
                 {Picnic_L5_FS, key_256_256_10_38, key_256_256_10_38, expected_256_256_10_38}};

static const size_t num_str_tests = sizeof(str_tests) / sizeof(str_tests[0]);

static const struct {
  picnic_params_t param;
  const uint8_t* key;
  const uint8_t* plaintext;
  const uint8_t* expected;
} tests[] = {{Picnic_L1_FS, key_L1_3, plaintext_L1_3, expected_L1_3}};

static const size_t num_tests = sizeof(tests) / sizeof(tests[0]);

int main(void) {
  int ret = 0;
  for (size_t s = 0; s < num_str_tests; ++s) {
    const int t = lowmc_enc_str(str_tests[s].param, str_tests[s].key, str_tests[s].plaintext,
                                str_tests[s].expected);
    if (t) {
      printf("ERR: lowmc_enc_str %zu FAILED (%d)\n", s, t);
      ret = -1;
    }
  }

  for (size_t s = 0; s < num_tests; ++s) {
    const int t = lowmc_enc(tests[s].param, tests[s].key, tests[s].plaintext, tests[s].expected);
    if (t) {
      printf("ERR: lowmc_enc %zu FAILED (%d)\n", s, t);
      ret = -1;
    }
  }

  return ret;
}
