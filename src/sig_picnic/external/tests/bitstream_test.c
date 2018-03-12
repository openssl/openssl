#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../bitstream.h"

#include <stdio.h>
#include <inttypes.h>

static int simple_test(void) {
  int ret = 0;
  for (unsigned int i = 1; i <= sizeof(uint64_t) * 8; ++i) {
    uint8_t buffer[sizeof(uint64_t)] = {0};
    const uint64_t v                 = UINT64_C(1) << (i - 1);

    bitstream_t bsw;
    bsw.buffer = buffer;
    bsw.position = 0;
    oqs_sig_picnic_bitstream_put_bits(&bsw, v, i);

    bitstream_t bsr;
    bsr.buffer = buffer;
    bsr.position = 0;
    const uint64_t r = oqs_sig_picnic_bitstream_get_bits(&bsr, i);
    if (r != v) {
      printf("simple_test: expected %016" PRIx64 ", got %016" PRIx64 "\n", v, r);
      ret = -1;
    }

    if (buffer[0] != 0x80) {
      printf("simple_test: expected buffer 80000000000000000000, got "
             "%02x%02x%02x%02x%02x%02x%02x%02x\n",
             buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
             buffer[7]);
      ret = -1;
    }
  }

  return ret;
}

static const uint64_t v = UINT64_C(0b110110000110110010100101001010);

static int test_30(void) {
  int ret                           = 0;
  uint8_t buffer[sizeof(uint64_t)]  = {0};
  uint8_t buffer2[sizeof(uint64_t)] = {0};

  bitstream_t bsw;
  bsw.buffer = buffer;
  bsw.position = 0;
  oqs_sig_picnic_bitstream_put_bits(&bsw, v, 30);

  bitstream_t bsw2;
  bsw2.buffer = buffer2;
  bsw2.position = 0;
  for (unsigned int i = 0; i < 30; ++i) {
    oqs_sig_picnic_bitstream_put_bits(&bsw2, v >> (30 - i - 1), 1);
  }

  bitstream_t bsr;
  bsr.buffer = buffer;
  bsr.position = 0;
  uint64_t r = oqs_sig_picnic_bitstream_get_bits(&bsr, 30);
  if (r != v) {
    printf("test_30: expected %016" PRIx64 ", got %016" PRIx64 "\n", v, r);
    ret = -1;
  }

  bitstream_t bsr2;
  bsr2.buffer = buffer2;
  bsr2.position = 0;
  for (unsigned int i = 0; i < 30; ++i) {
    r = oqs_sig_picnic_bitstream_get_bits(&bsr2, 1);
    const uint64_t e = (v >> (30 - i - 1)) & 0x1;
    if (e != r) {
      printf("test_30: expected2 %016" PRIx64 ", got %016" PRIx64 "\n", e, r);
      ret = -1;
    }
  }

  if (buffer[0] != 0b11011000 || buffer[1] != 0b01101100 || buffer[2] != 0b10100101 ||
      buffer[3] != 0b00101000) {
    printf("test_30: expected buffer %016" PRIx64 ", got %02x%02x%02x%02x%02x%02x%02x%02x\n", v << 34,
           buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);
    ret = -1;
  }
  if (buffer2[0] != 0b11011000 || buffer2[1] != 0b01101100 || buffer2[2] != 0b10100101 ||
      buffer2[3] != 0b00101000) {
    printf("test_30: expected buffer2 %016" PRIx64 ", got %02x%02x%02x%02x%02x%02x%02x%02x\n", v << 34,
           buffer2[0], buffer2[1], buffer2[2], buffer2[3], buffer2[4], buffer2[5], buffer2[6],
           buffer2[7]);
    ret = -1;
  }

  return ret;
}

static int test_multiple_30(void) {
  int ret                          = 0;
  uint8_t buffer[sizeof(uint64_t)] = {0};

  const uint64_t v2 = (~v) & ((1 << 30) - 1);

  bitstream_t bsw;
  bsw.buffer = buffer;
  bsw.position = 0;
  oqs_sig_picnic_bitstream_put_bits(&bsw, v, 30);
  oqs_sig_picnic_bitstream_put_bits(&bsw, v2, 30);

  bitstream_t bsr;
  bsr.buffer = buffer;
  bsr.position = 0;
  uint64_t r = oqs_sig_picnic_bitstream_get_bits(&bsr, 30);
  if (r != v) {
    printf("test_multiple_30: expected %016" PRIx64 ", got %016" PRIx64 "\n", v, r);
    ret = -1;
  }
  r = oqs_sig_picnic_bitstream_get_bits(&bsr, 30);
  if (r != v2) {
    printf("test_multiple_30: expected %016" PRIx64 ", got %016" PRIx64 "\n", v2, r);
    ret = -1;
  }

  if (buffer[0] != 0b11011000 || buffer[1] != 0b01101100 || buffer[2] != 0b10100101 ||
      buffer[3] != 0b00101000) {
    printf("test_30: expected buffer %016" PRIx64 ", got %02x%02x%02x%02x%02x%02x%02x%02x\n", v << 34,
           buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);
    ret = -1;
  }
  return ret;
}

int main(void) {
  int ret = 0;

  int tmp = simple_test();
  if (tmp) {
    printf("simple_test: failed!\n");
    ret = tmp;
  }

  tmp = test_30();
  if (tmp) {
    printf("test_30: failed!\n");
    ret = tmp;
  }

  tmp = test_multiple_30();
  if (tmp) {
    printf("test_multiple_30: failed!\n");
    ret = tmp;
  }

  return ret;
}
