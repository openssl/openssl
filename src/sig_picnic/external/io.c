/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "io.h"

#include "compat.h"

void oqs_sig_picnic_mzd_to_char_array(uint8_t* dst, const mzd_local_t* data, unsigned len) {
  const size_t word_count = len / sizeof(uint64_t);
  const uint64_t* rows    = &CONST_FIRST_ROW(data)[word_count - 1];
  uint64_t* wdst          = (uint64_t*)dst;

  for (size_t i = word_count; i; --i, --rows, ++wdst) {
    *wdst = htobe64(*rows);
  }
}

void oqs_sig_picnic_mzd_from_char_array(mzd_local_t* result, const uint8_t* data, unsigned len) {
  const size_t word_count = len / sizeof(uint64_t);
  uint64_t* rows          = &FIRST_ROW(result)[word_count - 1];
  const uint64_t* wsrc    = (const uint64_t*)data;

  for (size_t i = word_count; i; --i, --rows, ++wsrc) {
    *rows = be64toh(*wsrc);
  }
}

void uint64_to_char_array(uint8_t* dst, const uint64_t data) {
  uint64_t* wdst = (uint64_t*)dst;
  *wdst          = htobe64(data);
}

void uint64_from_char_array(uint64_t* result, const uint8_t* data) {
  const uint64_t* wsrc = (const uint64_t*)data;
  *result              = be64toh(*wsrc);
}

void print_hex(FILE* out, const uint8_t* data, size_t len) {
  for (size_t i = len; i; --i, ++data) {
    fprintf(out, "%02X", *data);
  }
}
