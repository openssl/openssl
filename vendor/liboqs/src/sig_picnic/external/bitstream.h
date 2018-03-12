/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef BITSTREAM_H

#include <stddef.h>
#include <stdint.h>

typedef uint64_t bitstream_value_t;

typedef struct {
  uint8_t* buffer;
  size_t position;
} bitstream_t;

bitstream_value_t oqs_sig_picnic_bitstream_get_bits(bitstream_t* bs, unsigned int num_bits);
int oqs_sig_picnic_bitstream_put_bits(bitstream_t* bs, bitstream_value_t value, unsigned int num_bits);

#endif
