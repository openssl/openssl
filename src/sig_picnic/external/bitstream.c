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

#include "bitstream.h"

bitstream_value_t oqs_sig_picnic_bitstream_get_bits(bitstream_t* bs, unsigned int num_bits) {
  const uint8_t* p              = &bs->buffer[bs->position / 8];
  const unsigned int skip_bits  = bs->position % 8;
  const unsigned int start_bits = 8 - skip_bits;

  bs->position += num_bits;
  bitstream_value_t ret = (*p++ & ((1 << start_bits) - 1));

  if (num_bits <= start_bits) {
    return ret >> (start_bits - num_bits);
  }

  num_bits -= start_bits;
  for (; num_bits >= 8; num_bits -= 8) {
    ret = ret << 8 | *p++;
  }

  if (num_bits > 0) {
    ret = ret << num_bits | ((*p >> (8 - num_bits)) & ((1 << num_bits) - 1));
  }

  return ret;
}

int oqs_sig_picnic_bitstream_put_bits(bitstream_t* bs, bitstream_value_t value, unsigned int num_bits) {
  const unsigned int skip_bits = bs->position % 8;
  uint8_t* p                   = &bs->buffer[bs->position / 8];

  bs->position += num_bits;
  if (skip_bits) {
    // the upper skip_bits of current pos have already been taken
    const unsigned int start_bits = 8 - skip_bits;
    const unsigned int bits       = num_bits < start_bits ? num_bits : start_bits;

    *p++ |= (value >> (num_bits - bits)) << (8 - skip_bits - bits);
    num_bits -= bits;
  }

  while (num_bits > 0) {
    if (num_bits >= 8) {
      *p++ = (value >> (num_bits - 8));
      num_bits -= 8;
    } else {
      *p = (value & ((1 << num_bits) - 1)) << (8 - num_bits);
      return 0;
    }
  }

  return 0;
}
