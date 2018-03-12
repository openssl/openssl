/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef IO_H
#define IO_H

#include <stdint.h>
#include <stdio.h>

#include "mzd_additional.h"

void oqs_sig_picnic_mzd_to_char_array(uint8_t* dst, const mzd_local_t* data, unsigned numbytes);
void oqs_sig_picnic_mzd_from_char_array(mzd_local_t* result, const uint8_t* data, unsigned len);

void print_hex(FILE* out, const uint8_t* data, size_t len);

#endif
