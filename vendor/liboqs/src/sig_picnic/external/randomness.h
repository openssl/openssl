/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef RANDOMNESS_H
#define RANDOMNESS_H

#include <stddef.h>
#include <stdint.h>

int rand_bytes(uint8_t* dst, size_t len);

#endif
