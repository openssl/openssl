/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef CPU_H
#define CPU_H

#include <stdbool.h>

#define CPU_CAP_SSE2 0x00000001
#define CPU_CAP_SSE4_1 0x00000002
#define CPU_CAP_AVX2 0x00000004
#define CPU_CAP_NEON 0x00000008

/**
 * Helper function in case __builtin_cpu_supports is not available.
 */
bool cpu_supports(unsigned int caps);

#endif
