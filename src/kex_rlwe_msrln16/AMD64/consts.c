/****************************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: constants for the x64 assembly implementation
*
*****************************************************************************************/

#include "../LatticeCrypto_priv.h"
#include <stdint.h>

uint32_t PRIME8x[8] = {OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_Q, OQS_RLWE_MSRLN16_PARAMETER_Q};
uint8_t ONE32x[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
uint32_t MASK12x8[8] = {0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff};
uint32_t PERM0246[4] = {0, 2, 4, 6};
uint32_t PERM00224466[8] = {0, 0, 2, 2, 4, 4, 6, 6};
uint32_t PERM02134657[8] = {0, 2, 1, 3, 4, 6, 5, 7};
uint64_t PERM0145[4] = {0, 1, 4, 5};
uint64_t PERM2367[4] = {2, 3, 6, 7};
uint64_t MASK32[4] = {0xffffffff, 0, 0xffffffff, 0};
uint64_t MASK42[4] = {0x3fff0000000, 0, 0x3fff0000000, 0};

uint64_t MASK14_1[4] = {0x3fff, 0, 0x3fff, 0};
uint64_t MASK14_2[4] = {0xFFFC000, 0, 0xFFFC000, 0};
uint64_t MASK14_3[4] = {0x3FFF0000000, 0, 0x3FFF0000000, 0};
uint64_t MASK14_4[4] = {0xFFFC0000000000, 0, 0xFFFC0000000000, 0};

uint32_t ONE8x[8] = {1, 1, 1, 1, 1, 1, 1, 1};
uint32_t THREE8x[8] = {3, 3, 3, 3, 3, 3, 3, 3};
uint32_t FOUR8x[8] = {4, 4, 4, 4, 4, 4, 4, 4};
uint32_t PARAM_Q4x8[8] = {3073, 3073, 3073, 3073, 3073, 3073, 3073, 3073};
uint32_t PARAM_3Q4x8[8] = {9217, 9217, 9217, 9217, 9217, 9217, 9217, 9217};
uint32_t PARAM_5Q4x8[8] = {15362, 15362, 15362, 15362, 15362, 15362, 15362, 15362};
uint32_t PARAM_7Q4x8[8] = {21506, 21506, 21506, 21506, 21506, 21506, 21506, 21506};
uint32_t PARAM_Q2x8[8] = {6145, 6145, 6145, 6145, 6145, 6145, 6145, 6145};
uint32_t PARAM_3Q2x8[8] = {18434, 18434, 18434, 18434, 18434, 18434, 18434, 18434};
