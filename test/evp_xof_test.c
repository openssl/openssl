/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "testutil.h"
#include "internal/nelem.h"

static const char *fips_config_file = NULL;

static const uint8_t shake256_input[] = {
    0x8d, 0x80, 0x01, 0xe2, 0xc0, 0x96, 0xf1, 0xb8,
    0x8e, 0x7c, 0x92, 0x24, 0xa0, 0x86, 0xef, 0xd4,
    0x79, 0x7f, 0xbf, 0x74, 0xa8, 0x03, 0x3a, 0x2d,
    0x42, 0x2a, 0x2b, 0x6b, 0x8f, 0x67, 0x47, 0xe4
};

/*
 * This KAT output is 250 bytes, which is more than
 * the SHAKE256 block size (136 bytes).
 */
static const uint8_t shake256_output[] = {
    0x2e, 0x97, 0x5f, 0x6a, 0x8a, 0x14, 0xf0, 0x70,
    0x4d, 0x51, 0xb1, 0x36, 0x67, 0xd8, 0x19, 0x5c,
    0x21, 0x9f, 0x71, 0xe6, 0x34, 0x56, 0x96, 0xc4,
    0x9f, 0xa4, 0xb9, 0xd0, 0x8e, 0x92, 0x25, 0xd3,
    0xd3, 0x93, 0x93, 0x42, 0x51, 0x52, 0xc9, 0x7e,
    0x71, 0xdd, 0x24, 0x60, 0x1c, 0x11, 0xab, 0xcf,
    0xa0, 0xf1, 0x2f, 0x53, 0xc6, 0x80, 0xbd, 0x3a,
    0xe7, 0x57, 0xb8, 0x13, 0x4a, 0x9c, 0x10, 0xd4,
    0x29, 0x61, 0x58, 0x69, 0x21, 0x7f, 0xdd, 0x58,
    0x85, 0xc4, 0xdb, 0x17, 0x49, 0x85, 0x70, 0x3a,
    0x6d, 0x6d, 0xe9, 0x4a, 0x66, 0x7e, 0xac, 0x30,
    0x23, 0x44, 0x3a, 0x83, 0x37, 0xae, 0x1b, 0xc6,
    0x01, 0xb7, 0x6d, 0x7d, 0x38, 0xec, 0x3c, 0x34,
    0x46, 0x31, 0x05, 0xf0, 0xd3, 0x94, 0x9d, 0x78,
    0xe5, 0x62, 0xa0, 0x39, 0xe4, 0x46, 0x95, 0x48,
    0xb6, 0x09, 0x39, 0x5d, 0xe5, 0xa4, 0xfd, 0x43,
    0xc4, 0x6c, 0xa9, 0xfd, 0x6e, 0xe2, 0x9a, 0xda,
    0x5e, 0xfc, 0x07, 0xd8, 0x4d, 0x55, 0x32, 0x49,
    0x45, 0x0d, 0xab, 0x4a, 0x49, 0xc4, 0x83, 0xde,
    0xd2, 0x50, 0xc9, 0x33, 0x8f, 0x85, 0xcd, 0x93,
    0x7a, 0xe6, 0x6b, 0xb4, 0x36, 0xf3, 0xb4, 0x02,
    0x6e, 0x85, 0x9f, 0xda, 0x1c, 0xa5, 0x71, 0x43,
    0x2f, 0x3b, 0xfc, 0x09, 0xe7, 0xc0, 0x3c, 0xa4,
    0xd1, 0x83, 0xb7, 0x41, 0x11, 0x1c, 0xa0, 0x48,
    0x3d, 0x0e, 0xda, 0xbc, 0x03, 0xfe, 0xb2, 0x3b,
    0x17, 0xee, 0x48, 0xe8, 0x44, 0xba, 0x24, 0x08,
    0xd9, 0xdc, 0xfd, 0x01, 0x39, 0xd2, 0xe8, 0xc7,
    0x31, 0x01, 0x25, 0xae, 0xe8, 0x01, 0xc6, 0x1a,
    0xb7, 0x90, 0x0d, 0x1e, 0xfc, 0x47, 0xc0, 0x78,
    0x28, 0x17, 0x66, 0xf3, 0x61, 0xc5, 0xe6, 0x11,
    0x13, 0x46, 0x23, 0x5e, 0x1d, 0xc3, 0x83, 0x25,
    0x66, 0x6c
};

static const uint8_t cshake256_output[] = {
    0x30, 0xa6, 0x5f, 0xd5, 0xff, 0x3e, 0x49, 0xe8,
    0xa9, 0xef, 0x06, 0xa3, 0x56, 0x4b, 0x4f, 0x55,
    0x93, 0x0f, 0x4a, 0x9e, 0xe9, 0x74, 0x13, 0xf8,
    0x4a, 0x80, 0x44, 0x65, 0xec, 0x62, 0x83, 0x7a,
    0x21, 0xce, 0x96, 0x0e, 0x27, 0x1f, 0x81, 0x26,
    0xcb, 0xd8, 0x42, 0x7b, 0x7d, 0x71, 0x6a, 0xdc,
    0xaf, 0x4d, 0x13, 0x52, 0x28, 0x2b, 0xd9, 0x70,
    0xfb, 0x90, 0x96, 0xfe, 0x24, 0xd2, 0x22, 0x48,
    0x73, 0xae, 0x73, 0x1e, 0x10, 0x07, 0x4b, 0x92,
    0x2a, 0xae, 0x1e, 0x7b, 0x7d, 0x06, 0xe2, 0x0f,
    0x80, 0x08, 0xc3, 0xa5, 0x09, 0x71, 0x57, 0x84,
    0x4a, 0xa8, 0x70, 0xe7, 0x61, 0x6b, 0x0c, 0x3c
};

static const uint8_t empty_input[1] = { 0 };

static const uint8_t turboshake128_empty_output[] = {
    0x1e, 0x41, 0x5f, 0x1c, 0x59, 0x83, 0xaf, 0xf2,
    0x16, 0x92, 0x17, 0x27, 0x7d, 0x17, 0xbb, 0x53,
    0x8c, 0xd9, 0x45, 0xa3, 0x97, 0xdd, 0xec, 0x54,
    0x1f, 0x1c, 0xe4, 0x1a, 0xf2, 0xc1, 0xb7, 0x4c,
    0x3e, 0x8c, 0xca, 0xe2, 0xa4, 0xda, 0xe5, 0x6c,
    0x84, 0xa0, 0x4c, 0x23, 0x85, 0xc0, 0x3c, 0x15,
    0xe8, 0x19, 0x3b, 0xdf, 0x58, 0x73, 0x73, 0x63,
    0x32, 0x16, 0x91, 0xc0, 0x54, 0x62, 0xc8, 0xdf
};

static const uint8_t turboshake256_empty_output[] = {
    0x36, 0x7a, 0x32, 0x9d, 0xaf, 0xea, 0x87, 0x1c,
    0x78, 0x02, 0xec, 0x67, 0xf9, 0x05, 0xae, 0x13,
    0xc5, 0x76, 0x95, 0xdc, 0x2c, 0x66, 0x63, 0xc6,
    0x10, 0x35, 0xf5, 0x9a, 0x18, 0xf8, 0xe7, 0xdb,
    0x11, 0xed, 0xc0, 0xe1, 0x2e, 0x91, 0xea, 0x60,
    0xeb, 0x6b, 0x32, 0xdf, 0x06, 0xdd, 0x7f, 0x00,
    0x2f, 0xba, 0xfa, 0xbb, 0x6e, 0x13, 0xec, 0x1c,
    0xc2, 0x0d, 0x99, 0x55, 0x47, 0x60, 0x0d, 0xb0
};

static const uint8_t kt128_empty_output[] = {
    0x1a, 0xc2, 0xd4, 0x50, 0xfc, 0x3b, 0x42, 0x05,
    0xd1, 0x9d, 0xa7, 0xbf, 0xca, 0x1b, 0x37, 0x51,
    0x3c, 0x08, 0x03, 0x57, 0x7a, 0xc7, 0x16, 0x7f,
    0x06, 0xfe, 0x2c, 0xe1, 0xf0, 0xef, 0x39, 0xe5,
    0x42, 0x69, 0xc0, 0x56, 0xb8, 0xc8, 0x2e, 0x48,
    0x27, 0x60, 0x38, 0xb6, 0xd2, 0x92, 0x96, 0x6c,
    0xc0, 0x7a, 0x3d, 0x46, 0x45, 0x27, 0x2e, 0x31,
    0xff, 0x38, 0x50, 0x81, 0x39, 0xeb, 0x0a, 0x71
};

static const uint8_t kt256_empty_output[] = {
    0xb2, 0x3d, 0x2e, 0x9c, 0xea, 0x9f, 0x49, 0x04,
    0xe0, 0x2b, 0xec, 0x06, 0x81, 0x7f, 0xc1, 0x0c,
    0xe3, 0x8c, 0xe8, 0xe9, 0x3e, 0xf4, 0xc8, 0x9e,
    0x65, 0x37, 0x07, 0x6a, 0xf8, 0x64, 0x64, 0x04,
    0xe3, 0xe8, 0xb6, 0x81, 0x07, 0xb8, 0x83, 0x3a,
    0x5d, 0x30, 0x49, 0x0a, 0xa3, 0x34, 0x82, 0x35,
    0x3f, 0xd4, 0xad, 0xc7, 0x14, 0x8e, 0xcb, 0x78,
    0x28, 0x55, 0x00, 0x3a, 0xae, 0xbd, 0xe4, 0xa9
};

typedef struct test_data_st {
    const char *alg;
    const uint8_t *in;
    size_t inlen;
    const uint8_t *out;
    size_t outlen;
    int default_xoflen;
    const char *param_n;
    const char *param_s;
} TEST_DATA;

static const TEST_DATA xof_test_data[] = {
    {
        "SHAKE256",
        shake256_input,
        sizeof(shake256_input),
        shake256_output,
        sizeof(shake256_output),
    },
    { "CSHAKE256",
        shake256_input, sizeof(shake256_input),
        shake256_output, sizeof(shake256_output),
        64 },
    { "CSHAKE256",
        shake256_input, sizeof(shake256_input),
        cshake256_output, sizeof(cshake256_output),
        64,
        "KMAC",
        "Custom" },
    { "TURBOSHAKE128",
        empty_input, 0,
        turboshake128_empty_output, sizeof(turboshake128_empty_output),
        32 },
    { "TURBOSHAKE256",
        empty_input, 0,
        turboshake256_empty_output, sizeof(turboshake256_empty_output),
        64 },
    { "KT128",
        empty_input, 0,
        kt128_empty_output, sizeof(kt128_empty_output),
        32 },
    { "KT256",
        empty_input, 0,
        kt256_empty_output, sizeof(kt256_empty_output),
        64 },
};

static const unsigned char shake256_largemsg_input[] = {
    0xb2, 0xd2, 0x38, 0x65, 0xaf, 0x8f, 0x25, 0x6e,
    0x64, 0x40, 0xe2, 0x0d, 0x49, 0x8e, 0x3e, 0x64,
    0x46, 0xd2, 0x03, 0xa4, 0x19, 0xe3, 0x7b, 0x80,
    0xf7, 0x2b, 0x32, 0xe2, 0x76, 0x01, 0xfe, 0xdd,
    0xaa, 0x33, 0x3d, 0xe4, 0x8e, 0xe1, 0x5e, 0x39,
    0xa6, 0x92, 0xa3, 0xa7, 0xe3, 0x81, 0x24, 0x74,
    0xc7, 0x38, 0x18, 0x92, 0xc9, 0x60, 0x50, 0x15,
    0xfb, 0xd8, 0x04, 0xea, 0xea, 0x04, 0xd2, 0xc5,
    0xc6, 0x68, 0x04, 0x5b, 0xc3, 0x75, 0x12, 0xd2,
    0xbe, 0xa2, 0x67, 0x75, 0x24, 0xbf, 0x68, 0xad,
    0x10, 0x86, 0xb3, 0x2c, 0xb3, 0x74, 0xa4, 0x6c,
    0xf9, 0xd7, 0x1e, 0x58, 0x69, 0x27, 0x88, 0x49,
    0x4e, 0x99, 0x15, 0x33, 0x14, 0xf2, 0x49, 0x21,
    0xf4, 0x99, 0xb9, 0xde, 0xd4, 0xf1, 0x12, 0xf5,
    0x68, 0xe5, 0x5c, 0xdc, 0x9e, 0xc5, 0x80, 0x6d,
    0x39, 0x50, 0x08, 0x95, 0xbb, 0x12, 0x27, 0x50,
    0x89, 0xf0, 0xf9, 0xd5, 0x4a, 0x01, 0x0b, 0x0d,
    0x90, 0x9f, 0x1e, 0x4a, 0xba, 0xbe, 0x28, 0x36,
    0x19, 0x7d, 0x9c, 0x0a, 0x51, 0xfb, 0xeb, 0x00,
    0x02, 0x6c, 0x4b, 0x0a, 0xa8, 0x6c, 0xb7, 0xc4,
    0xc0, 0x92, 0x37, 0xa7, 0x2d, 0x49, 0x61, 0x80,
    0xd9, 0xdb, 0x20, 0x21, 0x9f, 0xcf, 0xb4, 0x57,
    0x69, 0x75, 0xfa, 0x1c, 0x95, 0xbf, 0xee, 0x0d,
    0x9e, 0x52, 0x6e, 0x1e, 0xf8, 0xdd, 0x41, 0x8c,
    0x3b, 0xaa, 0x57, 0x13, 0x84, 0x73, 0x52, 0x62,
    0x18, 0x76, 0x46, 0xcc, 0x4b, 0xcb, 0xbd, 0x40,
    0xa1, 0xf6, 0xff, 0x7b, 0x32, 0xb9, 0x90, 0x7c,
    0x53, 0x2c, 0xf9, 0x38, 0x72, 0x0f, 0xcb, 0x90,
    0x42, 0x5e, 0xe2, 0x80, 0x19, 0x26, 0xe7, 0x99,
    0x96, 0x98, 0x18, 0xb1, 0x86, 0x5b, 0x4c, 0xd9,
    0x08, 0x27, 0x31, 0x8f, 0xf0, 0x90, 0xd9, 0x35,
    0x6a, 0x1f, 0x75, 0xc2, 0xe0, 0xa7, 0x60, 0xb8,
    0x1d, 0xd6, 0x5f, 0x56, 0xb2, 0x0b, 0x27, 0x0e,
    0x98, 0x67, 0x1f, 0x39, 0x18, 0x27, 0x68, 0x0a,
    0xe8, 0x31, 0x1b, 0xc0, 0x97, 0xec, 0xd1, 0x20,
    0x2a, 0x55, 0x69, 0x23, 0x08, 0x50, 0x05, 0xec,
    0x13, 0x3b, 0x56, 0xfc, 0x18, 0xc9, 0x1a, 0xa9,
    0x69, 0x0e, 0xe2, 0xcc, 0xc8, 0xd6, 0x19, 0xbb,
    0x87, 0x3b, 0x42, 0x77, 0xee, 0x77, 0x81, 0x26,
    0xdd, 0xf6, 0x5d, 0xc3, 0xb2, 0xb0, 0xc4, 0x14,
    0x6d, 0xb5, 0x4f, 0xdc, 0x13, 0x09, 0xc8, 0x53,
    0x50, 0xb3, 0xea, 0xd3, 0x5f, 0x11, 0x67, 0xd4,
    0x2f, 0x6e, 0x30, 0x1a, 0xbe, 0xd6, 0xf0, 0x2d,
    0xc9, 0x29, 0xd9, 0x0a, 0xa8, 0x6f, 0xa4, 0x18,
    0x74, 0x6b, 0xd3, 0x5d, 0x6a, 0x73, 0x3a, 0xf2,
    0x94, 0x7f, 0xbd, 0xb4, 0xa6, 0x7f, 0x5b, 0x3d,
    0x26, 0xf2, 0x6c, 0x13, 0xcf, 0xb4, 0x26, 0x1e,
    0x38, 0x17, 0x66, 0x60, 0xb1, 0x36, 0xae, 0xe0,
    0x6d, 0x86, 0x69, 0xe7, 0xe7, 0xae, 0x77, 0x6f,
    0x7e, 0x99, 0xe5, 0xd9, 0x62, 0xc9, 0xfc, 0xde,
    0xb4, 0xee, 0x7e, 0xc8, 0xe9, 0xb7, 0x2c, 0xe2,
    0x70, 0xe8, 0x8b, 0x2d, 0x94, 0xad, 0xe8, 0x54,
    0xa3, 0x2d, 0x9a, 0xe2, 0x50, 0x63, 0x87, 0xb3,
    0x56, 0x29, 0xea, 0xa8, 0x5e, 0x96, 0x53, 0x9f,
    0x23, 0x8a, 0xef, 0xa3, 0xd4, 0x87, 0x09, 0x5f,
    0xba, 0xc3, 0xd1, 0xd9, 0x1a, 0x7b, 0x5c, 0x5d,
    0x5d, 0x89, 0xed, 0xb6, 0x6e, 0x39, 0x73, 0xa5,
    0x64, 0x59, 0x52, 0x8b, 0x61, 0x8f, 0x66, 0x69,
    0xb9, 0xf0, 0x45, 0x0a, 0x57, 0xcd, 0xc5, 0x7f,
    0x5d, 0xd0, 0xbf, 0xcc, 0x0b, 0x48, 0x12, 0xe1,
    0xe2, 0xc2, 0xea, 0xcc, 0x09, 0xd9, 0x42, 0x2c,
    0xef, 0x4f, 0xa7, 0xe9, 0x32, 0x5c, 0x3f, 0x22,
    0xc0, 0x45, 0x0b, 0x67, 0x3c, 0x31, 0x69, 0x29,
    0xa3, 0x39, 0xdd, 0x6e, 0x2f, 0xbe, 0x10, 0xc9,
    0x7b, 0xff, 0x19, 0x8a, 0xe9, 0xea, 0xfc, 0x32,
    0x41, 0x33, 0x70, 0x2a, 0x9a, 0xa4, 0xe6, 0xb4,
    0x7e, 0xb4, 0xc6, 0x21, 0x49, 0x5a, 0xfc, 0x45,
    0xd2, 0x23, 0xb3, 0x28, 0x4d, 0x83, 0x60, 0xfe,
    0x70, 0x68, 0x03, 0x59, 0xd5, 0x15, 0xaa, 0x9e,
    0xa0, 0x2e, 0x36, 0xb5, 0x61, 0x0f, 0x61, 0x05,
    0x3c, 0x62, 0x00, 0xa0, 0x47, 0xf1, 0x86, 0xba,
    0x33, 0xb8, 0xca, 0x60, 0x2f, 0x3f, 0x0a, 0x67,
    0x09, 0x27, 0x2f, 0xa2, 0x96, 0x02, 0x52, 0x58,
    0x55, 0x68, 0x80, 0xf4, 0x4f, 0x47, 0xba, 0xff,
    0x41, 0x7a, 0x40, 0x4c, 0xfd, 0x9d, 0x10, 0x72,
    0x0e, 0x20, 0xa9, 0x7f, 0x9b, 0x9b, 0x14, 0xeb,
    0x8e, 0x61, 0x25, 0xcb, 0xf4, 0x58, 0xff, 0x47,
    0xa7, 0x08, 0xd6, 0x4e, 0x2b, 0xf1, 0xf9, 0x89,
    0xd7, 0x22, 0x0f, 0x8d, 0x35, 0x07, 0xa0, 0x54,
    0xab, 0x83, 0xd8, 0xee, 0x5a, 0x3e, 0x88, 0x74,
    0x46, 0x41, 0x6e, 0x3e, 0xb7, 0xc0, 0xb6, 0x55,
    0xe0, 0x36, 0xc0, 0x2b, 0xbf, 0xb8, 0x24, 0x8a,
    0x44, 0x82, 0xf4, 0xcb, 0xb5, 0xd7, 0x41, 0x48,
    0x51, 0x08, 0xe0, 0x14, 0x34, 0xd2, 0x6d, 0xe9,
    0x7a, 0xec, 0x91, 0x61, 0xa7, 0xe1, 0x81, 0x69,
    0x47, 0x1c, 0xc7, 0xf3
};

static const unsigned char shake256_largemsg_output[] = {
    0x64, 0xea, 0x24, 0x6a, 0xab, 0x80, 0x37, 0x9e,
    0x08, 0xe2, 0x19, 0x9e, 0x09, 0x69, 0xe2, 0xee,
    0x1a, 0x5d, 0xd1, 0x68, 0x68, 0xec, 0x8d, 0x42,
    0xd0, 0xf8, 0xb8, 0x44, 0x74, 0x54, 0x87, 0x3e
};

static const TEST_DATA large_msg_test_data[] = {
    {
        "SHAKE256",
        shake256_largemsg_input,
        sizeof(shake256_largemsg_input),
        shake256_largemsg_output,
        sizeof(shake256_largemsg_output),
    },
};

static EVP_MD_CTX *xof_digest_setup(const TEST_DATA *td)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    OSSL_PARAM params[3], *p = params;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, td->alg, NULL)))
        return NULL;

    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;
    if (td->param_n != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DIGEST_PARAM_FUNCTION_NAME, (char *)td->param_n, 0);
    if (td->param_s != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DIGEST_PARAM_CUSTOMIZATION, (char *)td->param_s, 0);
    *p = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_DigestInit_ex2(ctx, md, params)))
        goto err;
    EVP_MD_free(md);
    return ctx;
err:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    return NULL;
}

static int xof_kat_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    uint8_t out[2048];

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, td->outlen))
        || !TEST_mem_eq(out, td->outlen, td->out, td->outlen)
        /* Test that a second call to EVP_DigestFinalXOF fails */
        || !TEST_false(EVP_DigestFinalXOF(ctx, out, td->outlen))
        /* Test that a call to EVP_DigestSqueeze fails */
        || !TEST_false(EVP_DigestSqueeze(ctx, out, td->outlen)))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int xof_kat_digestfinal_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    unsigned int digest_length = 0;
    EVP_MD_CTX *ctx = NULL;
    uint8_t out[2048];

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen)))
        goto err;
    if (td->default_xoflen == 0) {
        /*
         * Test that EVP_DigestFinal without setting XOFLEN fails for SHAKE
         * (The original code for SHAKE set the wrong default value which is
         * why the XOF needs to be set for this).
         */
        ERR_set_mark();
        if (!TEST_false(EVP_DigestFinal(ctx, out, &digest_length))) {
            ERR_clear_last_mark();
            goto err;
        }
        ERR_pop_to_mark();
    } else {
        /*
         * Test that EVP_DigestFinal without setting XOFLEN passes for CSHAKE
         * and correctly returns 2 * 256 = 512 bits (64 bytes) by default.
         */
        if (!TEST_true(EVP_DigestFinal(ctx, out, &digest_length))
            || !TEST_uint_eq(digest_length, td->default_xoflen)
            || !TEST_mem_eq(out, digest_length, td->out, digest_length))
            goto err;
    }
    EVP_MD_CTX_free(ctx);

    /* EVP_DigestFinalXOF must work */
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen)))
        goto err;
    if (!TEST_true(EVP_DigestFinalXOF(ctx, out, td->outlen))
        || !TEST_mem_eq(out, td->outlen, td->out, td->outlen)
        || !TEST_false(EVP_DigestFinalXOF(ctx, out, td->outlen)))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Test that EVP_DigestFinal() returns the output length
 * set by the OSSL_DIGEST_PARAM_XOFLEN param.
 */
static int xof_kat_digestfinal_xoflen_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    unsigned int digest_length = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md;
    OSSL_PARAM params[2];
    size_t sz = 12;
    uint8_t out[2048];

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;

    md = EVP_MD_CTX_get0_md(ctx);

    memset(out, 0, td->outlen);
    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &sz);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_int_eq(EVP_MD_CTX_size(ctx), td->default_xoflen == 0 ? -1 : td->default_xoflen)
        || !TEST_int_eq(EVP_MD_CTX_set_params(ctx, params), 1)
        || !TEST_int_eq(EVP_MD_CTX_size(ctx), (int)sz)
        || !TEST_int_eq(EVP_MD_get_size(md), td->default_xoflen)
        || !TEST_true(EVP_MD_xof(md))
        || !TEST_true(EVP_DigestUpdate(ctx, td->in, td->inlen))
        || !TEST_true(EVP_DigestFinal(ctx, out, &digest_length))
        || !TEST_uint_eq(digest_length, (unsigned int)sz)
        || !TEST_mem_eq(out, digest_length, td->out, digest_length)
        || !TEST_uchar_eq(out[digest_length], 0))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Test that multiple absorb calls gives the expected result.
 * This is a nested test that uses multiple strides for the input.
 */
static int xof_absorb_test(int tstid)
{
    const TEST_DATA *td = large_msg_test_data + tstid;
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char out[2048];
    size_t total = td->inlen;
    size_t i, stride, sz;

    if (!TEST_size_t_le(td->outlen, sizeof(out)))
        return 0;
    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;

    for (stride = 1; stride < total; ++stride) {
        sz = 0;
        for (i = 0; i < total; i += sz) {
            sz += stride;
            if ((i + sz) > total)
                sz = total - i;
            if (!TEST_true(EVP_DigestUpdate(ctx, td->in + i, sz)))
                goto err;
        }
        if (!TEST_true(EVP_DigestFinalXOF(ctx, out, td->outlen))
            || !TEST_mem_eq(out, td->outlen, td->out, td->outlen))
            goto err;
        if (!TEST_true(EVP_DigestInit_ex2(ctx, NULL, NULL)))
            goto err;
    }
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Table containing the size of the output to squeeze for the
 * initially call, followed by a size for each subsequent call.
 */
typedef struct stride_test_data_st {
    size_t startsz, incsz;
} STRIDE_TEST_DATA;

static const STRIDE_TEST_DATA stride_test_data[] = {
    { 1, 1 },
    { 1, 136 },
    { 1, 136 / 2 },
    { 1, 136 / 2 - 1 },
    { 1, 136 / 2 + 1 },
    { 1, 136 * 3 },
    { 8, 8 },
    { 9, 9 },
    { 10, 10 },
    { 136 / 2 - 1, 136 },
    { 136 / 2 - 1, 136 - 1 },
    { 136 / 2 - 1, 136 + 1 },
    { 136 / 2, 136 },
    { 136 / 2, 136 - 1 },
    { 136 / 2, 136 + 1 },
    { 136 / 2 + 1, 136 },
    { 136 / 2 + 1, 136 - 1 },
    { 136 / 2 + 1, 136 + 1 },
    { 136, 2 },
    { 136, 136 },
    { 136 - 1, 136 },
    { 136 - 1, 136 - 1 },
    { 136 - 1, 136 + 1 },
    { 136 + 1, 136 },
    { 136 + 1, 136 - 1 },
    { 136 + 1, 136 + 1 },
    { 136 * 3, 136 },
    { 136 * 3, 136 + 1 },
    { 136 * 3, 136 - 1 },
    { 136 * 3, 136 / 2 },
    { 136 * 3, 136 / 2 + 1 },
    { 136 * 3, 136 / 2 - 1 },
};

/*
 * Helper to do multiple squeezes of output data using SHAKE256.
 * tst is an index into the stride_tests[] containing an initial starting
 * output length, followed by a second output length to use for all remaining
 * squeezes. expected_outlen contains the total number of bytes to squeeze.
 * in and inlen represent the input to absorb. expected_out and expected_outlen
 * represent the expected output.
 */
static int do_xof_squeeze_test(const TEST_DATA *td,
    const STRIDE_TEST_DATA *stride,
    const uint8_t *in, size_t inlen,
    const uint8_t *expected_out,
    size_t expected_outlen)
{
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *out = NULL;
    size_t i = 0, sz = stride->startsz;

    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    if (!TEST_ptr(out = OPENSSL_malloc(expected_outlen)))
        goto err;
    if (!TEST_true(EVP_DigestUpdate(ctx, in, inlen)))
        goto err;

    while (i < expected_outlen) {
        if ((i + sz) > expected_outlen)
            sz = expected_outlen - i;
        if (!TEST_true(EVP_DigestSqueeze(ctx, out + i, sz)))
            goto err;
        i += sz;
        sz = stride->incsz;
    }
    if (!TEST_mem_eq(out, expected_outlen, expected_out, expected_outlen))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int xof_squeeze_kat_test(int tstid)
{
    const STRIDE_TEST_DATA *sd = stride_test_data + tstid;
    const TEST_DATA *td = xof_test_data + (tstid % (OSSL_NELEM(xof_test_data)));

    return do_xof_squeeze_test(td, sd, td->in, td->inlen, td->out, td->outlen);
}

/*
 * Generate some random input to absorb, and then
 * squeeze it out in one operation to get a expected
 * output. Use this to test that multiple squeeze calls
 * on the same input gives the same output.
 */
static int xof_squeeze_large_test(int tstid)
{
    const STRIDE_TEST_DATA *sd = stride_test_data + tstid;
    const TEST_DATA *td = xof_test_data + (tstid % (OSSL_NELEM(xof_test_data)));
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char msg[16];
    unsigned char out[2000];

    if (!TEST_int_gt(RAND_bytes(msg, sizeof(msg)), 0)
        || !TEST_ptr(ctx = xof_digest_setup(td))
        || !TEST_true(EVP_DigestUpdate(ctx, msg, sizeof(msg)))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, sizeof(out))))
        goto err;

    ret = do_xof_squeeze_test(td, sd, msg, sizeof(msg), out, sizeof(out));
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static const size_t dupoffset_test_data[] = {
    1, 135, 136, 137, 136 * 3 - 1, 136 * 3, 136 * 3 + 1
};

/* Helper function to test that EVP_MD_CTX_dup() copies the internal state */
static int do_xof_squeeze_dup_test(const TEST_DATA *td, size_t dupoffset,
    const uint8_t *in, size_t inlen,
    const uint8_t *expected_out, size_t expected_outlen)
{
    int ret = 0;
    EVP_MD_CTX *cur, *ctx = NULL, *dupctx = NULL;
    unsigned char *out = NULL;
    size_t i = 0, sz = 10;

    if (!TEST_ptr(ctx = xof_digest_setup(td)))
        return 0;
    cur = ctx;
    if (!TEST_ptr(out = OPENSSL_malloc(expected_outlen)))
        goto err;
    if (!TEST_true(EVP_DigestUpdate(ctx, in, inlen)))
        goto err;

    while (i < expected_outlen) {
        if ((i + sz) > expected_outlen)
            sz = expected_outlen - i;
        if (!TEST_true(EVP_DigestSqueeze(cur, out + i, sz)))
            goto err;
        i += sz;
        /* At a certain offset we swap to a new ctx that copies the state */
        if (dupctx == NULL && i >= dupoffset) {
            if (!TEST_ptr(dupctx = EVP_MD_CTX_dup(ctx)))
                goto err;
            cur = dupctx;
        }
    }
    if (!TEST_mem_eq(out, expected_outlen, expected_out, expected_outlen))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(dupctx);
    return ret;
}

/* Test that the internal state can be copied */
static int xof_squeeze_dup_test(int tstid)
{
    size_t dupoffset = dupoffset_test_data[tstid];
    const TEST_DATA *td = xof_test_data + (tstid % (OSSL_NELEM(xof_test_data)));
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char msg[16];
    unsigned char out[1000];

    if (!TEST_int_gt(RAND_bytes(msg, sizeof(msg)), 0)
        || !TEST_ptr(ctx = xof_digest_setup(td))
        || !TEST_true(EVP_DigestUpdate(ctx, msg, sizeof(msg)))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, sizeof(out))))
        goto err;

    ret = do_xof_squeeze_dup_test(td, dupoffset, msg, sizeof(msg),
        out, sizeof(out));
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/* Test that a squeeze without a preceding absorb works */
static int xof_squeeze_no_absorb_test(int tstid)
{
    const TEST_DATA *td = xof_test_data + tstid;
    int ret = 0;
    EVP_MD_CTX *ctx = NULL, *ctx2 = NULL;
    unsigned char out[1000];
    unsigned char out2[1000];

    memset(out, 0, sizeof(out));
    memset(out2, 0, sizeof(out2));
    if (!TEST_ptr(ctx = xof_digest_setup(td))
        || !TEST_ptr(ctx2 = EVP_MD_CTX_dup(ctx))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, sizeof(out)))
        || !TEST_true(EVP_DigestSqueeze(ctx2, out2, sizeof(out2) / 2))
        || !TEST_true(EVP_DigestSqueeze(ctx2, out2 + sizeof(out2) / 2,
            sizeof(out2) / 2))
        || !TEST_mem_eq(out2, sizeof(out2), out, sizeof(out)))
        goto err;
    ret = 1;

err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx2);
    return ret;
}

static void fill_ptn(unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (unsigned char)(i % 251);
}

static int digest_xof_with_params_ex(OSSL_LIB_CTX *libctx, const char *propq,
    const char *alg, const unsigned char *in, size_t inlen,
    const OSSL_PARAM params[], unsigned char *out, size_t outlen)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(libctx, alg, propq))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, params))
        || !TEST_true(EVP_DigestUpdate(ctx, in, inlen))
        || !TEST_true(EVP_DigestFinalXOF(ctx, out, outlen)))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int digest_xof_with_params(const char *alg, const unsigned char *in,
    size_t inlen, const OSSL_PARAM params[], unsigned char *out, size_t outlen)
{
    return digest_xof_with_params_ex(NULL, NULL, alg, in, inlen, params, out,
        outlen);
}

static int digest_xof_chunked_with_params(const char *alg,
    const unsigned char *in, size_t inlen, const OSSL_PARAM params[],
    unsigned char *out, size_t outlen)
{
    static const size_t chunks[] = { 1, 7, 136, 168, 8191, 3, 257 };
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t i = 0, off = 0, len;
    int ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, alg, NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, params)))
        goto err;

    while (off < inlen) {
        len = chunks[i++ % OSSL_NELEM(chunks)];
        if (len > inlen - off)
            len = inlen - off;
        if (!TEST_true(EVP_DigestUpdate(ctx, in + off, len)))
            goto err;
        off += len;
    }

    if (!TEST_true(EVP_DigestFinalXOF(ctx, out, outlen)))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

typedef struct turboshake_kt_data_st {
    const char *alg;
    int is_kt;
    size_t outlen;
} TURBOSHAKE_KT_DATA;

static const TURBOSHAKE_KT_DATA turboshake_kt_tests[] = {
    { "TURBOSHAKE128", 0, 32 },
    { "TURBOSHAKE256", 0, 64 },
    { "KT128", 1, 32 },
    { "KT256", 1, 64 },
};

static int turboshake_kt_chunked_absorb_and_size_test(int tstid)
{
    const TURBOSHAKE_KT_DATA *td = turboshake_kt_tests + tstid;
    unsigned char *msg = NULL, *one_shot = NULL, *chunked = NULL, *noop = NULL;
    unsigned char custom[41], z = 0;
    unsigned int domain = 2;
    size_t msglen = 9005, outlen = td->outlen;
    OSSL_PARAM params[4], *p = params;
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(msg = OPENSSL_malloc(msglen))
        || !TEST_ptr(one_shot = OPENSSL_malloc(outlen))
        || !TEST_ptr(chunked = OPENSSL_malloc(outlen))
        || !TEST_ptr(noop = OPENSSL_malloc(outlen)))
        goto err;
    fill_ptn(msg, msglen);
    fill_ptn(custom, sizeof(custom));

    *p++ = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &outlen);
    if (td->is_kt) {
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, sizeof(custom));
    } else {
        *p++ = OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR,
            &domain);
    }
    *p = OSSL_PARAM_construct_end();

    if (!digest_xof_with_params(td->alg, msg, msglen, params, one_shot, outlen)
        || !digest_xof_chunked_with_params(td->alg, msg, msglen, params,
            chunked, outlen)
        || !TEST_mem_eq(chunked, outlen, one_shot, outlen))
        goto err;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, td->alg, NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || !TEST_true(EVP_DigestSqueeze(ctx, &z, 0))
        || !TEST_true(EVP_MD_CTX_set_params(ctx, params))
        || !TEST_true(EVP_DigestUpdate(ctx, msg, msglen))
        || !TEST_true(EVP_DigestFinalXOF(ctx, noop, outlen))
        || !TEST_mem_eq(noop, outlen, one_shot, outlen))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    OPENSSL_free(noop);
    OPENSSL_free(chunked);
    OPENSSL_free(one_shot);
    OPENSSL_free(msg);
    return ret;
}

static int turboshake_kt_copyctx_test(int tstid)
{
    const TURBOSHAKE_KT_DATA *td = turboshake_kt_tests + tstid;
    unsigned char msg[257], expected[64], copied[64];
    unsigned char custom[41];
    unsigned int domain = 3;
    size_t outlen = td->outlen;
    OSSL_PARAM params[4], *p = params;
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL, *copy = NULL;
    int ret = 0;

    fill_ptn(msg, sizeof(msg));
    fill_ptn(custom, sizeof(custom));

    *p++ = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &outlen);
    if (td->is_kt) {
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, sizeof(custom));
    } else {
        *p++ = OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR,
            &domain);
    }
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, td->alg, NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_ptr(copy = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, params))
        || !TEST_true(EVP_DigestInit_ex2(copy, md, params))
        || !TEST_true(EVP_DigestUpdate(ctx, msg, sizeof(msg)))
        || !TEST_true(EVP_MD_CTX_copy_ex(copy, ctx))
        || !TEST_true(EVP_DigestFinalXOF(ctx, expected, outlen))
        || !TEST_true(EVP_DigestFinalXOF(copy, copied, outlen))
        || !TEST_mem_eq(copied, outlen, expected, outlen))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(copy);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int turboshake_kt_xoflen_alias_conflict_test(int tstid)
{
    const TURBOSHAKE_KT_DATA *td = turboshake_kt_tests + tstid;
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t xoflen = td->outlen, size = td->outlen;
    OSSL_PARAM params[3];
    int i, ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, td->alg, NULL)))
        goto err;

    for (i = 0; i < 2; i++) {
        if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
            goto err;
        if (i == 0) {
            params[0] = OSSL_PARAM_construct_size_t(
                OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
            params[1] = OSSL_PARAM_construct_size_t(
                OSSL_DIGEST_PARAM_SIZE, &size);
        } else {
            params[0] = OSSL_PARAM_construct_size_t(
                OSSL_DIGEST_PARAM_SIZE, &size);
            params[1] = OSSL_PARAM_construct_size_t(
                OSSL_DIGEST_PARAM_XOFLEN, &xoflen);
        }
        params[2] = OSSL_PARAM_construct_end();

        ERR_set_mark();
        if (!TEST_false(EVP_DigestInit_ex2(ctx, md, params))) {
            ERR_clear_last_mark();
            goto err;
        }
        ERR_pop_to_mark();
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int turboshake_kt_repeated_param_test(void)
{
    static char custom_utf8[] = "Custom";
    static unsigned char custom_octet[] = {
        'C', 'u', 's', 't', 'o', 'm'
    };
    unsigned int domain1 = 1, domain2 = 2;
    OSSL_PARAM params[3];
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "TURBOSHAKE128", NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    params[0] = OSSL_PARAM_construct_uint(
        OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR, &domain1);
    params[1] = OSSL_PARAM_construct_uint(
        OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR, &domain2);
    params[2] = OSSL_PARAM_construct_end();
    ERR_set_mark();
    if (!TEST_false(EVP_DigestInit_ex2(ctx, md, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    ctx = NULL;
    md = NULL;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "KT128", NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom_utf8, 0);
    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom_octet, sizeof(custom_octet));
    params[2] = OSSL_PARAM_construct_end();
    ERR_set_mark();
    if (!TEST_false(EVP_DigestInit_ex2(ctx, md, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

#define TURBOSHAKE_KT_NO_CUSTOM SIZE_MAX

typedef enum turboshake_kt_input_kind_e {
    TURBOSHAKE_KT_INPUT_EMPTY,
    TURBOSHAKE_KT_INPUT_HEX,
    TURBOSHAKE_KT_INPUT_PTN
} TURBOSHAKE_KT_INPUT_KIND;

typedef struct turboshake_kt_vector_st {
    const char *alg;
    TURBOSHAKE_KT_INPUT_KIND input_kind;
    size_t input_len;
    const char *input_hex;
    size_t outlen;
    const char *expected_hex;
    int has_domain;
    unsigned int domain;
    size_t custom_len;
    int suffix_only;
} TURBOSHAKE_KT_VECTOR;

/*
 * The TurboSHAKE and KangarooTwelve test vectors in this table are from
 * RFC 9861.
 */
static const TURBOSHAKE_KT_VECTOR turboshake_kt_vectors[] = {
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_PTN, 1, NULL, 32,
        "55cedd6f60af7bb29a4042ae832ef3f58db7299f893ebb9247247d856958daa9", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_PTN, 17, NULL, 32,
        "9c97d036a3bac819db70ede0ca554ec6e4c2a1a4ffbfd9ec269ca6a111161233", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_PTN, 289, NULL, 32,
        "96c77c279e0126f7fc07c9b07f5cdae1e0be60bdbe10620040e75d7223a624d2", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_PTN, 4913, NULL, 32,
        "d4976eb56bcf118520582b709f73e1d6853e001fdaf80e1b13e0d0599d5fb372", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_PTN, 83521, NULL, 32,
        "da67c7039e98bf530cf7a37830c6664e14cbab7f540f58403b1b82951318ee5c", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_PTN, 1419857, NULL, 32,
        "b97a906fbf83ef7c812517abf3b2d0aea0c4f60318ce11cf103925127f59eecd", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_PTN, 24137569, NULL, 32,
        "35cd494adeded2f25239af09a7b8ef0c4d1ca4fe2d1ac370fa63216fe7b4c2b1", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_PTN, 1, NULL, 64,
        "3e1712f928f8eaf1054632b2aa0a246ed8b0c378728f60bc970410155c28820e90cc90d8a3006aa2372c5c5ea176b0682bf22bae7467ac94f74d43d39b0482e2", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_PTN, 17, NULL, 64,
        "b3bab0300e6a191fbe6137939835923578794ea54843f5011090fa2f3780a9e5cb22c59d78b40a0fbff9e672c0fbe0970bd2c845091c6044d687054da5d8e9c7", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_PTN, 289, NULL, 64,
        "66b810db8e90780424c0847372fdc95710882fde31c6df75beb9d4cd9305cfcae35e7b83e8b7e6eb4b78605880116316fe2c078a09b94ad7b8213c0a738b65c0", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_PTN, 4913, NULL, 64,
        "c74ebc919a5b3b0dd1228185ba02d29ef442d69d3d4276a93efe0bf9a16a7dc0cd4eabadab8cd7a5edd96695f5d360abe09e2c6511a3ec397da3b76b9e1674fb", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_PTN, 83521, NULL, 64,
        "02cc3a8897e6f4f6ccb6fd46631b1f5207b66c6de9c7b55b2d1a23134a170afdac234eaba9a77cff88c1f020b73724618c5687b362c430b248cd38647f848a1d", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_PTN, 1419857, NULL, 64,
        "add53b06543e584b5823f626996aee50fe45ed15f20243a7165485acb4aa76b4ffda75cedf6d8cdc95c332bd56f4b986b58bb17d1778bfc1b1a97545cdf4ec9f", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_PTN, 24137569, NULL, 64,
        "9e11bc59c24e73993c1484ec66358ef71db74aefd84e123f7800ba9c4853e02cfe701d9e6bb765a304f0dc34a4ee3ba82c410f0da70e86bfbd90ea877c2d6104", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 1, NULL, 32,
        "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 17, NULL, 32,
        "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 289, NULL, 32,
        "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 4913, NULL, 32,
        "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 83521, NULL, 32,
        "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 1419857, NULL, 32,
        "844d610933b1b9963cbdeb5ae3b6b05cc7cbd67ceedf883eb678a0a8e0371682", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 24137569, NULL, 32,
        "3c390782a8a4e89fa6367f72feaaf13255c8d95878481d3cd8ce85f58e880af8", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_EMPTY, 0, NULL, 32,
        "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583", 0, 0, 1, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_HEX, 0, "ff", 32,
        "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4", 0, 0, 41, 0 },
#if 0
    /*
     * These RFC 9861 vectors use customization strings longer than OpenSSL's
     * provider limit of 512 bytes, matching CSHAKE.
     */
    { "KT128", TURBOSHAKE_KT_INPUT_HEX, 0, "ffffff", 32,
        "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74", 0, 0, 1681, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_HEX, 0, "ffffffffffffff", 32,
        "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf", 0, 0, 68921, 0 },
#endif
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 8191, NULL, 32,
        "1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 8192, NULL, 32,
        "48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
#if 0
    /*
     * These RFC 9861 tree-boundary vectors use customization strings longer
     * than OpenSSL's provider limit of 512 bytes, matching CSHAKE.
     */
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 8192, NULL, 32,
        "3ed12f70fb05ddb58689510ab3e4d23c6c6033849aa01e1d8c220a297fedcd0b", 0, 0, 8189, 0 },
    { "KT128", TURBOSHAKE_KT_INPUT_PTN, 8192, NULL, 32,
        "6a7c1b6a5cd0d8c9ca943a4a216cc64604559a2ea45f78570a15253d67ba00ae", 0, 0, 8190, 0 },
#endif
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 1, NULL, 64,
        "0d005a194085360217128cf17f91e1f71314efa5564539d444912e3437efa17f82db6f6ffe76e781eaa068bce01f2bbf81eacb983d7230f2fb02834a21b1ddd0", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 17, NULL, 64,
        "1ba3c02b1fc514474f06c8979978a9056c8483f4a1b63d0dccefe3a28a2f323e1cdcca40ebf006ac76ef0397152346837b1277d3e7faa9c9653b19075098527b", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 289, NULL, 64,
        "de8ccbc63e0f133ebb4416814d4c66f691bbf8b6a61ec0a7700f836b086cb029d54f12ac7159472c72db118c35b4e6aa213c6562caaa9dcc518959e69b10f3ba", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 4913, NULL, 64,
        "647efb49fe9d717500171b41e7f11bd491544443209997ce1c2530d15eb1ffbb598935ef954528ffc152b1e4d731ee2683680674365cd191d562bae753b84aa5", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 83521, NULL, 64,
        "b06275d284cd1cf205bcbe57dccd3ec1ff6686e3ed15776383e1f2fa3c6ac8f08bf8a162829db1a44b2a43ff83dd89c3cf1ceb61ede659766d5ccf817a62ba8d", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 1419857, NULL, 64,
        "9473831d76a4c7bf77ace45b59f1458b1673d64bcd877a7c66b2664aa6dd149e60eab71b5c2bab858c074ded81ddce2b4022b5215935c0d4d19bf511aeeb0772", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 24137569, NULL, 64,
        "0652b740d78c5e1f7c8dcc1777097382768b7ff38f9a7a20f29f413bb1b3045b31a5578f568f911e09cf44746da84224a5266e96a4a535e871324e4f9c7004da", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_EMPTY, 0, NULL, 64,
        "9280f5cc39b54a5a594ec63de0bb99371e4609d44bf845c2f5b8c316d72b159811f748f23e3fabbe5c3226ec96c62186df2d33e9df74c5069ceecbb4dd10eff6", 0, 0, 1, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_HEX, 0, "ff", 64,
        "47ef96dd616f200937aa7847e34ec2feae8087e3761dc0f8c1a154f51dc9ccf845d7adbce57ff64b639722c6a1672e3bf5372d87e00aff89be97240756998853", 0, 0, 41, 0 },
#if 0
    /*
     * These RFC 9861 vectors use customization strings longer than OpenSSL's
     * provider limit of 512 bytes, matching CSHAKE.
     */
    { "KT256", TURBOSHAKE_KT_INPUT_HEX, 0, "ffffff", 64,
        "3b48667a5051c5966c53c5d42b95de451e05584e7806e2fb765eda959074172cb438a9e91dde337c98e9c41bed94c4e0aef431d0b64ef2324f7932caa6f54969", 0, 0, 1681, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_HEX, 0, "ffffffffffffff", 64,
        "e0911cc00025e1540831e266d94add9b98712142b80d2629e643aac4efaf5a3a30a88cbf4ac2a91a2432743054fbcc9897670e86ba8cec2fc2ace9c966369724", 0, 0, 68921, 0 },
#endif
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 8191, NULL, 64,
        "3081434d93a4108d8d8a3305b89682cebedc7ca4ea8a3ce869fbb73cbe4a58eef6f24de38ffc170514c70e7ab2d01f03812616e863d769afb3753193ba045b20", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 8192, NULL, 64,
        "c6ee8e2ad3200c018ac87aaa031cdac22121b412d07dc6e0dccbb53423747e9a1c18834d99df596cf0cf4b8dfafb7bf02d139d0c9035725adc1a01b7230a41fa", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 0 },
#if 0
    /*
     * These RFC 9861 tree-boundary vectors use customization strings longer
     * than OpenSSL's provider limit of 512 bytes, matching CSHAKE.
     */
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 8192, NULL, 64,
        "74e47879f10a9c5d11bd2da7e194fe57e86378bf3c3f7448eff3c576a0f18c5caae0999979512090a7f348af4260d4de3c37f1ecaf8d2c2c96c1d16c64b12496", 0, 0, 8189, 0 },
    { "KT256", TURBOSHAKE_KT_INPUT_PTN, 8192, NULL, 64,
        "f4b5908b929ffe01e0f79ec2f21243d41a396b2e7303a6af1d6399cd6c7a0a2dd7c4f607e8277f9c9b1cb4ab9ddc59d4b92d1fc7558441f1832c3279a4241b8b", 0, 0, 8190, 0 },
#endif
    { "TURBOSHAKE128", TURBOSHAKE_KT_INPUT_EMPTY, 0, NULL, 10032,
        "a3b9b0385900ce761f22aed548e754da10a5242d62e8c658e3f3a923a7555607", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 1 },
    { "TURBOSHAKE256", TURBOSHAKE_KT_INPUT_EMPTY, 0, NULL, 10032,
        "abefa11630c661269249742685ec082f207265dccf2f43534e9c61ba0c9d1d75", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 1 },
    { "KT128", TURBOSHAKE_KT_INPUT_EMPTY, 0, NULL, 10032,
        "e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 1 },
    { "KT256", TURBOSHAKE_KT_INPUT_EMPTY, 0, NULL, 10064,
        "ad4a1d718cf950506709a4c33396139b4449041fc79a05d68da35f1e453522e056c64fe94958e7085f2964888259b9932752f3ccd855288efee5fcbb8b563069", 0, 0, TURBOSHAKE_KT_NO_CUSTOM, 1 },
};

static int turboshake_kt_vector_test(int tstid)
{
    const TURBOSHAKE_KT_VECTOR *td = turboshake_kt_vectors + tstid;
    unsigned char *in = NULL, *custom = NULL, *expected = NULL, *out = NULL;
    const unsigned char *cmp;
    OSSL_PARAM params[3], *p = params;
    long hexlen;
    size_t inlen = 0, explen;
    unsigned int domain = td->domain;
    int ret = 0;

    switch (td->input_kind) {
    case TURBOSHAKE_KT_INPUT_EMPTY:
        in = (unsigned char *)empty_input;
        inlen = 0;
        break;
    case TURBOSHAKE_KT_INPUT_HEX:
        if (!TEST_ptr(in = OPENSSL_hexstr2buf(td->input_hex, &hexlen))
            || !TEST_long_ge(hexlen, 0))
            goto err;
        inlen = (size_t)hexlen;
        break;
    case TURBOSHAKE_KT_INPUT_PTN:
        if (!TEST_ptr(in = OPENSSL_malloc(td->input_len)))
            goto err;
        fill_ptn(in, td->input_len);
        inlen = td->input_len;
        break;
    }

    if (!TEST_ptr(expected = OPENSSL_hexstr2buf(td->expected_hex, &hexlen))
        || !TEST_long_gt(hexlen, 0))
        goto err;
    explen = (size_t)hexlen;
    if ((!td->suffix_only && !TEST_size_t_eq(explen, td->outlen))
        || (td->suffix_only && !TEST_size_t_le(explen, td->outlen))
        || !TEST_ptr(out = OPENSSL_malloc(td->outlen)))
        goto err;

    if (td->has_domain)
        *p++ = OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR,
            &domain);
    if (td->custom_len != TURBOSHAKE_KT_NO_CUSTOM) {
        if (!TEST_ptr(custom = OPENSSL_malloc(td->custom_len)))
            goto err;
        fill_ptn(custom, td->custom_len);
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, td->custom_len);
    }
    *p = OSSL_PARAM_construct_end();

    cmp = td->suffix_only ? out + td->outlen - explen : out;
    if (!digest_xof_with_params(td->alg, in, inlen, params, out, td->outlen)
        || !TEST_mem_eq(cmp, explen, expected, explen))
        goto err;
    ret = 1;
err:
    if (td->input_kind != TURBOSHAKE_KT_INPUT_EMPTY)
        OPENSSL_free(in);
    OPENSSL_free(custom);
    OPENSSL_free(expected);
    OPENSSL_free(out);
    return ret;
}

static int turboshake_domain_test(void)
{
    static const unsigned char msg[] = { 0xff, 0xff, 0xff };
    static const unsigned char expected[] = {
        0xbf, 0x32, 0x3f, 0x94, 0x04, 0x94, 0xe8, 0x8e,
        0xe1, 0xc5, 0x40, 0xfe, 0x66, 0x0b, 0xe8, 0xa0,
        0xc9, 0x3f, 0x43, 0xd1, 0x5e, 0xc0, 0x06, 0x99,
        0x84, 0x62, 0xfa, 0x99, 0x4e, 0xed, 0x5d, 0xab
    };
    unsigned int domain = 1, invalid = 0;
    OSSL_PARAM params[2];
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char out[sizeof(expected)];
    int ret = 0;

    params[0] = OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR,
        &domain);
    params[1] = OSSL_PARAM_construct_end();
    if (!digest_xof_with_params("TURBOSHAKE128", msg, sizeof(msg), params,
            out, sizeof(out))
        || !TEST_mem_eq(out, sizeof(out), expected, sizeof(expected)))
        goto err;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "TURBOSHAKE128", NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    params[0] = OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR,
        &invalid);
    ERR_set_mark();
    if (!TEST_false(EVP_DigestInit_ex2(ctx, md, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    invalid = 128;
    ERR_set_mark();
    if (!TEST_false(EVP_DigestInit_ex2(ctx, md, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    if (!TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || !TEST_true(EVP_DigestSqueeze(ctx, out, sizeof(out))))
        goto err;
    domain = 2;
    params[0] = OSSL_PARAM_construct_uint(OSSL_DIGEST_PARAM_DOMAIN_SEPARATOR,
        &domain);
    ERR_set_mark();
    if (!TEST_false(EVP_MD_CTX_set_params(ctx, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int kt_custom_octet_test(void)
{
    static const unsigned char msg[] = { 0xff };
    static const unsigned char expected[] = {
        0xd8, 0x48, 0xc5, 0x06, 0x8c, 0xed, 0x73, 0x6f,
        0x44, 0x62, 0x15, 0x9b, 0x98, 0x67, 0xfd, 0x4c,
        0x20, 0xb8, 0x08, 0xac, 0xc3, 0xd5, 0xbc, 0x48,
        0xe0, 0xb0, 0x6b, 0xa0, 0xa3, 0x76, 0x2e, 0xc4
    };
    unsigned char custom[41];
    unsigned char out[sizeof(expected)];
    OSSL_PARAM params[2];
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    fill_ptn(custom, sizeof(custom));
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, sizeof(custom));
    params[1] = OSSL_PARAM_construct_end();
    if (!digest_xof_with_params("KT128", msg, sizeof(msg), params, out,
            sizeof(out))
        || !TEST_mem_eq(out, sizeof(out), expected, sizeof(expected)))
        goto err;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "KT128", NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
        || !TEST_true(EVP_DigestSqueeze(ctx, out, sizeof(out))))
        goto err;
    ERR_set_mark();
    if (!TEST_false(EVP_MD_CTX_set_params(ctx, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int kt_custom_null_octet_test(void)
{
    static const unsigned char msg[] = { 0xff };
    static unsigned char custom[] = "Custom";
    unsigned char default_out[32], reset_out[32];
    OSSL_PARAM params[2];
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if (!digest_xof_with_params("KT128", msg, sizeof(msg), NULL, default_out,
            sizeof(default_out)))
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, sizeof(custom) - 1);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "KT128", NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex2(ctx, md, params)))
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, NULL, 0);
    if (!TEST_true(EVP_MD_CTX_set_params(ctx, params))
        || !TEST_true(EVP_DigestUpdate(ctx, msg, sizeof(msg)))
        || !TEST_true(EVP_DigestFinalXOF(ctx, reset_out, sizeof(reset_out)))
        || !TEST_mem_eq(reset_out, sizeof(reset_out), default_out,
            sizeof(default_out)))
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int kt_custom_limit_test(void)
{
    unsigned char custom[513], out[32];
    OSSL_PARAM params[2];
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    fill_ptn(custom, sizeof(custom));
    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "KT128", NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, sizeof(custom) - 1);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_DigestInit_ex2(ctx, md, params))
        || !TEST_true(EVP_DigestSqueeze(ctx, out, sizeof(out))))
        goto err;

    EVP_MD_CTX_free(ctx);
    ctx = NULL;
    if (!TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, sizeof(custom));
    ERR_set_mark();
    if (!TEST_false(EVP_DigestInit_ex2(ctx, md, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int cshake_custom_utf8_test_libctx(OSSL_LIB_CTX *libctx,
    const char *propq)
{
    static char function_name[] = "KMAC";
    static char custom_ascii[] = "Custom";
    unsigned char ascii_out[sizeof(cshake256_output)];
    OSSL_PARAM params[3];

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_DIGEST_PARAM_FUNCTION_NAME, function_name, 0);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom_ascii, 0);
    params[2] = OSSL_PARAM_construct_end();

    return digest_xof_with_params_ex(libctx, propq, "CSHAKE256",
               shake256_input, sizeof(shake256_input), params, ascii_out,
               sizeof(ascii_out))
        && TEST_mem_eq(ascii_out, sizeof(ascii_out), cshake256_output,
            sizeof(cshake256_output));
}

static int cshake_custom_octet_rejected_test_libctx(OSSL_LIB_CTX *libctx,
    const char *propq)
{
    static char function_name[] = "KMAC";
    static const unsigned char custom[] = "Custom";
    OSSL_PARAM params[3];
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_DIGEST_PARAM_FUNCTION_NAME, function_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, (void *)custom,
        sizeof(custom) - 1);
    params[2] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(md = EVP_MD_fetch(libctx, "CSHAKE256", propq))
        || !TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    ERR_set_mark();
    if (!TEST_false(EVP_DigestInit_ex2(ctx, md, params))) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();
    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int cshake_custom_limit_test_libctx(OSSL_LIB_CTX *libctx,
    const char *propq)
{
    static char function_name[] = "KMAC";
    char custom[513];
    unsigned char out[32];
    OSSL_PARAM params[3];
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    memset(custom, 'C', sizeof(custom) - 1);
    custom[sizeof(custom) - 1] = '\0';
    if (!TEST_ptr(md = EVP_MD_fetch(libctx, "CSHAKE256", propq))
        || !TEST_ptr(ctx = EVP_MD_CTX_new()))
        goto err;

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_DIGEST_PARAM_FUNCTION_NAME, function_name, 0);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, sizeof(custom) - 1);
    params[2] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_DigestInit_ex2(ctx, md, params))
        || !TEST_true(EVP_DigestSqueeze(ctx, out, sizeof(out))))
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    return ret;
}

static int cshake_custom_test(void)
{
    return cshake_custom_utf8_test_libctx(NULL, "provider=default")
        && cshake_custom_octet_rejected_test_libctx(NULL, "provider=default")
        && cshake_custom_limit_test_libctx(NULL, "provider=default");
}

static int cshake_custom_fips_test(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *nullprov = NULL, *fipsprov = NULL;
    int ret = 0;

    if (!TEST_ptr(fips_config_file)
        || !test_get_libctx(&libctx, &nullprov, fips_config_file,
            &fipsprov, "fips"))
        goto err;

    ret = cshake_custom_utf8_test_libctx(libctx, "fips=yes")
        && cshake_custom_octet_rejected_test_libctx(libctx, "fips=yes")
        && cshake_custom_limit_test_libctx(libctx, "fips=yes");
err:
    OSSL_PROVIDER_unload(fipsprov);
    OSSL_PROVIDER_unload(nullprov);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

typedef struct kt_boundary_data_st {
    const char *alg;
    size_t msglen;
    size_t customlen;
    const unsigned char *expected;
    size_t expected_len;
} KT_BOUNDARY_DATA;

static const unsigned char kt128_8191[] = {
    0x1b, 0x57, 0x76, 0x36, 0xf7, 0x23, 0x64, 0x3e,
    0x99, 0x0c, 0xc7, 0xd6, 0xa6, 0x59, 0x83, 0x74,
    0x36, 0xfd, 0x6a, 0x10, 0x36, 0x26, 0x60, 0x0e,
    0xb8, 0x30, 0x1c, 0xd1, 0xdb, 0xe5, 0x53, 0xd6
};

static const unsigned char kt128_8192[] = {
    0x48, 0xf2, 0x56, 0xf6, 0x77, 0x2f, 0x9e, 0xdf,
    0xb6, 0xa8, 0xb6, 0x61, 0xec, 0x92, 0xdc, 0x93,
    0xb9, 0x5e, 0xbd, 0x05, 0xa0, 0x8a, 0x17, 0xb3,
    0x9a, 0xe3, 0x49, 0x08, 0x70, 0xc9, 0x26, 0xc3
};

#if 0
/*
 * This RFC 9861 tree-boundary vector uses an 8189-byte customization string,
 * which is longer than OpenSSL's provider limit of 512 bytes.
 */
static const unsigned char kt128_8192_c8189[] = {
    0x3e, 0xd1, 0x2f, 0x70, 0xfb, 0x05, 0xdd, 0xb5,
    0x86, 0x89, 0x51, 0x0a, 0xb3, 0xe4, 0xd2, 0x3c,
    0x6c, 0x60, 0x33, 0x84, 0x9a, 0xa0, 0x1e, 0x1d,
    0x8c, 0x22, 0x0a, 0x29, 0x7f, 0xed, 0xcd, 0x0b
};
#endif

static const unsigned char kt256_8192[] = {
    0xc6, 0xee, 0x8e, 0x2a, 0xd3, 0x20, 0x0c, 0x01,
    0x8a, 0xc8, 0x7a, 0xaa, 0x03, 0x1c, 0xda, 0xc2,
    0x21, 0x21, 0xb4, 0x12, 0xd0, 0x7d, 0xc6, 0xe0,
    0xdc, 0xcb, 0xb5, 0x34, 0x23, 0x74, 0x7e, 0x9a,
    0x1c, 0x18, 0x83, 0x4d, 0x99, 0xdf, 0x59, 0x6c,
    0xf0, 0xcf, 0x4b, 0x8d, 0xfa, 0xfb, 0x7b, 0xf0,
    0x2d, 0x13, 0x9d, 0x0c, 0x90, 0x35, 0x72, 0x5a,
    0xdc, 0x1a, 0x01, 0xb7, 0x23, 0x0a, 0x41, 0xfa
};

static const KT_BOUNDARY_DATA kt_boundary_tests[] = {
    { "KT128", 8191, 0, kt128_8191, sizeof(kt128_8191) },
    { "KT128", 8192, 0, kt128_8192, sizeof(kt128_8192) },
#if 0
    /*
     * This RFC 9861 tree-boundary vector uses an 8189-byte customization
     * string, which is longer than OpenSSL's provider limit of 512 bytes.
     */
    { "KT128", 8192, 8189, kt128_8192_c8189,
        sizeof(kt128_8192_c8189) },
#endif
    { "KT256", 8192, 0, kt256_8192, sizeof(kt256_8192) },
};

static int kt_boundary_test(int tstid)
{
    const KT_BOUNDARY_DATA *td = kt_boundary_tests + tstid;
    unsigned char *msg = NULL, *custom = NULL, *out = NULL;
    OSSL_PARAM params[2], *p = params;
    int ret = 0;

    if (!TEST_ptr(msg = OPENSSL_malloc(td->msglen))
        || !TEST_ptr(out = OPENSSL_malloc(td->expected_len)))
        goto err;
    fill_ptn(msg, td->msglen);
    if (td->customlen > 0) {
        if (!TEST_ptr(custom = OPENSSL_malloc(td->customlen)))
            goto err;
        fill_ptn(custom, td->customlen);
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_DIGEST_PARAM_CUSTOMIZATION, custom, td->customlen);
    }
    *p = OSSL_PARAM_construct_end();

    if (!digest_xof_with_params(td->alg, msg, td->msglen, params, out,
            td->expected_len)
        || !TEST_mem_eq(out, td->expected_len, td->expected, td->expected_len))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    OPENSSL_free(custom);
    OPENSSL_free(msg);
    return ret;
}

static int xof_fail_test(void)
{
    int ret;
    EVP_MD *md = NULL;

    ret = TEST_ptr(md = EVP_MD_fetch(NULL, "SHA256", NULL))
        && TEST_false(EVP_MD_xof(md));
    EVP_MD_free(md);
    return ret;
}

int setup_tests(void)
{
    if (test_get_argument_count() > 0) {
        if (test_get_argument_count() != 2
            || strcmp(test_get_argument(0), "fips") != 0
            || !TEST_ptr(fips_config_file = test_get_argument(1)))
            return 0;
        ADD_TEST(cshake_custom_fips_test);
        return 1;
    }

    ADD_ALL_TESTS(xof_kat_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_kat_digestfinal_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_kat_digestfinal_xoflen_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_squeeze_no_absorb_test, OSSL_NELEM(xof_test_data));
    ADD_ALL_TESTS(xof_absorb_test, OSSL_NELEM(large_msg_test_data));
    ADD_ALL_TESTS(xof_squeeze_kat_test, OSSL_NELEM(stride_test_data));
    ADD_ALL_TESTS(xof_squeeze_large_test, OSSL_NELEM(stride_test_data));
    ADD_ALL_TESTS(xof_squeeze_dup_test, OSSL_NELEM(dupoffset_test_data));
    ADD_ALL_TESTS(turboshake_kt_vector_test, OSSL_NELEM(turboshake_kt_vectors));
    ADD_ALL_TESTS(turboshake_kt_chunked_absorb_and_size_test,
        OSSL_NELEM(turboshake_kt_tests));
    ADD_ALL_TESTS(turboshake_kt_copyctx_test, OSSL_NELEM(turboshake_kt_tests));
    ADD_ALL_TESTS(turboshake_kt_xoflen_alias_conflict_test,
        OSSL_NELEM(turboshake_kt_tests));
    ADD_TEST(turboshake_kt_repeated_param_test);
    ADD_TEST(turboshake_domain_test);
    ADD_TEST(kt_custom_octet_test);
    ADD_TEST(kt_custom_null_octet_test);
    ADD_TEST(kt_custom_limit_test);
    ADD_TEST(cshake_custom_test);
    ADD_ALL_TESTS(kt_boundary_test, OSSL_NELEM(kt_boundary_tests));
    ADD_TEST(xof_fail_test);
    return 1;
}

OPT_TEST_DECLARE_USAGE("[fips configfile]")
