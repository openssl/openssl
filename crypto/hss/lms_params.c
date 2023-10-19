/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/hss.h"

#define LMS_TYPE_SHA256_N32_H5   0x00000005
#define LMS_TYPE_SHA256_N32_H10  0x00000006
#define LMS_TYPE_SHA256_N32_H15  0x00000007
#define LMS_TYPE_SHA256_N32_H20  0x00000008
#define LMS_TYPE_SHA256_N32_H25  0x00000009
#define LMS_TYPE_SHA256_N24_H5   0x0000000A
#define LMS_TYPE_SHA256_N24_H10  0x0000000B
#define LMS_TYPE_SHA256_N24_H15  0x0000000C
#define LMS_TYPE_SHA256_N24_H20  0x0000000D
#define LMS_TYPE_SHA256_N24_H25  0x0000000E
#define LMS_TYPE_SHAKE_N32_H5    0x0000000F
#define LMS_TYPE_SHAKE_N32_H10   0x00000010
#define LMS_TYPE_SHAKE_N32_H15   0x00000011
#define LMS_TYPE_SHAKE_N32_H20   0x00000012
#define LMS_TYPE_SHAKE_N32_H25   0x00000013
#define LMS_TYPE_SHAKE_N24_H5    0x00000014
#define LMS_TYPE_SHAKE_N24_H10   0x00000015
#define LMS_TYPE_SHAKE_N24_H15   0x00000016
#define LMS_TYPE_SHAKE_N24_H20   0x00000017
#define LMS_TYPE_SHAKE_N24_H25   0x00000018

static const LMS_PARAMS lms_params[] = {
    { LMS_TYPE_SHA256_N32_H5,  "SHA256",     32,  5 },
    { LMS_TYPE_SHA256_N32_H10, "SHA256",     32, 10 },
    { LMS_TYPE_SHA256_N32_H15, "SHA256",     32, 15 },
    { LMS_TYPE_SHA256_N32_H20, "SHA256",     32, 20 },
    { LMS_TYPE_SHA256_N32_H25, "SHA256",     32, 25 },
    { LMS_TYPE_SHA256_N24_H5,  "SHA256-192", 24,  5 },
    { LMS_TYPE_SHA256_N24_H10, "SHA256-192", 24, 10 },
    { LMS_TYPE_SHA256_N24_H15, "SHA256-192", 24, 15 },
    { LMS_TYPE_SHA256_N24_H20, "SHA256-192", 24, 20 },
    { LMS_TYPE_SHA256_N24_H25, "SHA256-192", 24, 25 },
    { LMS_TYPE_SHAKE_N32_H5,   "SHAKE-256",  32,  5 },
    { LMS_TYPE_SHAKE_N32_H10,  "SHAKE-256",  32, 10 },
    { LMS_TYPE_SHAKE_N32_H15,  "SHAKE-256",  32, 15 },
    { LMS_TYPE_SHAKE_N32_H20,  "SHAKE-256",  32, 20 },
    { LMS_TYPE_SHAKE_N32_H25,  "SHAKE-256",  32, 25 },
    /* SHAKE-256/192 */
    { LMS_TYPE_SHAKE_N24_H5,   "SHAKE-256",  24,  5 },
    { LMS_TYPE_SHAKE_N24_H10,  "SHAKE-256",  24, 10 },
    { LMS_TYPE_SHAKE_N24_H15,  "SHAKE-256",  24, 15 },
    { LMS_TYPE_SHAKE_N24_H20,  "SHAKE-256",  24, 20 },
    { LMS_TYPE_SHAKE_N24_H25,  "SHAKE-256",  24, 25 },

    { 0, NULL, 0 , 0 }
};

const LMS_PARAMS *ossl_lms_params_get(uint32_t lms_type)
{
    const LMS_PARAMS *p;

    for (p = lms_params; p->lms_type != 0; ++p) {
        if (p->lms_type == lms_type)
            return p;
    }
    return NULL;
}
