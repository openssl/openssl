/******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/

/******************************************************************************
 *
 * File: ntru_crypto_sha.h
 *
 * Contents: Definitions and declarations common to all SHA hash algorithms.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_SHA_H
#define NTRU_CRYPTO_SHA_H

#include "ntru_crypto_error.h"
#include "ntru_crypto_hash_basics.h"

/***************
 * error codes *
 ***************/

#define SHA_OK ((uint32_t) NTRU_CRYPTO_HASH_OK)
#define SHA_FAIL ((uint32_t) NTRU_CRYPTO_HASH_FAIL)
#define SHA_BAD_PARAMETER ((uint32_t) NTRU_CRYPTO_HASH_BAD_PARAMETER)
#define SHA_OVERFLOW ((uint32_t) NTRU_CRYPTO_HASH_OVERFLOW)

#define SHA_RESULT(r) ((uint32_t)((r) ? SHA_ERROR_BASE + (r) : (r)))
#define SHA_RET(r) return SHA_RESULT(r);

/*********
 * flags *
 *********/

#define SHA_DATA_ONLY HASH_DATA_ONLY
#define SHA_INIT HASH_INIT
#define SHA_FINISH HASH_FINISH

#endif /* NTRU_CRYPTO_SHA_H */
