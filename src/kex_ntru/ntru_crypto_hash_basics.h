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
 * File: ntru_crypto_hash_basics.h
 *
 * Contents: Common definitions for all hash algorithms.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_HASH_BASICS_H
#define NTRU_CRYPTO_HASH_BASICS_H

#include "ntru_crypto_platform.h"

/**************
 * algorithms *
 **************/

typedef enum {
	NTRU_CRYPTO_HASH_ALGID_NONE = 0,
	NTRU_CRYPTO_HASH_ALGID_SHA1,
	NTRU_CRYPTO_HASH_ALGID_SHA256,
} NTRU_CRYPTO_HASH_ALGID;

/***************
 * error codes *
 ***************/

#define NTRU_CRYPTO_HASH_OK ((uint32_t) 0x00)
#define NTRU_CRYPTO_HASH_FAIL ((uint32_t) 0x01)
#define NTRU_CRYPTO_HASH_BAD_PARAMETER ((uint32_t) 0x02)
#define NTRU_CRYPTO_HASH_OVERFLOW ((uint32_t) 0x03)
#define NTRU_CRYPTO_HASH_BAD_ALG ((uint32_t) 0x20)
#define NTRU_CRYPTO_HASH_OUT_OF_MEMORY ((uint32_t) 0x21)

/* For backward-compatibility */
typedef uint32_t NTRU_CRYPTO_HASH_ERROR;

/*********
 * flags *
 *********/

#define HASH_DATA_ONLY 0
#define HASH_INIT (1 << 0)
#define HASH_FINISH (1 << 1)

#endif /* NTRU_CRYPTO_HASH_BASICS_H */
