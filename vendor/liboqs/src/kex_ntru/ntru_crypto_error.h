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
 * File:  ntru_crypto_error.h
 *
 * Contents: Contains base values for crypto error codes.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_ERROR_H
#define NTRU_CRYPTO_ERROR_H

/* define base values for crypto error codes */

#define HASH_ERROR_BASE ((uint32_t) 0x00000100)
#define HMAC_ERROR_BASE ((uint32_t) 0x00000200)
#define SHA_ERROR_BASE ((uint32_t) 0x00000400)
#define DRBG_ERROR_BASE ((uint32_t) 0x00000a00)
#define NTRU_ERROR_BASE ((uint32_t) 0x00003000)
#define MGF1_ERROR_BASE ((uint32_t) 0x00004100)

#endif /* NTRU_CRYPTO_ERROR_H */
