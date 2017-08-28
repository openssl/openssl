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
 * File: ntru_crypto_platform.h
 *
 * Contents: Platform-specific basic definitions.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_PLATFORM_H
#define NTRU_CRYPTO_PLATFORM_H

/* The default implementation is to use stdint.h, a part of the C99 standard.
 * Systems that don't support this are handled on a case-by-case basis.
 */

#if defined(WIN32) && (_MSC_VER < 1600)

#include <basetsd.h>
typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short int uint16_t;
typedef short int int16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

#elif defined(linux) && defined(__KERNEL__)

#include <linux/types.h>

#else

#include <stdint.h>

#endif

/* For linux kernel drivers:
 * Use kmalloc and kfree in place of malloc / free
 * Use BUG_ON in place of assert */
#if defined(linux) && defined(__KERNEL__)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#define MALLOC(size) (kmalloc(size, GFP_KERNEL))
#define FREE(x) (kfree(x))

#else

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#define MALLOC(size) (malloc(size))
#define FREE(x) (free(x))

#endif

#if !defined(HAVE_BOOL) && !defined(__cplusplus)
#define HAVE_BOOL
typedef uint8_t bool;
#endif /* HAVE_BOOL */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#endif /* NTRU_CRYPTO_PLATFORM_H */
