/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: main header file
*
*********************************************************************************************/

#ifndef __SIDH_H__
#define __SIDH_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <oqs/rand.h>

// Definition of operating system

#define OS_WIN       1
#define OS_LINUX     2

#if defined(WINDOWS)        // Microsoft Windows OS
#define OS_TARGET OS_WIN
#else
#define OS_TARGET OS_LINUX
#endif

#if (defined(__x86_64__) || defined(__x86_64) || defined(__arch64__) || defined(_M_AMD64) || defined(_M_X64) || defined(_WIN64) || !defined(__LP64__))
#define TARGET TARGET_AMD64
#define RADIX           64
typedef uint64_t        digit_t;        // Unsigned 64-bit digit
typedef int64_t         sdigit_t;       // Signed 64-bit digit
#define NWORDS_FIELD    12              // Number of words of a 751-bit field element
#define p751_ZERO_WORDS 5               // Number of "0" digits in the least significant part of p751 - 1     
#else
#define TARGET TARGET_x86
#define TARGET TARGET_ARM
#define RADIX           32
typedef uint32_t        digit_t;        // Unsigned 32-bit digit
typedef int32_t         sdigit_t;       // Signed 32-bit digit
#define NWORDS_FIELD    24
#define p751_ZERO_WORDS 11
#endif

// Extended datatype support
#if defined(SIDH_ASM)
#if (TARGET == TARGET_AMD64 && OS_TARGET == OS_WIN)
#define SCALAR_INTRIN_SUPPORT
typedef uint64_t uint128_t[2];
#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_LINUX)
#define UINT128_SUPPORT
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif
#else   /* generic implementation */
typedef uint64_t uint128_t[2];
#endif

// Basic constants

#define SIDH_NBITS_FIELD     751
#define SIDH_MAXBITS_FIELD   768
#define SIDH_MAXWORDS_FIELD  ((SIDH_MAXBITS_FIELD+RADIX-1)/RADIX)     // Max. number of words to represent field elements
#define SIDH_NWORDS64_FIELD  ((SIDH_NBITS_FIELD+63)/64)               // Number of 64-bit words of a 751-bit field element 
#define SIDH_NBITS_ORDER     384
#define SIDH_NWORDS_ORDER    ((SIDH_NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define SIDH_MAXBITS_ORDER   SIDH_NBITS_ORDER
#define SIDH_MAXWORDS_ORDER  ((SIDH_MAXBITS_ORDER+RADIX-1)/RADIX)     // Max. number of words to represent elements in [1, oA-1] or [1, oB].

// Basic constants for elliptic curve BigMont

#define BIGMONT_NBITS_ORDER     749
#define BIGMONT_MAXBITS_ORDER   768
#define BIGMONT_NWORDS_ORDER    ((BIGMONT_NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of BigMont's subgroup order.
#define BIGMONT_MAXWORDS_ORDER  ((BIGMONT_MAXBITS_ORDER+RADIX-1)/RADIX)     // Max. number of words to represent elements in [1, BigMont_order].

// Size of SIDH secret key = (CurveIsogeny_SIDHp751.owordbits + 7)/8
// Number of bytes in an element in [1, order]
#define SIDH_SECRETKEY_LEN 48
// Number of bytes in a field element
// PBYTES_SIDHp751 ((CurveIsogeny_SIDHp751.pwordbits + 7)/8)
// Size of SIDH public key = 3*2*PBYTES_SIDHp751
#define SIDH_PUBKEY_LEN 576
// Size of SIDH shared key = 2*PBYTES_SIDHp751
#define SIDH_SHAREDKEY_LEN 192

// Definitions of the error-handling type and error codes

typedef enum {
	SIDH_CRYPTO_SUCCESS,                          // 0x00
	SIDH_CRYPTO_ERROR,                            // 0x01
	SIDH_CRYPTO_ERROR_INVALID_PARAMETER,          // 0x02
	SIDH_CRYPTO_ERROR_PUBLIC_KEY_VALIDATION,      // 0x03
	SIDH_CRYPTO_ERROR_TOO_MANY_ITERATIONS,        // 0x04
	SIDH_CRYPTO_ERROR_END_OF_LIST
} SIDH_CRYPTO_STATUS;

// Definition of type for curve isogeny system identifiers. Currently valid value is "SIDHp751" (see SIDH.h)
typedef char CurveIsogeny_ID[10];


// Supersingular elliptic curve isogeny structures:

// This data struct contains the static curve isogeny data
typedef struct {
	CurveIsogeny_ID  CurveIsogeny;                           // Curve isogeny system identifier, base curve defined over GF(p^2)
	unsigned int     pwordbits;                              // Smallest multiple of 32 larger than the prime bitlength
	unsigned int     owordbits;                              // Smallest multiple of 32 larger than the order bitlength
	unsigned int     pbits;                                  // Bitlength of the prime p
	uint64_t         prime[SIDH_MAXWORDS_FIELD];             // Prime p
	uint64_t         A[SIDH_MAXWORDS_FIELD];                 // Base curve parameter "A"
	uint64_t         C[SIDH_MAXWORDS_FIELD];                 // Base curve parameter "C"
	unsigned int     oAbits;                                 // Order bitlength for Alice
	uint64_t         Aorder[SIDH_MAXWORDS_ORDER];            // Order of Alice's (sub)group
	unsigned int     oBbits;                                 // Order bitlength for Bob
	unsigned int     eB;                                     // Power of Bob's subgroup order (i.e., oB = 3^eB)
	uint64_t         Border[SIDH_MAXWORDS_ORDER];            // Order of Bob's (sub)group
	uint64_t         PA[2 * SIDH_MAXWORDS_FIELD];            // Alice's generator PA = (XPA,YPA), where XPA and YPA are defined over GF(p)
	uint64_t         PB[2 * SIDH_MAXWORDS_FIELD];            // Bob's generator PB = (XPB,YPB), where XPB and YPB are defined over GF(p)
	unsigned int     BigMont_A24;                            // BigMont's curve parameter A24 = (A+2)/4
	uint64_t         BigMont_order[BIGMONT_MAXWORDS_ORDER];  // BigMont's subgroup order
	uint64_t         Montgomery_R2[SIDH_MAXWORDS_FIELD];     // Montgomery constant (2^W)^2 mod p, using a suitable value W
	uint64_t         Montgomery_pp[SIDH_MAXWORDS_FIELD];     // Montgomery constant -p^-1 mod 2^W, using a suitable value W
	uint64_t         Montgomery_one[SIDH_MAXWORDS_FIELD];    // Value one in Montgomery representation
} CurveIsogenyStaticData, *PCurveIsogenyStaticData;


// This data struct is initialized with the targeted curve isogeny system during setup
typedef struct {
	CurveIsogeny_ID  CurveIsogeny;                           // Curve isogeny system identifier, base curve defined over GF(p^2)
	unsigned int     pwordbits;                              // Closest multiple of 32 to prime bitlength
	unsigned int     owordbits;                              // Closest multiple of 32 to order bitlength
	unsigned int     pbits;                                  // Bitlength of the prime p
	digit_t         *prime;                                  // Prime p
	digit_t         *A;                                      // Base curve parameter "A"
	digit_t         *C;                                      // Base curve parameter "C"
	unsigned int     oAbits;                                 // Order bitlength for Alice
	digit_t         *Aorder;                                 // Order of Alice's (sub)group
	unsigned int     oBbits;                                 // Order bitlength for Bob
	unsigned int     eB;                                     // Power of Bob's subgroup order (i.e., oB = 3^eB)
	digit_t         *Border;                                 // Order of Bob's (sub)group
	digit_t         *PA;                                     // Alice's generator PA = (XPA,YPA), where XPA and YPA are defined over GF(p)
	digit_t         *PB;                                     // Bob's generator PB = (XPB,YPB), where XPB and YPB are defined over GF(p)
	unsigned int     BigMont_A24;                            // BigMont's curve parameter A24 = (A+2)/4
	digit_t         *BigMont_order;                          // BigMont's subgroup order
	digit_t         *Montgomery_R2;                          // Montgomery constant (2^W)^2 mod p, using a suitable value W
	digit_t         *Montgomery_pp;                          // Montgomery constant -p^-1 mod 2^W, using a suitable value W
	digit_t         *Montgomery_one;                         // Value one in Montgomery representation
} CurveIsogenyStruct, *PCurveIsogenyStruct;


// Supported curve isogeny systems:

// "SIDHp751", base curve: supersingular elliptic curve E: y^2 = x^3 + x
extern CurveIsogenyStaticData CurveIsogeny_SIDHp751;


/******************** Function prototypes ***********************/
/*************** Setup/initialization functions *****************/

// Dynamic allocation of memory for curve isogeny structure.
// Returns NULL on error.
PCurveIsogenyStruct oqs_sidh_cln16_curve_allocate(PCurveIsogenyStaticData CurveData);

// Initialize curve isogeny structure pCurveIsogeny with static data extracted from pCurveIsogenyData.
// This needs to be called after allocating memory for "pCurveIsogeny" using oqs_sidh_cln16_curve_allocate().
SIDH_CRYPTO_STATUS oqs_sidh_cln16_curve_initialize(PCurveIsogenyStruct pCurveIsogeny, OQS_RAND *rand, PCurveIsogenyStaticData pCurveIsogenyData);

// Free memory for curve isogeny structure
void oqs_sidh_cln16_curve_free(PCurveIsogenyStruct pCurveIsogeny);

// Output random values in the range [1, order-1] in little endian format that can be used as private keys.
SIDH_CRYPTO_STATUS oqs_sidh_cln16_random_mod_order(digit_t *random_digits, unsigned int AliceOrBob, PCurveIsogenyStruct pCurveIsogeny, OQS_RAND *rand);

// Output random values in the range [1, BigMont_order-1] in little endian format that can be used as private keys
// to compute scalar multiplications using the elliptic curve BigMont.
SIDH_CRYPTO_STATUS oqs_sidh_cln16_random_BigMont_mod_order(digit_t *random_digits, PCurveIsogenyStruct pCurveIsogeny, OQS_RAND *rand);

// Clear "nwords" digits from memory
void oqs_sidh_cln16_clear_words(void *mem, digit_t nwords);

/*********************** Key exchange API ***********************/

// Alice's key-pair generation
// It produces a private key pPrivateKeyA and computes the public key pPublicKeyA.
// The private key is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total).
// The public key consists of 3 elements in GF(p751^2), i.e., 564 bytes.
// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
SIDH_CRYPTO_STATUS oqs_sidh_cln16_KeyGeneration_A(unsigned char *pPrivateKeyA, unsigned char *pPublicKeyA, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand);

// Bob's key-pair generation
// It produces a private key pPrivateKeyB and computes the public key pPublicKeyB.
// The private key is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total).
// The public key consists of 3 elements in GF(p751^2), i.e., 564 bytes.
// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
SIDH_CRYPTO_STATUS oqs_sidh_cln16_KeyGeneration_B(unsigned char *pPrivateKeyB, unsigned char *pPublicKeyB, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand);

// Alice's shared secret generation
// It produces a shared secret key pSharedSecretA using her secret key pPrivateKeyA and Bob's public key pPublicKeyB
// Inputs: Alice's pPrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total).
//         Bob's pPublicKeyB consists of 3 elements in GF(p751^2), i.e., 564 bytes.
//         "validate" flag that indicates if Alice must validate Bob's public key.
// Output: a shared secret pSharedSecretA that consists of one element in GF(p751^2), i.e., 1502 bits in total.
// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
SIDH_CRYPTO_STATUS oqs_sidh_cln16_SecretAgreement_A(unsigned char *pPrivateKeyA, unsigned char *pPublicKeyB, unsigned char *pSharedSecretA, bool validate, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand);

// Bob's shared secret generation
// It produces a shared secret key pSharedSecretB using his secret key pPrivateKeyB and Alice's public key pPublicKeyA
// Inputs: Bob's pPrivateKeyB is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total).
//         Alice's pPublicKeyA consists of 3 elements in GF(p751^2), i.e., 564 bytes.
//         "validate" flag that indicates if Bob must validate Alice's public key.
// Output: a shared secret pSharedSecretB that consists of one element in GF(p751^2), i.e., 1502 bits in total.
// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
SIDH_CRYPTO_STATUS oqs_sidh_cln16_SecretAgreement_B(unsigned char *pPrivateKeyB, unsigned char *pPublicKeyA, unsigned char *pSharedSecretB, bool validate, PCurveIsogenyStruct CurveIsogeny, OQS_RAND *rand);

/*********************** Scalar multiplication API using BigMont ***********************/

// BigMont's scalar multiplication using the Montgomery ladder
// Inputs: x, the affine x-coordinate of a point P on BigMont: y^2=x^3+A*x^2+x,
//         scalar m.
// Output: xout, the affine x-coordinate of m*(x:1)
// CurveIsogeny must be set up in advance using oqs_sidh_cln16_curve_initialize().
SIDH_CRYPTO_STATUS oqs_sidh_cln16_BigMont_ladder(unsigned char *x, digit_t *m, unsigned char *xout, PCurveIsogenyStruct CurveIsogeny);


// Encoding of keys for isogeny system "SIDHp751" (wire format):
// ------------------------------------------------------------
// Elements over GF(p751) are encoded in 96 octets in little endian format (i.e., the least significant octet located at the leftmost position).
// Elements (a+b*i) over GF(p751^2), where a and b are defined over GF(p751), are encoded as {b, a}, with b in the least significant position.
// Elements over Z_oA and Z_oB are encoded in 48 octets in little endian format.
//
// Private keys pPrivateKeyA and pPrivateKeyB are defined in Z_oA and Z_oB (resp.) and can have values in the range [2, 2^372-2] and [1, 3^239-1], resp.
// In the key exchange API, they are encoded in 48 octets in little endian format.
// Public keys pPublicKeyA and pPublicKeyB consist of four elements in GF(p751^2). In the key exchange API, they are encoded in 768 octets in little
// endian format.
// Shared keys pSharedSecretA and pSharedSecretB consist of one element in GF(p751^2). In the key exchange API, they are encoded in 192 octets in little
// endian format.


#ifdef __cplusplus
}
#endif


#endif
