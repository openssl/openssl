/***************************************************************************************
* LatticeCrypt: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: main header file
*
****************************************************************************************/

#ifndef __LatticeCrypt_H__
#define __LatticeCrypt_H__

// For C++
#ifdef __cplusplus
extern "C" {
#endif

#include <oqs/rand.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// NOTE: probably a better way to do this.
#if (defined(__x86_64__) || defined(__x86_64) || defined(__arch64__) || defined(_M_AMD64) || defined(_M_X64) || defined(_WIN64) || !defined(__LP64__))
#define RADIX 64
typedef uint64_t digit_t; // Unsigned 64-bit digit
typedef int64_t sdigit_t; // Signed 64-bit digit
#else
#define RADIX 32
typedef uint32_t digit_t; // Unsigned 32-bit digit
typedef int32_t sdigit_t; // Signed 32-bit digit

#endif

// Definitions of the error-handling type and error codes

typedef enum {
	CRYPTO_SUCCESS,                   // 0x00
	CRYPTO_ERROR,                     // 0x01
	CRYPTO_ERROR_DURING_TEST,         // 0x02
	CRYPTO_ERROR_UNKNOWN,             // 0x03
	CRYPTO_ERROR_NOT_IMPLEMENTED,     // 0x04
	CRYPTO_ERROR_NO_MEMORY,           // 0x05
	CRYPTO_ERROR_INVALID_PARAMETER,   // 0x06
	CRYPTO_ERROR_SHARED_KEY,          // 0x07
	CRYPTO_ERROR_TOO_MANY_ITERATIONS, // 0x08
	CRYPTO_ERROR_END_OF_LIST
} CRYPTO_STATUS;

#define CRYPTO_STATUS_TYPE_SIZE (CRYPTO_ERROR_END_OF_LIST)

// Basic key-exchange constants
#define OQS_RLWE_MSRLN16_PKA_BYTES 1824     // Alice's public key size
#define OQS_RLWE_MSRLN16_PKB_BYTES 2048     // Bob's public key size
#define OQS_RLWE_MSRLN16_SHAREDKEY_BYTES 32 // Shared key size

/******************** Function prototypes *******************/

// Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
extern void oqs_rlwe_msrln16_clear_words(void *mem, digit_t nwords);

/*********************** Key exchange API ***********************/

// Alice's key generation
// It produces a private key SecretKeyA and computes the public key PublicKeyA.
// Outputs: the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
//          the public key PublicKeyA that occupies 1824 bytes
CRYPTO_STATUS oqs_rlwe_msrln16_KeyGeneration_A(int32_t *SecretKeyA, unsigned char *PublicKeyA, OQS_RAND *rand);

// Bob's key generation and shared secret computation
// It produces a private key and computes the public key PublicKeyB. In combination with Alice's public key PublicKeyA, it computes
// the shared secret SharedSecretB.
// Input:   Alice's public key PublicKeyA that consists of 1824 bytes
// Outputs: the public key PublicKeyB that occupies 2048 bytes.
//          the 256-bit shared secret SharedSecretB.
CRYPTO_STATUS oqs_rlwe_msrln16_SecretAgreement_B(unsigned char *PublicKeyA, unsigned char *SharedSecretB, unsigned char *PublicKeyB, OQS_RAND *rand);

// Alice's shared secret computation
// It computes the shared secret SharedSecretA using Bob's public key PublicKeyB and Alice's private key SecretKeyA.
// Inputs: Bob's public key PublicKeyB that consists of 2048 bytes
//         the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
// Output: the 256-bit shared secret SharedSecretA.
CRYPTO_STATUS oqs_rlwe_msrln16_SecretAgreement_A(unsigned char *PublicKeyB, int32_t *SecretKeyA, unsigned char *SharedSecretA);

#ifdef __cplusplus
}
#endif

#endif
