/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_H
#define PICNIC_H

#define PICNIC_STATIC /* in OQS */

#if !defined(PICNIC_EXPORT)
#if !defined(PICNIC_STATIC) && (defined(_WIN16) || defined(_WIN32) || defined(_WIN64))
#define PICNIC_EXPORT __declspec(dllimport)
#else
#define PICNIC_EXPORT
#endif
#endif

#if defined(_WIN16) || defined(_WIN32) || defined(_WIN64)
#define PICNIC_CALLING_CONVENTION __stdcall
#else
#define PICNIC_CALLING_CONVENTION
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <oqs/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOWMC_BLOCK_SIZE(p) ((((unsigned int)(p) + 3) / 2) * 8)

#define MAX_LOWMC_ROUNDS 38
#define MAX_LOWMC_SBOXES 10
#define MAX_ROUNDS 438

#define PICNIC_PRIVATE_KEY_SIZE(p) (1 + 3 * LOWMC_BLOCK_SIZE(p))
#define PICNIC_PUBLIC_KEY_SIZE(p) (1 + 2 * LOWMC_BLOCK_SIZE(p))

#define PICNIC_SIGNATURE_SIZE_Picnic_L1_FS 34000
#define PICNIC_SIGNATURE_SIZE_Picnic_L1_UR 53929
#define PICNIC_SIGNATURE_SIZE_Picnic_L3_FS 76740
#define PICNIC_SIGNATURE_SIZE_Picnic_L3_UR 121813
#define PICNIC_SIGNATURE_SIZE_Picnic_L5_FS 132824
#define PICNIC_SIGNATURE_SIZE_Picnic_L5_UR 209474

#define PICNIC_CONCAT2(a, b) a##_##b
#define PICNIC_CONCAT(a, b) PICNIC_CONCAT2(a, b)

#define PICNIC_SIGNATURE_SIZE(p) PICNIC_CONCAT(PICNIC_SIGNATURE_SIZE, p)

#define MAX_LOWMC_BLOCK_SIZE LOWMC_BLOCK_SIZE(Picnic_L5_UR)
#define PICNIC_MAX_PRIVATEKEY_SIZE PICNIC_PRIVATE_KEY_SIZE(Picnic_L5_UR)
#define PICNIC_MAX_PUBLICKEY_SIZE PICNIC_PUBLIC_KEY_SIZE(Picnic_L5_UR)
#define PICNIC_MAX_SIGNATURE_SIZE PICNIC_SIGNATURE_SIZE(Picnic_L5_UR)

/** Parameter set names */
typedef enum {
  PARAMETER_SET_INVALID,
  Picnic_L1_FS, // 1
  Picnic_L1_UR, // 2
  Picnic_L3_FS, // 3
  Picnic_L3_UR, // 4
  Picnic_L5_FS, // 5
  Picnic_L5_UR, // 6
  PARAMETER_SET_MAX_INDEX
} picnic_params_t;

/** Public key */
typedef struct { uint8_t data[PICNIC_MAX_PUBLICKEY_SIZE]; } picnic_publickey_t;

/** Private key */
typedef struct { uint8_t data[1 + 3 * MAX_LOWMC_BLOCK_SIZE]; } picnic_privatekey_t;

/**
 * Get a string representation of the parameter set.
 *
 * @param parameters A parameter set
 *
 * @return A null-terminated string describing the parameter set.
 */
PICNIC_EXPORT const char* PICNIC_CALLING_CONVENTION
picnic_get_param_name(picnic_params_t parameters);

/* Signature API */

/**
 * Key generation function.
 * Generates a public and private key pair, for the specified parameter set.
 *
 * @param[in]  parameters The parameter set to use when generating a key.
 * @param[out] pk         The new public key.
 * @param[out] sk         The new private key.
 *
 * @return Returns 0 for success, or a nonzero value indicating an error.
 *
 * @see picnic_verify(), picnic_sign()
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_keygen(picnic_params_t parameters,
                                                          picnic_publickey_t* pk,
                                                          picnic_privatekey_t* sk, OQS_RAND* rand);

/**
 * Signature function.
 * Signs a message with the given keypair.
 *
 * @param[in] sk      The signer's private key.
 * @param[in] message The message to be signed.
 * @param[in] message_len The length of the message, in bytes.
 * @param[out] signature A buffer to hold the signature. The required size does
 * not exceed PICNIC_MAX_SIGNATURE_SIZE bytes.  The specific max number of
 * bytes required for a parameter set is given by picnic_signature_size(). Note
 * that the length of each signature varies slightly, for the parameter sets
 * using the FS transform.  The parameter sets using the Unruh transform have a
 * fixed length.
 * @param[in,out] signature_len The length of the provided signature buffer.
 * On success, this is set to the number of bytes written to the signature buffer.
 *
 * @return Returns 0 for success, or a nonzero value indicating an error.
 *
 * @see picnic_verify(), picnic_keygen(), picnic_signature_size()
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_sign(const picnic_privatekey_t* sk,
                                                        const uint8_t* message, size_t message_len,
                                                        uint8_t* signature, size_t* signature_len);

/**
 * Get the number of bytes required to hold a signature.
 *
 * @param[in] parameters The parameter set of the signature.
 *
 * @return The number of bytes required to hold the signature created by
 * picnic_sign
 *
 * @note The size of signatures with parameter sets using the FS transform vary
 *       slightly based on the random choices made during signing.  This function
 *       will return a suffcient number of bytes to hold a signature, and the
 *       picnic_sign() function returns the exact number used for a given signature.
 *
 * @see picnic_sign()
 */
PICNIC_EXPORT size_t PICNIC_CALLING_CONVENTION picnic_signature_size(picnic_params_t parameters);

/**
 * Verification function.
 * Verifies a signature is valid with respect to a public key and message.
 *
 * @param[in] pk      The signer's public key.
 * @param[in] message The message the signature purpotedly signs.
 * @param[in] message_len The length of the message, in bytes.
 * @param[in] signature The signature to verify.
 * @param[in] signature_len The length of the signature.
 *
 * @return Returns 0 for success, indicating a valid signature, or a nonzero
 * value indicating an error or an invalid signature.
 *
 * @see picnic_sign(), picnic_keygen()
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_verify(const picnic_publickey_t* pk,
                                                          const uint8_t* message,
                                                          size_t message_len,
                                                          const uint8_t* signature,
                                                          size_t signature_len);

/**
 * Serialize a public key.
 *
 * @param[in]  key The public key to serialize
 * @param[out] buf The buffer to write the key to.
 *                 Must have size at least PICNIC_MAX_PUBLICKEY_SIZE + 1 bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns the number of bytes written.
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_write_public_key(const picnic_publickey_t* key,
                                                                    uint8_t* buf, size_t buflen);

/**
 * De-serialize a public key.
 *
 * @param[out]  key The public key object to be populated.
 * @param[in] buf The buffer to read the public key from.
 *                 Must be at least PICNIC_MAX_PUBLICKEY_SIZE + 1 bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns 0 on success, or a nonzero value indicating an error.
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_read_public_key(picnic_publickey_t* key,
                                                                   const uint8_t* buf,
                                                                   size_t buflen);

/**
 * Serialize a private key.
 *
 * @param[in]  key The private key to serialize
 * @param[out] buf The buffer to write the key to.
 *                 Must have size at least PICNIC_MAX_PRIVATEKEY_SIZE + 1 bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns the number of bytes written.
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_write_private_key(const picnic_privatekey_t* key,
                                                                     uint8_t* buf, size_t buflen);

/**
 * De-serialize a private key.
 *
 * @param[out]  key The private key object to be populated
 * @param[in] buf The buffer to read the key from.
 *                 Must have size at least PICNIC_MAX_PRIVATEKEY_SIZE + 1 bytes.
 * @param[in]  buflen The length of buf, in bytes
 *
 * @return Returns 0 on success, or a nonzero value indicating an error.
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION picnic_read_private_key(picnic_privatekey_t* key,
                                                                    const uint8_t* buf,
                                                                    size_t buflen);

/**
 * Check that a key pair is valid.
 *
 * @param[in] privatekey The private key to check
 * @param[in] publickey The public key to check
 *
 * @return Returns 0 if the key pair is valid, or a nonzero value indicating an error
 */
PICNIC_EXPORT int PICNIC_CALLING_CONVENTION
picnic_validate_keypair(const picnic_privatekey_t* privatekey, const picnic_publickey_t* publickey);

#ifdef __cplusplus
}
#endif

#endif
