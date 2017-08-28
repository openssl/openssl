/**
 * \file sig.h
 * \brief Header defining the API for generic OQS Signature
 */

#ifndef __OQS_SIG_H
#define __OQS_SIG_H

#include <stddef.h>
#include <stdint.h>
#include <oqs/rand.h>

/**
 * Supported signature algorithms.
 * Note: the Picnic algs are not wrapped with a ENABLE_PICNIC
 *       to avoid forcing calling apps to define the macro. The library
 *       compiled without the macro fails if these algid are requested.
 */
enum OQS_SIG_algid {
	OQS_SIG_picnic_default,  // equivalent to OQS_SIG_picnic_10_38_FS
	OQS_SIG_picnic_42_14_FS, // LowMC with Fiat-Shamir balanced number of s-boxes (42) and rounds (14).
	OQS_SIG_picnic_42_14_UR, // LowMC with Unruh balanced number of s-boxes (42) and rounds (14). */
	OQS_SIG_picnic_1_316_FS, // LowMC with Fiat-Shamir and a small number of s-boxes (1) with a large number of rounds (316). */
	OQS_SIG_picnic_1_316_UR, // LowMC with Unruh and a small number of s-boxes (1) with a large number of rounds (316). */
	OQS_SIG_picnic_10_38_FS, // LowMC with Fiat-Shamir balanced number of s-boxes (10) and rounds (38). */
	OQS_SIG_picnic_10_38_UR, // LowMC with Unruh balanced number of s-boxes (10) and rounds (38). */
};

/**
 * OQS signature object
 */
typedef struct OQS_SIG OQS_SIG; // so the code below compiles...
struct OQS_SIG {

	/**
	 * PRNG
	 */
	OQS_RAND *rand;

	/**
	 * Specifies the name of the signature method
	 */
	char *method_name;

	/**
	 * Classical security in terms of the number of bits provided by the
	 * signature method.
	 */
	uint16_t estimated_classical_security;

	/**
	 *  Equivalent quantum security in terms of the number of bits provided by the
	 *  signature method.
	 */
	uint16_t estimated_quantum_security;

	/**
	 *  Private key length.
	 */
	uint16_t priv_key_len;

	/**
	 *  Public key length.
	 */
	uint16_t pub_key_len;

	/**
	 *  Maximum signature length.
	 */
	uint32_t max_sig_len;

	/**
	 * Opaque pointer for passing around any computation context
	 */
	void *ctx;

	/**
	 * Pointer to a function for public and private signature key generation.
	 *
	 * @param s                The signature structure.
	 * @param priv             The signer's private key.
	 * @param pub              The signer's public key.
	 * @return                 OQS_SUCCESS on success, or OQS_ERROR on failure.
	 */
	int (*keygen)(const OQS_SIG *s, uint8_t *priv, uint8_t *pub);

	/**
	 * Pointer to a function for signature generation.
	 *
	 * @param s                The signature structure.
	 * @param priv             The signer's private key.
	 * @param msg              The message to sign.
	 * @param msg_len          Length of the message to sign.
	 * @param sig              The generated signature. Must be allocated by the caller, or NULL to learn how much space is needed, as returned in sig_len.
	 * @param sig_len          In: length of sig, out: length of the generated signature.
	 * @return                 OQS_SUCCESS on success, or OQS_ERROR on failure.
	 */
	int (*sign)(const OQS_SIG *s, const uint8_t *priv, const uint8_t *msg, const size_t msg_len, uint8_t *sig, size_t *sig_len);

	/**
	 * Pointer to a function for signature verification.
	 *
	 * @param s                The signature structure.
	 * @param pub              The signer's public key.
	 * @param msg              The signed message.
	 * @param msg_len          Length of the signed message.
	 * @param sig              The signature to verify.
	 * @param sig_len          Length of the signature to verify.
	 @return                 OQS_SUCCESS on success, or OQS_ERROR on failure.
	 */
	int (*verify)(const OQS_SIG *s, const uint8_t *pub, const uint8_t *msg, const size_t msg_len, const uint8_t *sig, const size_t sig_len);

	/**
	 * Shuts down the algorithm library.
	 *
	 * @param s                The signature structure.
	 @return                 OQS_SUCCESS on success, or OQS_ERROR on failure.
	 */
	int (*shutdown)(OQS_SIG *s);
};

/**
 * Instantiate a new signature object.
 *
 * @param rand               The random number generator.
 * @param algid              The id of the signature algorithm to be instantiated.
 * @return                   A new signature object on success, or NULL on failure.
 */
OQS_SIG *OQS_SIG_new(OQS_RAND *rand, enum OQS_SIG_algid algid);

/**
 * Generates a new signature key pair.
 * @param s                  Pointer to the signature object.
 * @param priv               Pointer where the generated private key will be stored. Caller 
 *                           must have allocated s->priv_key_len bytes.
 * @param pub                Pointer where the generated public key will be stored. Caller 
 *                           must have allocated s->pub_key_len bytes.
 * @return                   OQS_SUCCESS on success, or OQS_ERROR on failure
 */
int OQS_SIG_keygen(const OQS_SIG *s, uint8_t *priv, uint8_t *pub);

/**
 * Generates a new signature.
 * @param s         Pointer to the signature object.
 * @param priv      Pointer to the signer's private key, of expected length `s->priv_key_len` bytes.
 * @param msg       Pointer to the message to sign.
 * @param msg_len   Length of the message to sign `msg`.
 * @param sig       Pointer where the generated signature will be stored. Caller must have allocated `s->max_sig_len` bytes.
 * @param sig_len   Pointer to the length of the generated signature. 
 * @return          OQS_SUCCESS on success, or OQS_ERROR on failure
 */
int OQS_SIG_sign(const OQS_SIG *s, const uint8_t *priv, const uint8_t *msg, const size_t msg_len, uint8_t *sig, size_t *sig_len);

/**
 * Verifies a signature.
 * @param s         Pointer to the signature object.
 * @param pub       Pointer to the signer's public key, of expected length `s->pub_key_len` bytes.
 * @param msg       Pointer to the signed message.
 * @param msg_len   Length of the signed message `msg`.
 * @param sig       Pointer to the signature.
 * @param sig_len   Length of the signature. 
 * @return          OQS_SUCCESS on success, or OQS_ERROR on failure
 */
int OQS_SIG_verify(const OQS_SIG *s, const uint8_t *pub, const uint8_t *msg, const size_t msg_len, const uint8_t *sig, const size_t sig_len);

/**
 * Frees the signature object, de-initializing the underlying library code.
 * Does NOT free the rand object passed to OQS_SIG_new.
 * @param s          The signature object.
 */
void OQS_SIG_free(OQS_SIG *s);

#endif
