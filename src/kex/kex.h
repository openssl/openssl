/**
 * \file kex.h
 * \brief Header defining the API for generic OQS Key exchange
 */

#ifndef __OQS_KEX_H
#define __OQS_KEX_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>
#include <oqs/rand.h>

#if defined(_WIN32)
#include <oqs/winconfig.h>
#else
#include <oqs/config.h>
#endif

enum OQS_KEX_alg_name {
	OQS_KEX_alg_default,
	OQS_KEX_alg_rlwe_bcns15,
	OQS_KEX_alg_rlwe_newhope,
	OQS_KEX_alg_rlwe_msrln16,
	OQS_KEX_alg_lwe_frodo,
	OQS_KEX_alg_sidh_msr_503,
	OQS_KEX_alg_sidh_msr_751,
	OQS_KEX_alg_sike_msr_503,
	OQS_KEX_alg_sike_msr_751,
	OQS_KEX_alg_code_mcbits,
	OQS_KEX_alg_ntru,
	OQS_KEX_alg_sidh_iqc_ref,
	OQS_KEX_alg_rlwe_newhope_avx2,
};

/**
 * OQS key exchange object
 */
typedef struct OQS_KEX {

	/**
	 * PRNG
	 */
	OQS_RAND *rand;

	/**
	 * Specifies the name of the key exchange method
	 */
	char *method_name;

	/**
	 * Classical security in terms of the number of bits provided by the key
	 * exchange method.
	 */
	uint16_t estimated_classical_security;

	/**
	 *  Equivalent quantum security in terms of the number of bits provided by the key
	 *  exchange method.
	 */
	uint16_t estimated_quantum_security;

	/**
	 * An instance-specific seed, if any.
	 */
	uint8_t *seed;

	/**
	 * Size of instance-specific seed, if any.
	 */
	size_t seed_len;

	/**
	 * Named parameters for this key exchange method instance, if any.
	 */
	char *named_parameters;

	/**
	 * Opaque pointer for passing around instance-specific data
	 */
	void *params;

	/**
	 * Opaque pointer for passing around any computation context
	 */
	void *ctx;

	/**
	 * Pointer to a function for public and private key generation by Alice.
	 *
	 * @param k                Key exchange structure
	 * @param alice_priv       Alice's private key
	 * @param alice_msg        Alice's message (public key + optional additional data)
	 * @param alice_msg_len    Alice's message length
	 * @return                 OQS_SUCCESS on success, or OQS_ERROR on failure
	 */
	OQS_STATUS(*alice_0)
	(struct OQS_KEX *k, void **alive_priv, uint8_t **alice_msg, size_t *alice_msg_len);

	/**
	 * Pointer to a function for shared key generation by Bob.
	 *
	 * @param k                Key exchange structure
	 * @param alice_msg        Alice's message (public key + optional additional data)
	 * @param alice_msg_len    Alice's message length
	 * @param bob_msg          Bob's message (public key / encryption of shared key + optional additional data)
	 * @param bob_msg_len      Bob's message length
	 * @param key              Shared key
	 * @param key_len          Shared key length
	 * @return                 OQS_SUCCESS on success, or OQS_ERROR on failure
	 */
	OQS_STATUS(*bob)
	(struct OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);

	/**
	 * Pointer to a function for shared key generation by Alice.
	 *
	 * @param k                Key exchange structure
	 * @param alice_priv       Alice's private key
	 * @param bob_msg          Bob's message (public key / encryption of shared key + optional additional data)
	 * @param bob_msg_len      Bob's message length
	 * @param key              Shared key
	 * @param key_len          Shared key length
	 * @return                 OQS_SUCCESS on success, or OQS_ERROR on failure
	 */
	OQS_STATUS(*alice_1)
	(struct OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

	/**
	 * Pointer to a function for freeing Alice's private key
	 *
	 * @param k                Key exchange structure
	 * @param alice_priv       Alice's private key
	 */
	void (*alice_priv_free)(struct OQS_KEX *k, void *alice_priv);

	/**
	 * Pointer to a function for freeing the allocated key exchange structure
	 *
	 * @param k                Key exchange structure
	 */
	void (*free)(struct OQS_KEX *k);

} OQS_KEX;

/**
 * Allocate a new key exchange object.
 *
 * @param rand               Random number generator.
 * @param alg_name           Algorithm to be instantiated
 * @param seed               An instance-specific seed, if any, or NULL.
 * @param seed_len           The length of seed, or 0.
 * @param named_parameters   Name or description of method-specific parameters
 *                           to use for this instance (as a NULL-terminated C string),
 *                           if any, or NULL.
 * @return                   The object on success, or NULL on failure.
 */
OQS_KEX *OQS_KEX_new(OQS_RAND *rand, enum OQS_KEX_alg_name alg_name, const uint8_t *seed, const size_t seed_len, const char *named_parameters);

OQS_STATUS OQS_KEX_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
OQS_STATUS OQS_KEX_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
OQS_STATUS OQS_KEX_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_free(OQS_KEX *k);

#endif
