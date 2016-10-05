/**
 * \file kex.h
 * \brief Header defining the API for generic OQS Key exchange
 */

#ifndef __OQS_KEX_H
#define __OQS_KEX_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/rand.h>

enum OQS_KEX_alg_name {
	OQS_KEX_alg_rlwe_bcns15,
};

typedef struct OQS_KEX OQS_KEX;

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
	const uint8_t *seed;

	/**
	 * Size of instance-specific seed, if any.
	 */
	size_t seed_len;

	/**
	 * Named parameters for this key exchange method instance, if any.
	 */
	const char *named_parameters;

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
	 * @param alice_msg        Alice's public key
	 * @param alice_msg_len    Alice's public key length
	 * @return                 1 on success, or 0 on failure
	 */
	int (*alice_0)(OQS_KEX *k, void **alive_priv, uint8_t **alice_msg, size_t *alice_msg_len);

	/**
	 * Pointer to a function for public, private and shared key generation by Bob.
	 *
	 * @param k                Key exchange structure
	 * @param alice_msg        Alice's public key
	 * @param alice_msg_len    Alice's public key length
	 * @param bob_msg          Bob's public key
	 * @param bob_msg_len      Bob's public key length
	 * @param key              Shared key
	 * @param key_len          Shared key length
	 * @return                 1 on success, or 0 on failure
	 */
	int (*bob)(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);

	/**
	 * Pointer to a function for shared key generation by Alice.
	 *
	 * @param k                Key exchange structure
	 * @param alice_priv       Alice's private key
	 * @param bob_msg          Bob's public key
	 * @param bob_msg_len      Bob's public key length
	 * @param key              Shared key
	 * @param key_len          Shared key length
	 * @return                 1 on success, or 0 on failure
	 */
	int (*alice_1)(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

	/**
	 * Pointer to a function for freeing Alice's private key
	 *
	 * @param k                Key exchange structure
	 * @param alice_priv       Alice's private key
	 */
	void (*alice_priv_free)(OQS_KEX *k, void *alice_priv);

	/**
	 * Pointer to a function for freeing the allocated key exchange structure
	 *
	 * @param k                Key exchange structure
	 */
	void (*free)(OQS_KEX *k);

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

int OQS_KEX_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len);
int OQS_KEX_bob(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len);
int OQS_KEX_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len);

void OQS_KEX_alice_priv_free(OQS_KEX *k, void *alice_priv);
void OQS_KEX_free(OQS_KEX *k);

#endif
