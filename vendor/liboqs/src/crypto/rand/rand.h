/**
 * \file rand.h
 * \brief Header defining the generic OQS PRNG
 */

#ifndef __OQS_RAND_H
#define __OQS_RAND_H

#include <stddef.h>
#include <stdint.h>

enum OQS_RAND_alg_name {
	OQS_RAND_alg_default,
	OQS_RAND_alg_urandom_chacha20,
	OQS_RAND_alg_urandom_aesctr,
};

typedef struct OQS_RAND OQS_RAND;

/**
 * OQS PRNG object
 */
struct OQS_RAND {

	/**
	 * Specifies the name of the random number function
	 */
	char *method_name;

	/**
	 * Estimated number of bits of security provided against a classical
	 * attacker
	 */
	uint16_t estimated_classical_security;

	/**
	 * Estimated number of bits of security provided against a quantum
	 * attacker
	 */
	uint16_t estimated_quantum_security;

	/**
	 * Pointer for storing the state of the PRNG
	 */
	void *ctx;

	/**
	 * Function which returns an 8-bit random unsigned integer
	 */
	uint8_t (*rand_8)(OQS_RAND *r);

	/**
	 * Function which returns an 32-bit random unsigned integer
	 */
	uint32_t (*rand_32)(OQS_RAND *r);

	/**
	 * Function which returns an 64-bit random unsigned integer
	 */
	uint64_t (*rand_64)(OQS_RAND *r);

	/**
	 * Function which generates n random 8-bit unsigned integers
	 *
	 * @param out : pointer to an array large enough to store the output integers (\f$\text{size} \geq n\f$)
	 * @param n : number of integers to generate
	 */
	void (*rand_n)(OQS_RAND *r, uint8_t *out, size_t n);

	/**
	 * Pointer to a function for freeing the allocated key exchange structure
	 *
	 * @param k : Key exchange structure
	 *
	 */
	void (*free)(OQS_RAND *r);
};

OQS_RAND *OQS_RAND_new(enum OQS_RAND_alg_name alg_name);

uint8_t OQS_RAND_8(OQS_RAND *r);
uint32_t OQS_RAND_32(OQS_RAND *r);
uint64_t OQS_RAND_64(OQS_RAND *r);
void OQS_RAND_n(OQS_RAND *r, uint8_t *out, size_t n);

void OQS_RAND_free(OQS_RAND *r);

void OQS_RAND_test_record_occurrence(const unsigned char b, unsigned long occurrences[256]);
double OQS_RAND_test_statistical_distance_from_uniform(const unsigned long occurrences[256]);

#define ZSCORE_SPARSE (999.999)
#define ZSCORE_BIGNEG (-100.0)
#define ZSCORE_BIGPOS (+100.0)
double OQS_RAND_zscore_deviation_from_uniform(const unsigned long occurrences[256]);
void OQS_RAND_report_statistics(const unsigned long occurrences[256], const char *indent);

int OQS_RAND_get_system_entropy(uint8_t *buf, size_t n);
#endif
