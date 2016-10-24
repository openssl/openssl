#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/rand.h>

#include "local.h"

static int lwe_sample_n_inverse_8(uint16_t *s, const size_t n, const uint8_t *cdf_table, const size_t cdf_table_len, OQS_RAND *rand) {

	/* Fills vector s with n samples from the noise distribution which requires
	 * 8 bits to sample. The distribution is specified by its CDF. Super-constant
	 * timing: the CDF table is ingested for every sample.
	 */

	size_t rndlen = n;
	uint8_t *rndvec = (uint8_t *)malloc(rndlen);
	if (rndvec == NULL) {
		fprintf(stderr, "malloc failure\n");
		return 0;
	}
	OQS_RAND_n(rand, rndvec, rndlen);

	size_t i, j;

	for (i = 0; i < n; ++i) {
		uint8_t sample = 0;
		uint8_t rnd = rndvec[i] >> 1; // drop the least significant bit
		uint8_t sign = rndvec[i] & 0x1; // pick the least significant bit

		// No need to compare with the last value.
		for (j = 0; j < cdf_table_len - 1; j++) {
			// Constant time comparison: 1 if cdf_table[j] < rnd, 0 otherwise.
			// Critically uses the fact that cdf_table[j] and rnd fit in 7 bits.
			sample += (uint8_t)(cdf_table[j] - rnd) >> 7;
		}
		// Assuming that sign is either 0 or 1, flips sample iff sign = 1
		s[i] = ((-sign) ^ sample) + sign;
	}

	bzero(rndvec, rndlen);
	free(rndvec);
	return 1;
}

typedef struct {
	uint16_t rnd1 : 11;
	uint8_t sign1 : 1;
	uint16_t rnd2 : 11;
	uint8_t sign2 : 1;
} __attribute__((__packed__)) three_bytes_packed;

static int lwe_sample_n_inverse_12(uint16_t *s, const size_t n, const uint16_t *cdf_table, const size_t cdf_table_len, OQS_RAND *rand) {
	/* Fills vector s with n samples from the noise distribution which requires
	 * 12 bits to sample. The distribution is specified by its CDF. Super-constant
	 * timing: the CDF table is ingested for every sample.
	 */

	assert(sizeof(three_bytes_packed) == 3);

	size_t rndlen = 3 * ((n + 1) / 2);  // 12 bits of unif randomness per output element

	uint8_t *rnd = (uint8_t *)malloc(rndlen);
	if (rnd == NULL) {
		fprintf(stderr, "malloc failure\n");
		return 0;
	}
	OQS_RAND_n(rand, rnd, rndlen);

	size_t i;

	for (i = 0; i < n; i += 2) {  // two output elements at a time
		three_bytes_packed *ptr_packed = (three_bytes_packed *) (rnd + 3 * i / 2);

		uint16_t rnd1 = ptr_packed->rnd1;
		uint16_t rnd2 = ptr_packed->rnd2;

		uint8_t sample1 = 0;
		uint8_t sample2 = 0;

		size_t j;
		// No need to compare with the last value.
		for (j = 0; j < cdf_table_len - 1; j++) {
			// Constant time comparison: 1 if LWE_CDF_TABLE[j] < rnd1, 0 otherwise.
			// Critically uses the fact that LWE_CDF_TABLE[j] and rnd1 fit in 15 bits.
			sample1 += (uint16_t)(cdf_table[j] - rnd1) >> 15;
			sample2 += (uint16_t)(cdf_table[j] - rnd2) >> 15;
		}

		uint8_t sign1 = ptr_packed->sign1;
		uint8_t sign2 = ptr_packed->sign2;

		// Assuming that sign1 is either 0 or 1, flips sample1 iff sign1 = 1
		s[i] = ((-sign1) ^ sample1) + sign1;

		if (i + 1 < n) {
			s[i + 1] = ((-sign2) ^ sample2) + sign2;
		}
	}

	bzero(rnd, rndlen);
	free(rnd);
	return 1;
}

static int lwe_sample_n_inverse_16(uint16_t *s, const size_t n, const uint16_t *cdf_table, const size_t cdf_table_len, OQS_RAND *rand) {
	/* Fills vector s with n samples from the noise distribution which requires
	 * 16 bits to sample. The distribution is specified by its CDF. Super-constant
	 * timing: the CDF table is ingested for every sample.
	 */

	size_t rndlen = 2 * n;
	uint16_t *rndvec = (uint16_t *)malloc(rndlen);
	if (rndvec == NULL) {
		return 0;
	}
	OQS_RAND_n(rand, (uint8_t *) rndvec, rndlen);

	size_t i, j;

	for (i = 0; i < n; ++i) {
		uint8_t sample = 0;
		uint16_t rnd = rndvec[i] >> 1; // drop the least significant bit
		uint8_t sign = rndvec[i] & 0x1; // pick the least significant bit

		// No need to compare with the last value.
		for (j = 0; j < cdf_table_len - 1; j++) {
			// Constant time comparison: 1 if LWE_CDF_TABLE[j] < rnd, 0 otherwise.
			// Critically uses the fact that LWE_CDF_TABLE[j] and rnd fit in 15 bits.
			sample += (uint16_t)(cdf_table[j] - rnd) >> 15;
		}
		// Assuming that sign is either 0 or 1, flips sample iff sign = 1
		s[i] = ((-sign) ^ sample) + sign;
	}

	bzero(rndvec, rndlen);
	free(rndvec);
	return 1;
}

int oqs_kex_lwe_frodo_sample_n(uint16_t *s, const size_t n, struct oqs_kex_lwe_frodo_params *params, OQS_RAND *rand) {

	switch (params->sampler_num) {
	case 8: {
		// have to copy cdf_table from uint16_t to uint8_t
		uint8_t *cdf_table_8 = malloc(params->cdf_table_len * sizeof(uint8_t));
		if (NULL == cdf_table_8) {
			return 0;
		}
		for (size_t i = 0; i < params->cdf_table_len; i++) {
			cdf_table_8[i] = (uint8_t) params->cdf_table[i];
		}
		int ret = lwe_sample_n_inverse_8(s, n, cdf_table_8, params->cdf_table_len, rand);
		free(cdf_table_8);
		return ret;
	}
	case 12:
		return lwe_sample_n_inverse_12(s, n, params->cdf_table, params->cdf_table_len, rand);
	case 16:
		return lwe_sample_n_inverse_16(s, n, params->cdf_table, params->cdf_table_len, rand);
	default:
		return 0;
	}

}
