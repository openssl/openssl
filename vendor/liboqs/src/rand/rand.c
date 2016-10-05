#include <assert.h>
#include <math.h>

#include <oqs/rand.h>
#include <oqs/rand_urandom_chacha20.h>

OQS_RAND *OQS_RAND_new(enum OQS_RAND_alg_name alg_name) {
	switch (alg_name) {
	case OQS_RAND_alg_default:
	case OQS_RAND_alg_urandom_chacha20:
		return OQS_RAND_urandom_chacha20_new();
	default:
		assert(0);
	}
}

uint8_t OQS_RAND_8(OQS_RAND *r) {
	return r->rand_8(r);
}

uint32_t OQS_RAND_32(OQS_RAND *r) {
	return r->rand_32(r);
}

uint64_t OQS_RAND_64(OQS_RAND *r) {
	return r->rand_64(r);
}

void OQS_RAND_n(OQS_RAND *r, uint8_t *out, size_t n) {
	r->rand_n(r, out, n);
}

void OQS_RAND_free(OQS_RAND *r) {
	if (r) {
		r->free(r);
	}
}

#if !defined(WINDOWS)
/* For some reason specifying inline results in a build error */
inline
#endif
void OQS_RAND_test_record_occurrence(const unsigned char b, unsigned long occurrences[256]) {
	occurrences[b] += 1;
}

double OQS_RAND_test_statistical_distance_from_uniform(const unsigned long occurrences[256]) {

	// compute total number of samples
	unsigned long total = 0;
	for (int i = 0; i < 256; i++) {
		total += occurrences[i];
	}

	// compute statistical distance from uniform
	// SD(X,Y) = 1/2 \sum_z | Pr[X=z] - Pr[Y=z] |
	//         = 1/2 \sum_z | 1/256   - Pr[Y=z] |
	double distance = 0.0;
	for (int i = 0; i < 256; i++) {
		distance += fabs(1.0 / 256.0 - (double) occurrences[i] / (double) total);
	}
	distance /= 2.0;

	return distance;

}
