#include <assert.h>
#include <stdio.h>
#include <math.h>
#if defined(_WIN32)
#include <windows.h>
#include <Wincrypt.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#endif

#include <oqs/common.h>
#include <oqs/rand.h>
#include <oqs/rand_urandom_aesctr.h>
#include <oqs/rand_urandom_chacha20.h>

OQS_RAND *OQS_RAND_new(enum OQS_RAND_alg_name alg_name) {
	switch (alg_name) {
	case OQS_RAND_alg_default:
	case OQS_RAND_alg_urandom_chacha20:
		return OQS_RAND_urandom_chacha20_new();
	case OQS_RAND_alg_urandom_aesctr:
		return OQS_RAND_urandom_aesctr_new();
	default:
		assert(0);
		return NULL; // avoid the warning of potentialy uninitialized variable in VS
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

#if !defined(_WIN32)
/* For some reason specifying inline results in a build error */
inline
#endif
    void
    OQS_RAND_test_record_occurrence(const unsigned char b, unsigned long occurrences[256]) {
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

// Even for a perfectly uniform generator, if the number of samples is
// low then the std dev of the counts will be high.  So, instead, whilst
// still assuming the number of samples isn't super-low, we calculate an
// approximate Chi-squared statistic and back-convert to the Normal
// distribution.  The number of sigmas is reported: -3 to +3 is pretty
// ordinary, big negative is suspiciously-flat counts, big positive is
// wildly-fluctuating counts.
double OQS_RAND_zscore_deviation_from_uniform(const unsigned long occurrences[256]) {
	double quantiles[102] = {
	    156.7872, 158.4155, 160.0555, 161.7072, 163.3707, 165.0460, 166.7331, 168.4321,
	    170.1430, 171.8658, 173.6006, 175.3475, 177.1064, 178.8773, 180.6604, 182.4557,
	    184.2631, 186.0828, 187.9147, 189.7589, 191.6155, 193.4844, 195.3657, 197.2594,
	    199.1656, 201.0843, 203.0155, 204.9593, 206.9157, 208.8847, 210.8663, 212.8607,
	    214.8678, 216.8877, 218.9203, 220.9658, 223.0241, 225.0953, 227.1794, 229.2765,
	    231.3866, 233.5096, 235.6457, 237.7949, 239.9572, 242.1326, 244.3212, 246.5230,
	    248.7380, 250.9663, 253.2079, 255.4627, 257.7310, 260.0126, 262.3076, 264.6160,
	    266.9379, 269.2733, 271.6222, 273.9846, 276.3607, 278.7503, 281.1536, 283.5705,
	    286.0011, 288.4454, 290.9035, 293.3754, 295.8610, 298.3605, 300.8739, 303.4011,
	    305.9422, 308.4973, 311.0663, 313.6493, 316.2463, 318.8574, 321.4825, 324.1217,
	    326.7751, 329.4426, 332.1242, 334.8201, 337.5301, 340.2544, 342.9930, 345.7459,
	    348.5131, 351.2947, 354.0906, 356.9009, 359.7256, 362.5648, 365.4184, 368.2866,
	    371.1692, 374.0664, 376.9782, 379.9045, 382.8454, 385.8010}; // -5.05 to +5.05 sigma: qchisq(pnorm(seq(-5.05,5.05,length.out=102)),255)
	unsigned long total;
	double chsq;
	int i;

	for (total = i = 0; i < 256; i++) {
		total += occurrences[i];
	}
	if (total / 256. < 5) {
		return ZSCORE_SPARSE;
	}

	for (chsq = i = 0; i < 256; i++) {
		chsq += pow(occurrences[i] - total / 256., 2) * 256. / total;
	}

	if (chsq <= quantiles[0]) {
		return ZSCORE_BIGNEG;
	}
	for (i = 1; i < 102; i++) {
		if (chsq <= quantiles[i]) {
			return (i - 51) / 10.0;
		}
	}
	return ZSCORE_BIGPOS;
}
//
// convenience function for statistics reporting
void OQS_RAND_report_statistics(const unsigned long occurrences[256], const char *indent) {
	double zscore = OQS_RAND_zscore_deviation_from_uniform(occurrences);
	printf("%sStatistical distance from uniform: %12.10f\n", indent, OQS_RAND_test_statistical_distance_from_uniform(occurrences));
	printf("%s   Z-score deviation from uniform: ", indent);
	if (zscore == ZSCORE_BIGNEG) {
		printf("less than -5.0 sigma ***\n");
	} else if (zscore == ZSCORE_BIGPOS) {
		printf("more than +5.0 sigma ***\n");
	} else if (zscore == ZSCORE_SPARSE) {
		printf("(too few data)\n");
	} else {
		printf("about %.1f sigma\n", zscore);
	}
	return;
}

OQS_STATUS OQS_RAND_get_system_entropy(uint8_t *buf, size_t n) {
	OQS_STATUS result = OQS_ERROR;

#if !defined(_WIN32)
	int fd = 0;
#endif

	if (!buf) {
		goto err;
	}

#if defined(_WIN32)
	HCRYPTPROV hCryptProv;
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
	    !CryptGenRandom(hCryptProv, (DWORD) n, buf)) {
		goto err;
	}
#else
	fd = open("/dev/urandom", O_RDONLY);
	if (fd <= 0) {
		goto err;
	}
	size_t r = read(fd, buf, n);
	if (r != n) {
		goto err;
	}
#endif
	result = OQS_SUCCESS;

err:
#if !defined(_WIN32)
	if (fd > 0) {
		close(fd);
	}
#endif

	return result;
}
