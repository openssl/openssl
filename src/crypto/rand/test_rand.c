#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

struct rand_testcase {
	enum OQS_RAND_alg_name alg_name;
};

/* Add new testcases here */
struct rand_testcase rand_testcases[] = {
    {OQS_RAND_alg_urandom_chacha20},
    {OQS_RAND_alg_urandom_aesctr},
};

#define RAND_TEST_ITERATIONS 10000000L

static void rand_test_distribution_8(OQS_RAND *rand, unsigned long occurrences[256], int iterations) {
	uint8_t b;
	for (int i = 0; i < iterations; i++) {
		b = OQS_RAND_8(rand);
		OQS_RAND_test_record_occurrence(b, occurrences);
	}
}

static void rand_test_distribution_32(OQS_RAND *rand, unsigned long occurrences[256], int iterations) {
	uint32_t x;
	for (int i = 0; i < iterations; i++) {
		x = OQS_RAND_32(rand);
		uint8_t b;
		for (size_t j = 0; j < sizeof(uint32_t); j++) {
			b = (x >> j) & 0xFF;
			OQS_RAND_test_record_occurrence(b, occurrences);
		}
	}
}

static void rand_test_distribution_64(OQS_RAND *rand, unsigned long occurrences[256], int iterations) {
	uint64_t x;
	for (int i = 0; i < iterations; i++) {
		x = OQS_RAND_64(rand);
		uint8_t b;
		for (size_t j = 0; j < sizeof(uint64_t); j++) {
			b = (x >> j) & 0xFF;
			OQS_RAND_test_record_occurrence(b, occurrences);
		}
	}
}

static OQS_STATUS rand_test_distribution_n(OQS_RAND *rand, unsigned long occurrences[256], int len) {
	uint8_t *x = malloc(len);
	if (x == NULL) {
		return OQS_ERROR;
	}
	OQS_RAND_n(rand, x, len);
	for (int i = 0; i < len; i++) {
		OQS_RAND_test_record_occurrence(x[i], occurrences);
	}
	free(x);
	return OQS_SUCCESS;
}
static OQS_STATUS rand_test_distribution_wrapper(enum OQS_RAND_alg_name alg_name, int iterations, bool quiet) {

	OQS_RAND *rand = OQS_RAND_new(alg_name);
	if (rand == NULL) {
		eprintf("rand is NULL\n");
		return OQS_ERROR;
	}

	if (!quiet) {
		printf("================================================================================\n");
		printf("Sample outputs of PRNG %s\n", rand->method_name);
		printf("================================================================================\n");

		uint8_t x[256];
		OQS_RAND_n(rand, x, 256);
		OQS_print_hex_string("OQS_RAND_n, n = 256", x, 256);

		uint8_t y8 = OQS_RAND_8(rand);
		OQS_print_hex_string("OQS_RAND_8", (uint8_t *) &y8, sizeof(y8));
		y8 = OQS_RAND_8(rand);
		OQS_print_hex_string("OQS_RAND_8", (uint8_t *) &y8, sizeof(y8));

		uint32_t y32 = OQS_RAND_32(rand);
		OQS_print_hex_string("OQS_RAND_32", (uint8_t *) &y32, sizeof(y32));
		y32 = OQS_RAND_32(rand);
		OQS_print_hex_string("OQS_RAND_32", (uint8_t *) &y32, sizeof(y32));

		uint64_t y64 = OQS_RAND_64(rand);
		OQS_print_hex_string("OQS_RAND_64", (uint8_t *) &y64, sizeof(y64));
		y64 = OQS_RAND_64(rand);
		OQS_print_hex_string("OQS_RAND_64", (uint8_t *) &y64, sizeof(y64));

		OQS_RAND_n(rand, x, 256);
		OQS_print_hex_string("OQS_RAND_n, n = 256", x, 256);
	}

	printf("================================================================================\n");
	printf("Testing distribution of PRNG %s\n", rand->method_name);
	printf("================================================================================\n");

	unsigned long occurrences[256];
	for (int i = 0; i < 256; i++) {
		occurrences[i] = 0;
	}

	printf("1-byte mode for %d iterations\n", 8 * iterations);
	rand_test_distribution_8(rand, occurrences, 8 * iterations);
	OQS_RAND_report_statistics(occurrences, "    ");

	for (int i = 0; i < 256; i++) {
		occurrences[i] = 0;
	}

	printf("4-byte mode for %d iterations\n", 2 * iterations);
	rand_test_distribution_32(rand, occurrences, 2 * iterations);
	OQS_RAND_report_statistics(occurrences, "    ");

	for (int i = 0; i < 256; i++) {
		occurrences[i] = 0;
	}

	printf("8-byte mode for %d iterations\n", iterations);
	rand_test_distribution_64(rand, occurrences, iterations);
	OQS_RAND_report_statistics(occurrences, "    ");

	for (int i = 0; i < 256; i++) {
		occurrences[i] = 0;
	}

	printf("n-byte mode for %d bytes\n", 8 * iterations);
	rand_test_distribution_n(rand, occurrences, 8 * iterations);
	OQS_RAND_report_statistics(occurrences, "    ");

	OQS_RAND_free(rand);

	return OQS_SUCCESS;
}

int main(int argc, char **argv) {

	OQS_STATUS success;
	bool quiet = false;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
				quiet = true;
			} else {
				printf("Usage: ./test_rand [options]\n");
				printf("\nOptions:\n");
				printf("  --quiet, -q\n");
				printf("    Less verbose output\n");
				if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "-help") == 0) || (strcmp(argv[i], "--help") == 0)) {
					return EXIT_SUCCESS;
				} else {
					return EXIT_FAILURE;
				}
			}
		}
	}

	size_t rand_testcases_len = sizeof(rand_testcases) / sizeof(struct rand_testcase);
	for (size_t i = 0; i < rand_testcases_len; i++) {
		success = rand_test_distribution_wrapper(rand_testcases[i].alg_name, RAND_TEST_ITERATIONS, quiet);
		if (success != OQS_SUCCESS) {
			goto err;
		}
	}

	success = OQS_SUCCESS;
	goto cleanup;

err:
	success = OQS_ERROR;
	eprintf("ERROR!\n");

cleanup:

	return (success == OQS_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
