#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <oqs/rand.h>

#include "aes.h"
#include "../ds_benchmark.h"

#define BENCH_DURATION 1

#define TEST_ITERATIONS 100

#define TEST_REPEATEDLY(x) \
	for (int i = 0; i < TEST_ITERATIONS; i++) { \
		int ok = (x); \
		if (ok != EXIT_SUCCESS) { \
			fprintf(stderr, "Failure in %s (iteration %d)\n", #x, i); \
			return EXIT_FAILURE; \
		} \
	}

static void print_bytes(uint8_t *bytes, size_t num_bytes) {
	for (size_t i = 0; i < num_bytes; i++) {
		printf("%02x", (unsigned)bytes[i]);
	}
}

static int test_aes128_correctness_c(OQS_RAND *rand) {
	uint8_t key[16], schedule[OQS_AES128_SCHEDULE_NUMBYTES], plaintext[16], ciphertext[16], decrypted[16];
	OQS_RAND_n(rand, key, 16);
	OQS_RAND_n(rand, plaintext, 16);
	OQS_AES128_load_schedule_c(key, schedule);
	OQS_AES128_enc_c(plaintext, schedule, ciphertext);
	OQS_AES128_dec_c(ciphertext, schedule, decrypted);
	if (memcmp(plaintext, decrypted, 16) == 0) {
		return EXIT_SUCCESS;
	} else {
		print_bytes(plaintext, 16);
		printf("\n");
		print_bytes(decrypted, 16);
		printf("\n");
		return EXIT_FAILURE;
		return EXIT_FAILURE;
	}
}

#ifndef AES_DISABLE_NI
static int test_aes128_correctness_ni(OQS_RAND *rand) {
	uint8_t key[16], schedule[OQS_AES128_SCHEDULE_NUMBYTES], plaintext[16], ciphertext[16], decrypted[16];
	OQS_RAND_n(rand, key, 16);
	OQS_RAND_n(rand, plaintext, 16);
	OQS_AES128_load_schedule_ni(key, schedule);
	OQS_AES128_enc_ni(plaintext, schedule, ciphertext);
	OQS_AES128_dec_ni(ciphertext, schedule, decrypted);
	if (memcmp(plaintext, decrypted, 16) == 0) {
		return EXIT_SUCCESS;
	} else {
		print_bytes(plaintext, 16);
		printf("\n");
		print_bytes(decrypted, 16);
		printf("\n");
		return EXIT_FAILURE;
	}
}

static int test_aes128_c_equals_ni(OQS_RAND *rand) {
	uint8_t key[16], schedule_c[OQS_AES128_SCHEDULE_NUMBYTES], schedule_ni[OQS_AES128_SCHEDULE_NUMBYTES], plaintext[16], ciphertext_c[16], ciphertext_ni[16];
	OQS_RAND_n(rand, key, 16);
	OQS_RAND_n(rand, plaintext, 16);
	OQS_AES128_load_schedule_c(key, schedule_c);
	OQS_AES128_load_schedule_ni(key, schedule_ni);
	OQS_AES128_enc_c(plaintext, schedule_c, ciphertext_c);
	OQS_AES128_enc_ni(plaintext, schedule_ni, ciphertext_ni);
	if (memcmp(ciphertext_c, ciphertext_ni, 16) == 0) {
		return EXIT_SUCCESS;
	} else {
		print_bytes(ciphertext_c, 16);
		printf("\n");
		print_bytes(ciphertext_ni, 16);
		printf("\n");
		return EXIT_FAILURE;
	}
}
#endif

static int test_aes128_ecb_correctness(OQS_RAND *rand) {
	uint8_t key[16], schedule[OQS_AES128_SCHEDULE_NUMBYTES], plaintext[320], ciphertext[320], decrypted[320];
	OQS_RAND_n(rand, key, 16);
	OQS_RAND_n(rand, plaintext, 320);
	OQS_AES128_load_schedule(key, schedule);
	OQS_AES128_ECB_enc(plaintext, 320, schedule, ciphertext);
	OQS_AES128_ECB_dec(ciphertext, 320, schedule, decrypted);
	if (memcmp(plaintext, decrypted, 320) == 0) {
		return EXIT_SUCCESS;
	} else {
		print_bytes(plaintext, 320);
		printf("\n");
		print_bytes(decrypted, 320);
		printf("\n");
		return EXIT_FAILURE;
	}
}

static void speed_aes128_c(OQS_RAND *rand) {
	uint8_t key[16], schedule[OQS_AES128_SCHEDULE_NUMBYTES], plaintext[16], ciphertext[16], decrypted[16];
	OQS_RAND_n(rand, key, 16);
	OQS_RAND_n(rand, plaintext, 16);
	TIME_OPERATION_SECONDS(OQS_AES128_load_schedule_c(key, schedule), "OQS_AES128_load_schedule_c", BENCH_DURATION);
	TIME_OPERATION_SECONDS(OQS_AES128_enc_c(plaintext, schedule, ciphertext), "OQS_AES128_enc_c", BENCH_DURATION);
	TIME_OPERATION_SECONDS(OQS_AES128_dec_c(ciphertext, schedule, decrypted), "OQS_AES128_dec_c", BENCH_DURATION);
}

#ifndef AES_DISABLE_NI
static void speed_aes128_ni(OQS_RAND *rand) {
	uint8_t key[16], schedule[OQS_AES128_SCHEDULE_NUMBYTES], plaintext[16], ciphertext[16], decrypted[16];
	OQS_RAND_n(rand, key, 16);
	OQS_RAND_n(rand, plaintext, 16);
	TIME_OPERATION_SECONDS(OQS_AES128_load_schedule_ni(key, schedule), "OQS_AES128_load_schedule_ni", BENCH_DURATION);
	TIME_OPERATION_SECONDS(OQS_AES128_enc_ni(plaintext, schedule, ciphertext), "OQS_AES128_enc_ni", BENCH_DURATION);
	TIME_OPERATION_SECONDS(OQS_AES128_dec_ni(ciphertext, schedule, decrypted), "OQS_AES128_dec_ni", BENCH_DURATION);
}
#endif

int main() {
	int ret;
	printf("=== test_aes correctness ===\n");
	OQS_RAND *rand = OQS_RAND_new(OQS_RAND_alg_default);
	if (rand == NULL) {
		fprintf(stderr, "OQS_RAND_new() failed\n");
		goto err;
	}
	TEST_REPEATEDLY(test_aes128_correctness_c(rand));
#ifndef AES_DISABLE_NI
	TEST_REPEATEDLY(test_aes128_correctness_ni(rand));
	TEST_REPEATEDLY(test_aes128_c_equals_ni(rand));
#endif
	TEST_REPEATEDLY(test_aes128_ecb_correctness(rand));
	printf("Tests passed.\n\n");
	printf("=== test_aes performance ===\n");
	PRINT_TIMER_HEADER
	speed_aes128_c(rand);
#ifndef AES_DISABLE_NI
	speed_aes128_ni(rand);
#endif
	PRINT_TIMER_FOOTER
	ret = EXIT_SUCCESS;
	goto cleanup;
err:
	ret = EXIT_FAILURE;
cleanup:
	OQS_RAND_free(rand);
	return ret;
}
