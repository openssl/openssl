#if defined(_WIN32)
#pragma warning(disable : 4244 4293)
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include "../ds_benchmark.h"

// TODO: add signature size to benchmark

struct sig_testcase {
	enum OQS_SIG_algid algid;
	char *algid_name;
	int run;
	int iter;
};

/* Add new testcases here */
#ifdef ENABLE_SIG_PICNIC
struct sig_testcase sig_testcases[] = {
    {OQS_SIG_picnic_L1_FS, "picnic_L1_FS", 0, 10},
    {OQS_SIG_picnic_L1_UR, "picnic_L1_UR", 0, 10},
    {OQS_SIG_picnic_L3_FS, "picnic_L3_FS", 0, 10},
    {OQS_SIG_picnic_L3_UR, "picnic_L3_UR", 0, 10},
    {OQS_SIG_picnic_L5_FS, "picnic_L5_FS", 0, 10},
    {OQS_SIG_picnic_L5_UR, "picnic_L5_UR", 0, 10},
};
#endif

#define SIG_TEST_ITERATIONS 100
#define SIG_BENCH_SECONDS 1

static OQS_STATUS sig_test_correctness(OQS_RAND *rand, enum OQS_SIG_algid algid, const int print) {

	OQS_STATUS rc;

	uint8_t *priv = NULL;
	uint8_t *pub = NULL;
	uint8_t *msg = NULL;
	size_t msg_len;
	uint8_t *sig = NULL;
	size_t sig_len;

	/* setup signature object */
	OQS_SIG *s = OQS_SIG_new(rand, algid);
	if (s == NULL) {
		eprintf("sig new failed\n");
		goto err;
	}

	if (print) {
		printf("================================================================================\n");
		printf("Sample computation for signature method %s\n", s->method_name);
		printf("================================================================================\n");
	}

	/* key generation */
	priv = malloc(s->priv_key_len);
	if (priv == NULL) {
		eprintf("priv malloc failed\n");
		goto err;
	}
	pub = malloc(s->pub_key_len);
	if (pub == NULL) {
		eprintf("pub malloc failed\n");
		goto err;
	}

	rc = OQS_SIG_keygen(s, priv, pub);
	if (rc != OQS_SUCCESS) {
		eprintf("OQS_SIG_keygen failed\n");
		goto err;
	}

	if (print) {
		OQS_print_hex_string("Private key", priv, s->priv_key_len);
		OQS_print_hex_string("Public key", pub, s->pub_key_len);
	}

	/* Generate message to sign */
	msg_len = 100; // FIXME TODO: randomize based on scheme's max length
	msg = malloc(msg_len);
	if (msg == NULL) {
		eprintf("msg malloc failed\n");
		goto err;
	}
	OQS_RAND_n(rand, msg, msg_len);
	if (print) {
		OQS_print_hex_string("Message", msg, msg_len);
	}

	/* Signature */
	sig_len = s->max_sig_len;
	sig = malloc(sig_len);
	if (sig == NULL) {
		eprintf("sig malloc failed\n");
		goto err;
	}

	rc = OQS_SIG_sign(s, priv, msg, msg_len, sig, &sig_len);
	if (rc != OQS_SUCCESS) {
		eprintf("OQS_SIG_sign failed\n");
		goto err;
	}

	if (print) {
		if (sig_len > 40) {
			// only print the parts of the sig if too long
			OQS_print_part_hex_string("Signature", sig, sig_len, 20);
		}
	}

	/* Verification */
	rc = OQS_SIG_verify(s, pub, msg, msg_len, sig, sig_len);
	if (rc != OQS_SUCCESS) {
		eprintf("ERROR: OQS_SIG_verify failed\n");
		goto err;
	}

	if (print) {
		printf("Signature is valid.\n");
		printf("\n\n");
	}

	rc = OQS_SUCCESS;
	goto cleanup;

err:
	rc = OQS_ERROR;

cleanup:
	if (msg != NULL) {
		free(msg);
	}
	if (sig != NULL) {
		free(sig);
	}
	if (pub != NULL) {
		free(pub);
	}
	if (priv != NULL) {
		free(priv);
	}
	if (s != NULL) {
		OQS_SIG_free(s);
	}

	return rc;
}

UNUSED static OQS_STATUS sig_test_correctness_wrapper(OQS_RAND *rand, enum OQS_SIG_algid algid, int iterations, bool quiet) {
	OQS_STATUS ret;
	ret = sig_test_correctness(rand, algid, !quiet);
	if (ret != OQS_SUCCESS) {
		goto err;
	}

	printf("Testing correctness and randomness of signature for %d iterations\n", iterations);
	for (int i = 0; i < iterations; i++) {
		ret = sig_test_correctness(rand, algid, 0);
		if (ret != OQS_SUCCESS) {
			goto err;
		}
	}
	printf("All signatures were valid.\n");
	printf("\n\n");
	return OQS_SUCCESS;
err:
	return ret;
}

UNUSED static OQS_STATUS sig_bench_wrapper(OQS_RAND *rand, enum OQS_SIG_algid algid, const int seconds) {
	OQS_STATUS rc;

	uint8_t *priv = NULL;
	uint8_t *pub = NULL;
	uint8_t *msg = NULL;
	size_t msg_len;
	uint8_t *sig = NULL;
	size_t sig_len;

	/* setup signature object */
	OQS_SIG *s = OQS_SIG_new(rand, algid);
	if (s == NULL) {
		eprintf("sig new failed\n");
		goto err;
	}

	/* key generation */
	priv = malloc(s->priv_key_len);
	if (priv == NULL) {
		eprintf("priv malloc failed\n");
		goto err;
	}
	pub = malloc(s->pub_key_len);
	if (pub == NULL) {
		eprintf("pub malloc failed\n");
		goto err;
	}

	printf("%-30s | %10s | %14s | %15s | %10s | %16s | %10s\n", s->method_name, "", "", "", "", "", "");

	TIME_OPERATION_SECONDS({ OQS_SIG_keygen(s, priv, pub); }, "keygen", seconds);

	OQS_SIG_keygen(s, priv, pub);
	/* Generate message to sign */
	msg_len = 100; // FIXME TODO: randomize based on scheme's max length
	msg = malloc(msg_len);
	if (msg == NULL) {
		eprintf("msg malloc failed\n");
		goto err;
	}
	sig_len = s->max_sig_len;
	sig = malloc(sig_len);
	if (sig == NULL) {
		eprintf("sig malloc failed\n");
		goto err;
	}

	TIME_OPERATION_SECONDS({ OQS_SIG_sign(s, priv, msg, msg_len, sig, &sig_len); sig_len = s->max_sig_len; }, "sign", seconds);

	OQS_SIG_sign(s, priv, msg, msg_len, sig, &sig_len);
	TIME_OPERATION_SECONDS({ OQS_SIG_verify(s, pub, msg, msg_len, sig, sig_len); }, "verify", seconds);

	rc = OQS_SUCCESS;
	goto cleanup;

err:
	rc = OQS_ERROR;

cleanup:
	free(priv);
	free(pub);
	free(msg);
	free(sig);
	OQS_SIG_free(s);

	return rc;
}

#ifdef ENABLE_SIG_PICNIC
int main(int argc, char **argv) {
	OQS_STATUS success = OQS_SUCCESS;
	bool run_all = true;
	bool quiet = false;
	bool bench = false;
	OQS_RAND *rand = NULL;
	size_t sig_testcases_len = sizeof(sig_testcases) / sizeof(struct sig_testcase);
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "-help") == 0) || (strcmp(argv[i], "--help") == 0)) {
				printf("Usage: ./test_sig [options] [schemes]\n");
				printf("\nOptions:\n");
				printf("  --quiet, -q\n");
				printf("    Less verbose output\n");
				printf("  --bench, -b\n");
				printf("    Run benchmarks\n");
				printf("\nschemes:\n");
				for (size_t i = 0; i < sig_testcases_len; i++) {
					printf("  %s\n", sig_testcases[i].algid_name);
				}
				return EXIT_SUCCESS;
			} else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
				quiet = true;
			} else if (strcmp(argv[i], "--bench") == 0 || strcmp(argv[i], "-b") == 0) {
				bench = true;
			}

		} else {
			run_all = false;
			for (size_t j = 0; j < sig_testcases_len; j++) {
				if (strcmp(argv[i], sig_testcases[j].algid_name) == 0) {
					sig_testcases[j].run = 1;
				}
			}
		}
	}

	/* setup RAND */
	rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
	if (rand == NULL) {
		goto err;
	}

	for (size_t i = 0; i < sig_testcases_len; i++) {
		if (run_all || sig_testcases[i].run == 1) {
			int num_iter = sig_testcases[i].iter;
			success = sig_test_correctness_wrapper(rand, sig_testcases[i].algid, num_iter, quiet);
		}
		if (success != OQS_SUCCESS) {
			goto err;
		}
	}

	if (bench) {
		PRINT_TIMER_HEADER
		for (size_t i = 0; i < sig_testcases_len; i++) {
			if (run_all || sig_testcases[i].run == 1) {
				sig_bench_wrapper(rand, sig_testcases[i].algid, SIG_BENCH_SECONDS);
			}
		}
		PRINT_TIMER_FOOTER
	}

	success = OQS_SUCCESS;
	goto cleanup;

err:
	success = OQS_ERROR;
	eprintf("ERROR!\n");

cleanup:
	if (rand) {
		OQS_RAND_free(rand);
	}
	return (success == OQS_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
#else // !ENABLE_SIG_PICNIC
int main(void) {
	printf("No signature algorithm available. Make sure configure was run properly; see Readme.md.\n");
	return EXIT_FAILURE;
}
#endif
