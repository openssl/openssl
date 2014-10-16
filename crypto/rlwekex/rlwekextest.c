/* crypto/rlwekex/rlwekextest.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../e_os.h"

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#ifdef OPENSSL_NO_RLWEKEX
int main(int argc, char *argv[]) {
	printf("No RLWEKEX support\n");
	return (0);
}
#else
#include <openssl/rlwekex.h>

#ifdef OPENSSL_SYS_WIN16
#define MS_CALLBACK	_far _loadds
#else
#define MS_CALLBACK
#endif

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out, size_t *outlen) {
#ifndef OPENSSL_NO_SHA
	if (*outlen < SHA_DIGEST_LENGTH)
		return NULL;
	else
		*outlen = SHA_DIGEST_LENGTH;
	return SHA1(in, inlen, out);
#else
	return NULL;
#endif
}


static int test_rlwekex(BIO *out, int single) {

	RLWE_PAIR *alice = NULL, *bob = NULL;
	RLWE_REC *rec = NULL;

	RLWE_PUB *bob_reconstructed = NULL;
	RLWE_REC *rec_reconstructed = NULL;

	RLWE_CTX *ctx = NULL;

	unsigned char *apubbuf = NULL, *bpubbuf = NULL;
	size_t apublen, bpublen;

	unsigned char *recbuf = NULL;
	size_t reclen;

	unsigned char *assbuf = NULL, *bssbuf = NULL;
	size_t asslen, bsslen;

	int i, ret = 0;

	alice = RLWE_PAIR_new();
	bob = RLWE_PAIR_new();
	bob_reconstructed = RLWE_PUB_new();
	rec = RLWE_REC_new();
	rec_reconstructed = RLWE_REC_new();
	ctx = RLWE_CTX_new ();
	if ((alice == NULL) || (bob == NULL) || (bob_reconstructed == NULL) || (rec == NULL) || (rec_reconstructed == NULL) || (ctx == NULL)) {
		goto err;
	}

	if (single) BIO_puts(out, "Testing key generation\n");

	if (!RLWE_PAIR_generate_key(alice, ctx)) goto err;
	apublen = i2o_RLWE_PUB(RLWE_PAIR_get_publickey(alice), &apubbuf);
	if (single) BIO_printf(out, "  pub_A (%i bytes) = ", (int) apublen);
	if (apublen <= 0) {
		fprintf(stderr, "Error in RLWEKEX routines\n");
		ret = 0;
		goto err;
	}
	if (single) {
		for (i = 0; i < apublen; i++) {
			BIO_printf(out, "%02X", apubbuf[i]);
		}
		BIO_puts(out, "\n");
	}

	if (!RLWE_PAIR_generate_key(bob, ctx)) goto err;
	bpublen = i2o_RLWE_PUB(RLWE_PAIR_get_publickey(bob), &bpubbuf);
	if (single) {
		BIO_printf(out, "\n  pub_B (%i bytes) = ", (int) bpublen);
		for (i = 0; i < bpublen; i++) {
			BIO_printf(out, "%02X", bpubbuf[i]);
		}
		BIO_puts(out, "\n");
	}

	if (single) BIO_puts(out, "Testing Bob shared secret generation\n");

	bsslen = KDF1_SHA1_len;
	bssbuf = (unsigned char *)OPENSSL_malloc(bsslen);
	bsslen = RLWEKEX_compute_key_bob(bssbuf, bsslen, rec,
	                                 RLWE_PAIR_get_publickey(alice), bob, KDF1_SHA1, ctx);
	if (single) {
		BIO_printf(out, "  key_B (%i bytes) = ", (int) bsslen);
		for (i = 0; i < bsslen; i++) {
			BIO_printf(out, "%02X", bssbuf[i]);
		}
		BIO_puts(out, "\n");
	}
	reclen = i2o_RLWE_REC(rec, &recbuf);
	if (single) {
		BIO_printf(out, "  rec (%i bytes) = ", (int) reclen);
		for (i = 0; i < reclen; i++) {
			BIO_printf(out, "%02X", recbuf[i]);
		}
		BIO_puts(out, "\n");
	}

	if (single) BIO_puts(out, "Reconstructing Bob's values\n");

	if (o2i_RLWE_PUB(&bob_reconstructed, bpubbuf, bpublen) == NULL) {
		fprintf(stderr, "Error in RLWEKEX routines (Bob public key reconstruction)\n");
		ret = 0;
		goto err;
	}
	if (o2i_RLWE_REC(&rec_reconstructed, recbuf, reclen) == NULL) {
		fprintf(stderr, "Error in RLWEKEX routines (Bob reconciliation reconstruction)\n");
		ret = 0;
		goto err;
	}

	if (single) BIO_puts(out, "Testing Alice shared secret generation\n");

	asslen = KDF1_SHA1_len;
	assbuf = (unsigned char *)OPENSSL_malloc(asslen);
	asslen = RLWEKEX_compute_key_alice(assbuf, asslen, bob_reconstructed, rec_reconstructed, alice, KDF1_SHA1, ctx);
	if (single) {
		BIO_printf(out, "  key_A (%i bytes) = ", (int) asslen);
		for (i = 0; i < asslen; i++) {
			BIO_printf(out, "%02X", assbuf[i]);
		}
		BIO_puts(out, "\n");
	}

	if ((bsslen != asslen) || (memcmp(assbuf, bssbuf, asslen) != 0)) {
		BIO_printf(out, " failed\n\n");
		fprintf(stderr, "Error in RLWEKEX routines (mismatched shared secrets)\n");
		ret = 0;
	} else {
		if (single) BIO_printf(out, "ok!\n");
		ret = 1;
	}
err:
	ERR_print_errors_fp(stderr);

	OPENSSL_free(bssbuf);
	OPENSSL_free(assbuf);
	OPENSSL_free(apubbuf);
	OPENSSL_free(bpubbuf);
	OPENSSL_free(recbuf);
	RLWE_REC_free(rec_reconstructed);
	RLWE_REC_free(rec);
	RLWE_PUB_free(bob_reconstructed);
	RLWE_PAIR_free(bob);
	RLWE_PAIR_free(alice);
	RLWE_CTX_free(ctx);
	return (ret);
}

int main(int argc, char *argv[]) {
	int ret = 1;
	BIO *out;

	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

#ifdef OPENSSL_SYS_WIN32
	CRYPTO_malloc_init();
#endif

	RAND_seed(rnd_seed, sizeof rnd_seed);

	out = BIO_new(BIO_s_file());
	if (out == NULL) EXIT(1);
	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	if (argc == 1) {
		if (!test_rlwekex(out, 1)) goto err;
	} else {
		int iterations = 0;
		int failures = 0;
		time_t starttime = time(NULL);
		while (1) {
			iterations++;
			if (test_rlwekex(out, 0) == 1) {
			} else {
				failures++;
			}
			if ((iterations % 100) == 0) {
				BIO_printf(out, "Iterations: %d, failures: %d, elapsed time: %ld\n", iterations, failures, time(NULL) - starttime);
			}
		}
	}

	ret = 0;

err:
	ERR_print_errors_fp(stderr);
	BIO_free(out);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	CRYPTO_mem_leaks_fp(stderr);
	EXIT(ret);
	return (ret);
}

#endif
