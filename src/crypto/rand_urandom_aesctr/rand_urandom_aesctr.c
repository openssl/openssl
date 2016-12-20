#include <sys/types.h>
#if defined(WINDOWS)
#include <windows.h>
#include <Wincrypt.h>
#else
#include <sys/uio.h>
#include <unistd.h>
#include <strings.h>
#endif
#include <string.h> //memcpy
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>

#include <oqs/rand.h>
#include <oqs/rand_urandom_aesctr.h>
#include <oqs/aes.h>
#include <assert.h>

typedef struct oqs_rand_urandom_aesctr_ctx {
	uint64_t ctr;
	void *schedule;
	uint8_t cache[64];
	size_t cache_next_byte;
} oqs_rand_urandom_aesctr_ctx;

static oqs_rand_urandom_aesctr_ctx *oqs_rand_urandom_aesctr_ctx_new() {
#if defined(WINDOWS)
	HCRYPTPROV   hCryptProv;
#else
	int fd = 0;
#endif
	oqs_rand_urandom_aesctr_ctx *rand_ctx = NULL;
	rand_ctx = (oqs_rand_urandom_aesctr_ctx *) malloc(sizeof(oqs_rand_urandom_aesctr_ctx));
	if (rand_ctx == NULL) {
		goto err;
	}
	uint8_t key[16];
#if defined(WINDOWS)
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
	        !CryptGenRandom(hCryptProv, 16, key)) {
		goto err;
	}
#else
	fd = open("/dev/urandom", O_RDONLY);
	if (fd <= 0) {
		goto err;
	}
	int r = read(fd, key, 16);
	if (r != 16) {
		goto err;
	}
#endif
	OQS_AES128_load_schedule(key, &rand_ctx->schedule, 1);
	rand_ctx->cache_next_byte = 64; // cache is empty
	rand_ctx->ctr = 0;
	goto okay;
err:
	if (rand_ctx) {
		free(rand_ctx);
	}
#if !defined(WINDOWS)
	if (fd > 0) {
		close(fd);
	}
#endif
	return NULL;
okay:
#if !defined(WINDOWS)
	close(fd);
#endif
	return rand_ctx;
}

void OQS_RAND_urandom_aesctr_n(OQS_RAND *r, uint8_t *out, size_t n) {
	oqs_rand_urandom_aesctr_ctx *rand_ctx = (oqs_rand_urandom_aesctr_ctx *) r->ctx;
	uint64_t *out_64 = (uint64_t *) out;
	for (size_t i = 0; i < n / 16; i++) {
		out_64[i] = rand_ctx->ctr;
		rand_ctx->ctr++;
	}
	OQS_AES128_ECB_enc_sch(out, n, rand_ctx->schedule, out);
	for (size_t i = 0; i < n % 16; i++) {
		out[16 * (n / 16) + i] = OQS_RAND_urandom_aesctr_8(r);
	}
}

static void OQS_RAND_urandom_aesctr_fill_cache(OQS_RAND *r) {
	oqs_rand_urandom_aesctr_ctx *rand_ctx = (oqs_rand_urandom_aesctr_ctx *) r->ctx;
	OQS_RAND_urandom_aesctr_n(r, rand_ctx->cache, sizeof(rand_ctx->cache));
	rand_ctx->cache_next_byte = 0;
}

uint8_t OQS_RAND_urandom_aesctr_8(OQS_RAND *r) {
	oqs_rand_urandom_aesctr_ctx *rand_ctx = (oqs_rand_urandom_aesctr_ctx *) r->ctx;
	if (rand_ctx->cache_next_byte > sizeof(rand_ctx->cache) - 1) {
		OQS_RAND_urandom_aesctr_fill_cache(r);
	}
	uint8_t out = rand_ctx->cache[rand_ctx->cache_next_byte];
	rand_ctx->cache_next_byte += 1;
	return out;
}


uint32_t OQS_RAND_urandom_aesctr_32(OQS_RAND *r) {
	oqs_rand_urandom_aesctr_ctx *rand_ctx = (oqs_rand_urandom_aesctr_ctx *) r->ctx;
	if (rand_ctx->cache_next_byte > sizeof(rand_ctx->cache) - 4) {
		OQS_RAND_urandom_aesctr_fill_cache(r);
	}
	uint32_t out;
	memcpy(&out, &rand_ctx->cache[rand_ctx->cache_next_byte], 4);
	rand_ctx->cache_next_byte += 4;
	return out;
}

uint64_t OQS_RAND_urandom_aesctr_64(OQS_RAND *r) {
	oqs_rand_urandom_aesctr_ctx *rand_ctx = (oqs_rand_urandom_aesctr_ctx *) r->ctx;
	if (rand_ctx->cache_next_byte > sizeof(rand_ctx->cache) - 8) {
		OQS_RAND_urandom_aesctr_fill_cache(r);
	}
	uint64_t out;
	memcpy(&out, &rand_ctx->cache[rand_ctx->cache_next_byte], 8);
	rand_ctx->cache_next_byte += 8;
	return out;
}

void OQS_RAND_urandom_aesctr_free(OQS_RAND *r) {
	if (r) {
		oqs_rand_urandom_aesctr_ctx *rand_ctx = (oqs_rand_urandom_aesctr_ctx *) r->ctx;
		if (rand_ctx) {
			OQS_AES128_free_schedule(rand_ctx->schedule);
		}
		free(r->ctx);
		free(r->method_name);
	}
	free(r);
}

OQS_RAND *OQS_RAND_urandom_aesctr_new() {
	OQS_RAND *r = malloc(sizeof(OQS_RAND));
	if (r == NULL) {
		return NULL;
	}
	r->method_name = strdup("urandom_aesctr");
	r->ctx = oqs_rand_urandom_aesctr_ctx_new();
	if (r->ctx == NULL || r->method_name == NULL) {
		OQS_RAND_urandom_aesctr_free(r);
		return NULL;
	}
	r->estimated_classical_security = 128;
	r->estimated_quantum_security = 64; // Grover search
	r->rand_8 = &OQS_RAND_urandom_aesctr_8;
	r->rand_32 = &OQS_RAND_urandom_aesctr_32;
	r->rand_64 = &OQS_RAND_urandom_aesctr_64;
	r->rand_n = &OQS_RAND_urandom_aesctr_n;
	r->free = &OQS_RAND_urandom_aesctr_free;
	return r;
}
