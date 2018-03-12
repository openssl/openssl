#include <sys/types.h>
#if defined(_WIN32)
#include <windows.h>
#include <Wincrypt.h>
#else
#include <strings.h>
#include <sys/uio.h>
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> //memcpy

#include <assert.h>
#include <oqs/aes.h>
#include <oqs/common.h>
#include <oqs/rand.h>
#include <oqs/rand_urandom_aesctr.h>

#if defined(_WIN32)
#define strdup _strdup // for strdup deprecation warning
#endif

typedef struct oqs_rand_urandom_aesctr_ctx {
	uint64_t ctr;
	void *schedule;
	uint8_t cache[64];
	size_t cache_next_byte;
} oqs_rand_urandom_aesctr_ctx;

static oqs_rand_urandom_aesctr_ctx *oqs_rand_urandom_aesctr_ctx_new() {
	oqs_rand_urandom_aesctr_ctx *rand_ctx = NULL;
	rand_ctx = (oqs_rand_urandom_aesctr_ctx *) malloc(sizeof(oqs_rand_urandom_aesctr_ctx));
	if (rand_ctx == NULL) {
		goto err;
	}
	uint8_t key[16];
	if (OQS_RAND_get_system_entropy(key, 16) != OQS_SUCCESS) {
		goto err;
	}
	OQS_AES128_load_schedule(key, &rand_ctx->schedule, 1);
	rand_ctx->cache_next_byte = 64; // cache is empty
	rand_ctx->ctr = 0;
	goto okay;
err:
	if (rand_ctx) {
		free(rand_ctx);
	}
	return NULL;
okay:
	return rand_ctx;
}

void OQS_RAND_urandom_aesctr_n(OQS_RAND *r, uint8_t *out, size_t n) {
	oqs_rand_urandom_aesctr_ctx *rand_ctx = (oqs_rand_urandom_aesctr_ctx *) r->ctx;
	const uint64_t num_full_blocks = n / 16;
	uint64_t *half_blocks = (uint64_t *) out;
	for (size_t i = 0; i < num_full_blocks; i++) {
		half_blocks[2 * i] = rand_ctx->ctr++;
		half_blocks[2 * i + 1] = rand_ctx->ctr++;
	}
	OQS_AES128_ECB_enc_sch(out, 16 * num_full_blocks, rand_ctx->schedule, out);
	if (n % 16 > 0) {
		uint8_t tmp_8[16];
		uint64_t *tmp_64 = (uint64_t *) tmp_8;
		tmp_64[0] = rand_ctx->ctr++;
		tmp_64[1] = rand_ctx->ctr++;
		OQS_AES128_ECB_enc_sch(tmp_8, 16, rand_ctx->schedule, tmp_8);
		memcpy(out + 16 * num_full_blocks, tmp_8, n % 16);
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
