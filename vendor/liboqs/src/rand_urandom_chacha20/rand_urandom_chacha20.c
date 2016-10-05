#include <sys/types.h>
#if defined(WINDOWS)
#include <windows.h>
#include <Wincrypt.h>
#else
#include <sys/uio.h>
#include <unistd.h>
#include <strings.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>

#include <oqs/rand.h>
#include <oqs/rand_urandom_chacha20.h>

#include "external/chacha20.c"

typedef struct OQS_RAND_urandom_chacha20_ctx {
	uint8_t key[32];
	uint32_t nonce[2];
	uint8_t cache[64];
	size_t cache_next_byte;
	uint32_t chacha20_input[16];
} OQS_RAND_urandom_chacha20_ctx;

static OQS_RAND_urandom_chacha20_ctx *OQS_RAND_urandom_chacha20_ctx_new();
static void OQS_RAND_urandom_chacha20_fill_cache(OQS_RAND *r);
static void OQS_RAND_urandom_chacha20_ctx_free(void *rand_ctx);

OQS_RAND *OQS_RAND_urandom_chacha20_new() {
	OQS_RAND *r = malloc(sizeof(OQS_RAND));
	if (r == NULL) {
		return NULL;
	}
	r->method_name = strdup("urandom_chacha20");
	r->ctx = OQS_RAND_urandom_chacha20_ctx_new();
	if (r->ctx == NULL || r->method_name == NULL) {
		OQS_RAND_urandom_chacha20_free(r);
		return NULL;
	}
	r->estimated_classical_security = 256;
	r->estimated_quantum_security = 128; // Grover search
	r->rand_8 = &OQS_RAND_urandom_chacha20_8;
	r->rand_32 = &OQS_RAND_urandom_chacha20_32;
	r->rand_64 = &OQS_RAND_urandom_chacha20_64;
	r->rand_n = &OQS_RAND_urandom_chacha20_n;
	r->free = &OQS_RAND_urandom_chacha20_free;
	return r;
}

static OQS_RAND_urandom_chacha20_ctx *OQS_RAND_urandom_chacha20_ctx_new() {
#if defined(WINDOWS)
	HCRYPTPROV   hCryptProv;
#else
	int fd = 0;
#endif
	OQS_RAND_urandom_chacha20_ctx *rand_ctx = NULL;
	rand_ctx = (OQS_RAND_urandom_chacha20_ctx *) malloc(sizeof(OQS_RAND_urandom_chacha20_ctx));
	if (rand_ctx == NULL) {
		goto err;
	}
#if defined(WINDOWS)
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
	        !CryptGenRandom(hCryptProv, 32, rand_ctx->key)) {
		goto err;
	}
#else
	fd = open("/dev/urandom", O_RDONLY);
	if (fd == 0) {
		goto err;
	}
	int r = read(fd, rand_ctx->key, 32);
	if (r != 32) {
		goto err;
	}
#endif
	memset(rand_ctx->nonce, 0, 8);
	rand_ctx->cache_next_byte = 64; // cache is empty
	ECRYPT_keysetup(rand_ctx->chacha20_input, rand_ctx->key);
	goto okay;
err:
	if (rand_ctx) {
		free(rand_ctx);
	}
#if defined(WINDOWS)
#else
	if (fd) {
		close(fd);
	}
#endif
	return NULL;
okay:
#if defined(WINDOWS)
#else
	close(fd);
#endif
	return rand_ctx;
}

static void OQS_RAND_urandom_chacha20_fill_cache(OQS_RAND *r) {
	OQS_RAND_urandom_chacha20_ctx *rand_ctx = (OQS_RAND_urandom_chacha20_ctx *) r->ctx;
	r->rand_n(r, rand_ctx->cache, 64);
	rand_ctx->cache_next_byte = 0;
}

uint8_t OQS_RAND_urandom_chacha20_8(OQS_RAND *r) {
	OQS_RAND_urandom_chacha20_ctx *rand_ctx = (OQS_RAND_urandom_chacha20_ctx *) r->ctx;
	if (rand_ctx->cache_next_byte > 64 - 1) {
		OQS_RAND_urandom_chacha20_fill_cache(r);
	}
	uint8_t out = rand_ctx->cache[rand_ctx->cache_next_byte];
	rand_ctx->cache_next_byte += 1;
	return out;
}

uint32_t OQS_RAND_urandom_chacha20_32(OQS_RAND *r) {
	OQS_RAND_urandom_chacha20_ctx *rand_ctx = (OQS_RAND_urandom_chacha20_ctx *) r->ctx;
	if (rand_ctx->cache_next_byte > 64 - 4) {
		OQS_RAND_urandom_chacha20_fill_cache(r);
	}
	uint32_t out;
	memcpy(&out, &rand_ctx->cache[rand_ctx->cache_next_byte], 4);
	rand_ctx->cache_next_byte += 4;
	return out;
}

uint64_t OQS_RAND_urandom_chacha20_64(OQS_RAND *r) {
	OQS_RAND_urandom_chacha20_ctx *rand_ctx = (OQS_RAND_urandom_chacha20_ctx *) r->ctx;
	if (rand_ctx->cache_next_byte > 64 - 8) {
		OQS_RAND_urandom_chacha20_fill_cache(r);
	}
	uint64_t out;
	memcpy(&out, &rand_ctx->cache[rand_ctx->cache_next_byte], 8);
	rand_ctx->cache_next_byte += 8;
	return out;
}

void OQS_RAND_urandom_chacha20_n(OQS_RAND *r, uint8_t *out, size_t n) {
	OQS_RAND_urandom_chacha20_ctx *rand_ctx = (OQS_RAND_urandom_chacha20_ctx *) r->ctx;
	rand_ctx->nonce[0]++;
	if (rand_ctx->nonce[0] == 0) {
		rand_ctx->nonce[1]++;
	}
	ECRYPT_ivsetup(rand_ctx->chacha20_input, (u8 *) rand_ctx->nonce);
	ECRYPT_keystream_bytes(rand_ctx->chacha20_input, out, n);
}

static void OQS_RAND_urandom_chacha20_ctx_free(void *rand_ctx) {
	free(rand_ctx);
}

void OQS_RAND_urandom_chacha20_free(OQS_RAND *r) {
	if (r) {
		OQS_RAND_urandom_chacha20_ctx_free(r->ctx);
	}
	if (r) {
		free(r->method_name);
	}
	free(r);
}
