#include <assert.h>

#include "aes.h"

void OQS_AES128_load_schedule(const uint8_t *key, uint8_t *schedule) {
#ifndef AES_DISABLE_NI
	OQS_AES128_load_schedule_ni(key, schedule);
#else
	OQS_AES128_load_schedule_c(key, schedule);
#endif
}
void OQS_AES128_enc(const uint8_t *plaintext, const uint8_t *schedule, uint8_t *ciphertext) {
#ifndef AES_DISABLE_NI
	OQS_AES128_enc_ni(plaintext, schedule, ciphertext);
#else
	OQS_AES128_enc_c(plaintext, schedule, ciphertext);
#endif
}

void OQS_AES128_dec(const uint8_t *ciphertext, const uint8_t *schedule, uint8_t *plaintext) {
#ifndef AES_DISABLE_NI
	OQS_AES128_dec_ni(ciphertext, schedule, plaintext);
#else
	OQS_AES128_dec_c(ciphertext, schedule, plaintext);
#endif
}

void OQS_AES128_ECB_enc(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
	uint8_t schedule[OQS_AES128_SCHEDULE_NUMBYTES];
	OQS_AES128_load_schedule(key, schedule);
	assert(plaintext_len % 16 == 0);
	for (size_t block = 0; block < plaintext_len / 16; block++) {
		OQS_AES128_enc(plaintext + (16 * block), schedule, ciphertext + (16 * block));
	}
}

void OQS_AES128_ECB_enc_sch(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *schedule, uint8_t *ciphertext) {
	assert(plaintext_len % 16 == 0);
	for (size_t block = 0; block < plaintext_len / 16; block++) {
		OQS_AES128_enc(plaintext + (16 * block), schedule, ciphertext + (16 * block));
	}
}

void OQS_AES128_ECB_dec(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext) {
	uint8_t schedule[OQS_AES128_SCHEDULE_NUMBYTES];
	OQS_AES128_load_schedule(key, schedule);
	assert(ciphertext_len % 16 == 0);
	for (size_t block = 0; block < ciphertext_len / 16; block++) {
		OQS_AES128_dec(ciphertext + (16 * block), schedule, plaintext + (16 * block));
	}
}
