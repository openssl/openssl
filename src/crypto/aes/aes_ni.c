#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <oqs/common.h>

#ifndef AES_ENABLE_NI
#include <assert.h>
void oqs_aes128_load_schedule_ni(UNUSED const uint8_t *key, UNUSED void **_schedule) {
	assert(0);
}
void oqs_aes128_free_schedule_ni(UNUSED void *_schedule) {
	assert(0);
}
void oqs_aes128_enc_ni(UNUSED const uint8_t *plaintext, UNUSED const void *_schedule, UNUSED uint8_t *ciphertext) {
	assert(0);
}
void oqs_aes128_dec_ni(UNUSED const uint8_t *ciphertext, UNUSED const void *_schedule, UNUSED uint8_t *plaintext) {
	assert(0);
}
#else

#include <wmmintrin.h>

static __m128i key_expand(__m128i key, __m128i keygened) {
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	// The last 4 bytes from aeskeygenassist store the values we want so
	// and they need to be xored all four sets of bytes in the result so
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	return _mm_xor_si128(key, keygened);
}

//This is needed since the rcon argument to _mm_aeskeygenassist_si128
//must be a compile time constaint

#define key_exp(k, rcon) key_expand(k, _mm_aeskeygenassist_si128(k, rcon))

void oqs_aes128_load_schedule_ni(const uint8_t *key, void **_schedule) {
	*_schedule = malloc(20 * 16);
	assert(*_schedule != NULL);
	__m128i *schedule = (__m128i *) *_schedule;
	schedule[0] = _mm_loadu_si128((const __m128i *) key);
	schedule[1] = key_exp(schedule[0], 0x01);
	schedule[2] = key_exp(schedule[1], 0x02);
	schedule[3] = key_exp(schedule[2], 0x04);
	schedule[4] = key_exp(schedule[3], 0x08);
	schedule[5] = key_exp(schedule[4], 0x10);
	schedule[6] = key_exp(schedule[5], 0x20);
	schedule[7] = key_exp(schedule[6], 0x40);
	schedule[8] = key_exp(schedule[7], 0x80);
	schedule[9] = key_exp(schedule[8], 0x1b);
	schedule[10] = key_exp(schedule[9], 0x36);
	// generate decryption keys in reverse order.
	// schedule[10] is shared by last encryption and first decryption rounds
	// schedule[0] is shared by first encryption round and last decryption round
	for (size_t i = 0; i < 9; i++) {
		schedule[11 + i] = _mm_aesimc_si128(schedule[9 - i]);
	}
}

void oqs_aes128_free_schedule_ni(void *schedule) {
	if (schedule != NULL) {
		free(schedule);
	}
}

void oqs_aes128_enc_ni(const uint8_t *plaintext, const void *_schedule, uint8_t *ciphertext) {
	__m128i *schedule = (__m128i *) _schedule;
	__m128i m = _mm_loadu_si128((__m128i *) plaintext);

	m = _mm_xor_si128(m, schedule[0]);
	for (size_t i = 1; i < 10; i++) {
		m = _mm_aesenc_si128(m, schedule[i]);
	}
	m = _mm_aesenclast_si128(m, schedule[10]);

	_mm_storeu_si128((__m128i *) ciphertext, m);
}

void oqs_aes128_dec_ni(const uint8_t *ciphertext, const void *_schedule, uint8_t *plaintext) {
	__m128i *schedule = (__m128i *) _schedule;
	__m128i m = _mm_loadu_si128((__m128i *) ciphertext);

	m = _mm_xor_si128(m, schedule[10]);
	for (size_t i = 1; i < 10; i++) {
		m = _mm_aesdec_si128(m, schedule[10 + i]);
	}
	m = _mm_aesdeclast_si128(m, schedule[0]);

	_mm_storeu_si128((__m128i *) plaintext, m);
}

#endif
