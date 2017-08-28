#include <assert.h>

#include "aes.h"
#include "aes_local.h"

void OQS_AES128_load_schedule(const uint8_t *key, void **schedule, int for_encryption) {
#ifdef USE_OPENSSL
	oqs_aes128_load_schedule_ossl(key, schedule, for_encryption);
#else
	for_encryption++; // need some dummy operation to avoid unused parameter warning
#ifdef AES_ENABLE_NI
	oqs_aes128_load_schedule_ni(key, schedule);
#else
	oqs_aes128_load_schedule_c(key, schedule);
#endif
#endif
}

void OQS_AES128_free_schedule(void *schedule) {
#ifdef USE_OPENSSL
	oqs_aes128_free_schedule_ossl(schedule);
#else
#ifdef AES_ENABLE_NI
	oqs_aes128_free_schedule_ni(schedule);
#else
	oqs_aes128_free_schedule_c(schedule);
#endif
#endif
}

void OQS_AES128_ECB_enc(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
#ifdef USE_OPENSSL
	oqs_aes128_ecb_enc_ossl(plaintext, plaintext_len, key, ciphertext);
#else
#ifdef AES_ENABLE_NI
	oqs_aes128_ecb_enc_ni(plaintext, plaintext_len, key, ciphertext);
#else
	oqs_aes128_ecb_enc_c(plaintext, plaintext_len, key, ciphertext);
#endif
#endif
}

void OQS_AES128_ECB_dec(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext) {
#ifdef USE_OPENSSL
	oqs_aes128_ecb_dec_ossl(ciphertext, ciphertext_len, key, plaintext);
#else
#ifdef AES_ENABLE_NI
	oqs_aes128_ecb_dec_ni(ciphertext, ciphertext_len, key, plaintext);
#else
	oqs_aes128_ecb_dec_c(ciphertext, ciphertext_len, key, plaintext);
#endif
#endif
}

void OQS_AES128_ECB_enc_sch(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext) {
#ifdef USE_OPENSSL
	oqs_aes128_ecb_enc_sch_ossl(plaintext, plaintext_len, schedule, ciphertext);
#else
#ifdef AES_ENABLE_NI
	oqs_aes128_ecb_enc_sch_ni(plaintext, plaintext_len, schedule, ciphertext);
#else
	oqs_aes128_ecb_enc_sch_c(plaintext, plaintext_len, schedule, ciphertext);
#endif
#endif
}

void OQS_AES128_ECB_dec_sch(const uint8_t *ciphertext, const size_t ciphertext_len, const void *schedule, uint8_t *plaintext) {
#ifdef USE_OPENSSL
	oqs_aes128_ecb_dec_sch_ossl(ciphertext, ciphertext_len, schedule, plaintext);
#else
#ifdef AES_ENABLE_NI
	oqs_aes128_ecb_dec_sch_ni(ciphertext, ciphertext_len, schedule, plaintext);
#else
	oqs_aes128_ecb_dec_sch_c(ciphertext, ciphertext_len, schedule, plaintext);
#endif
#endif
}

#ifdef AES_ENABLE_NI
inline void oqs_aes128_ecb_enc_ni(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
	void *schedule = NULL;
	oqs_aes128_load_schedule_ni(key, &schedule);
	oqs_aes128_ecb_enc_sch_ni(plaintext, plaintext_len, schedule, ciphertext);
	oqs_aes128_free_schedule_ni(schedule);
}
#endif

inline void oqs_aes128_ecb_enc_c(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
	void *schedule = NULL;
	oqs_aes128_load_schedule_c(key, &schedule);
	oqs_aes128_ecb_enc_sch_c(plaintext, plaintext_len, schedule, ciphertext);
	oqs_aes128_free_schedule_c(schedule);
}

#ifdef AES_ENABLE_NI
inline void oqs_aes128_ecb_enc_sch_ni(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext) {
	assert(plaintext_len % 16 == 0);
	for (size_t block = 0; block < plaintext_len / 16; block++) {
		oqs_aes128_enc_ni(plaintext + (16 * block), schedule, ciphertext + (16 * block));
	}
}
#endif

inline void oqs_aes128_ecb_enc_sch_c(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext) {
	assert(plaintext_len % 16 == 0);
	for (size_t block = 0; block < plaintext_len / 16; block++) {
		oqs_aes128_enc_c(plaintext + (16 * block), schedule, ciphertext + (16 * block));
	}
}

#ifdef AES_ENABLE_NI
inline void oqs_aes128_ecb_dec_ni(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext) {
	void *schedule = NULL;
	oqs_aes128_load_schedule_ni(key, &schedule);
	oqs_aes128_ecb_dec_sch_ni(ciphertext, ciphertext_len, schedule, plaintext);
	oqs_aes128_free_schedule_ni(schedule);
}
#endif

inline void oqs_aes128_ecb_dec_c(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext) {
	void *schedule = NULL;
	oqs_aes128_load_schedule_c(key, &schedule);
	oqs_aes128_ecb_dec_sch_c(ciphertext, ciphertext_len, schedule, plaintext);
	oqs_aes128_free_schedule_c(schedule);
}

#ifdef AES_ENABLE_NI
inline void oqs_aes128_ecb_dec_sch_ni(const uint8_t *ciphertext, const size_t ciphertext_len, const void *schedule, uint8_t *plaintext) {
	assert(ciphertext_len % 16 == 0);
	for (size_t block = 0; block < ciphertext_len / 16; block++) {
		oqs_aes128_dec_ni(ciphertext + (16 * block), schedule, plaintext + (16 * block));
	}
}
#endif

inline void oqs_aes128_ecb_dec_sch_c(const uint8_t *ciphertext, const size_t ciphertext_len, const void *schedule, uint8_t *plaintext) {
	assert(ciphertext_len % 16 == 0);
	for (size_t block = 0; block < ciphertext_len / 16; block++) {
		oqs_aes128_dec_c(ciphertext + (16 * block), schedule, plaintext + (16 * block));
	}
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>

inline void oqs_aes128_load_schedule_ossl(const uint8_t *key, void **schedule, int for_encryption) {
	EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
	assert(aes_ctx != NULL);
	if (for_encryption) {
		assert(1 == EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), NULL, key, NULL));
	} else {
		assert(1 == EVP_DecryptInit_ex(aes_ctx, EVP_aes_128_ecb(), NULL, key, NULL));
	}
	EVP_CIPHER_CTX_set_padding(aes_ctx, 0);
	*schedule = aes_ctx;
}

inline void oqs_aes128_free_schedule_ossl(void *schedule) {
	if (schedule != NULL) {
		EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *) schedule);
	}
}

inline void oqs_aes128_ecb_enc_ossl(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
	void *schedule = NULL;
	oqs_aes128_load_schedule_ossl(key, &schedule, 1);
	oqs_aes128_ecb_enc_sch_ossl(plaintext, plaintext_len, schedule, ciphertext);
	oqs_aes128_free_schedule_ossl(schedule);
}

inline void oqs_aes128_ecb_dec_ossl(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext) {
	void *schedule = NULL;
	oqs_aes128_load_schedule_ossl(key, &schedule, 0);
	oqs_aes128_ecb_dec_sch_ossl(ciphertext, ciphertext_len, schedule, plaintext);
	oqs_aes128_free_schedule_ossl(schedule);
}

inline void oqs_aes128_ecb_enc_sch_ossl(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext) {
	assert(plaintext_len % 16 == 0);
	int outlen;
	assert(1 == EVP_EncryptUpdate((EVP_CIPHER_CTX *) schedule, ciphertext, &outlen, plaintext, plaintext_len));
	assert((size_t) outlen == plaintext_len);
	assert(1 == EVP_EncryptFinal_ex((EVP_CIPHER_CTX *) schedule, ciphertext, &outlen));
}

inline void oqs_aes128_ecb_dec_sch_ossl(const uint8_t *ciphertext, const size_t ciphertext_len, const void *schedule, uint8_t *plaintext) {
	assert(ciphertext_len % 16 == 0);
	int outlen;
	assert(1 == EVP_DecryptUpdate((EVP_CIPHER_CTX *) schedule, plaintext, &outlen, ciphertext, ciphertext_len));
	assert((size_t) outlen == ciphertext_len);
	assert(1 == EVP_DecryptFinal_ex((EVP_CIPHER_CTX *) schedule, plaintext, &outlen));
}

#endif
