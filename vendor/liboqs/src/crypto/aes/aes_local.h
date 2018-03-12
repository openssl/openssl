/**
 * \file aes_local.h
 * \brief Header defining additional internal functions for OQS AES
 */

#ifndef __OQS_AES_LOCAL_H
#define __OQS_AES_LOCAL_H

#include <stdint.h>
#include <stdlib.h>

void oqs_aes128_load_schedule_ni(const uint8_t *key, void **schedule);
void oqs_aes128_free_schedule_ni(void *schedule);
void oqs_aes128_enc_ni(const uint8_t *plaintext, const void *schedule, uint8_t *ciphertext);
void oqs_aes128_dec_ni(const uint8_t *ciphertext, const void *schedule, uint8_t *plaintext);
void oqs_aes128_ecb_enc_ni(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
void oqs_aes128_ecb_dec_ni(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext);
void oqs_aes128_ecb_enc_sch_ni(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);
void oqs_aes128_ecb_dec_sch_ni(const uint8_t *ciphertext, const size_t ciphertext_len, const void *schedule, uint8_t *plaintext);

void oqs_aes128_load_schedule_c(const uint8_t *key, void **schedule);
void oqs_aes128_free_schedule_c(void *schedule);
void oqs_aes128_enc_c(const uint8_t *plaintext, const void *schedule, uint8_t *ciphertext);
void oqs_aes128_dec_c(const uint8_t *ciphertext, const void *schedule, uint8_t *plaintext);
void oqs_aes128_ecb_enc_c(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
void oqs_aes128_ecb_dec_c(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext);
void oqs_aes128_ecb_enc_sch_c(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);
void oqs_aes128_ecb_dec_sch_c(const uint8_t *ciphertext, const size_t ciphertext_len, const void *schedule, uint8_t *plaintext);

#ifdef USE_OPENSSL
void oqs_aes128_load_schedule_ossl(const uint8_t *key, void **schedule, int for_encryption);
void oqs_aes128_free_schedule_ossl(void *schedule);
void oqs_aes128_ecb_enc_ossl(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
void oqs_aes128_ecb_dec_ossl(const uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext);
void oqs_aes128_ecb_enc_sch_ossl(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);
void oqs_aes128_ecb_dec_sch_ossl(const uint8_t *ciphertext, const size_t ciphertext_len, const void *schedule, uint8_t *plaintext);
#endif

#endif
