#ifndef ASCON_H
#define ASCON_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ASCON-AEAD128 constants */
#define ASCON_AEAD128_KEY_LEN 16      /* 128-bit key */
#define ASCON_AEAD_NONCE_LEN 16       /* 128-bit nonce */
#define ASCON_AEAD_TAG_MIN_SECURE_LEN 16  /* 128-bit tag */

/* ASCON AEAD context structure */
typedef struct {
    uint64_t state[5];
    uint64_t key[2];
    size_t offset;
    uint64_t flags;
} ascon_aead128_ctx;

/* Provider-compatible typedef */
typedef ascon_aead128_ctx ascon_aead_ctx_t;

#ifndef OPENSSL_BUILDING_OPENSSL
void ascon_test_state();
#endif

/* Provider API functions */
void ascon_aead128_init(ascon_aead_ctx_t* ctx, const uint8_t key[ASCON_AEAD128_KEY_LEN], const uint8_t nonce[ASCON_AEAD_NONCE_LEN]);
void ascon_aead128_assoc_data_update(ascon_aead_ctx_t* ctx, const uint8_t* assoc_data, size_t assoc_data_len);
size_t ascon_aead128_encrypt_update(ascon_aead_ctx_t* ctx, uint8_t* ciphertext, const uint8_t* plaintext, size_t plaintext_len);
size_t ascon_aead128_encrypt_final(ascon_aead_ctx_t* ctx, uint8_t* ciphertext, uint8_t* tag, size_t tag_len);
size_t ascon_aead128_decrypt_update(ascon_aead_ctx_t* ctx, uint8_t* plaintext, const uint8_t* ciphertext, size_t ciphertext_len);
size_t ascon_aead128_decrypt_final(ascon_aead_ctx_t* ctx, uint8_t* plaintext, bool* is_tag_valid, const uint8_t* expected_tag, size_t expected_tag_len);
void ascon_aead_cleanup(ascon_aead_ctx_t* ctx);
#endif /* ASCON_H */
