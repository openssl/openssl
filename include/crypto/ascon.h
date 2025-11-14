#ifndef ASCON_H
#define ASCON_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t state[5];
    uint64_t key[2];
    size_t offset;
    uint64_t flags;
} ascon_aead128_ctx;

#ifndef OPENSSL_BUILDING_OPENSSL
void ascon_test_state();
#endif
size_t ascon_aead128_init(ascon_aead128_ctx* ctx, const unsigned char* k, const unsigned char* n);
size_t ascon_aead128_encrypt_update(ascon_aead128_ctx* ctx, unsigned char* ct, const unsigned char* pt, size_t len);
size_t ascon_aead128_encrypt_final(ascon_aead128_ctx* ctx, unsigned char* tag);
size_t ascon_aead128_decrypt_final(ascon_aead128_ctx* ctx, unsigned char* out, int* is_valid, const unsigned char* expected_tag, size_t expected_tag_len);
size_t ascon_aead128_aad_update(ascon_aead128_ctx* ctx, const unsigned char* in, size_t len);
size_t ascon_aead128_decrypt_update(ascon_aead128_ctx* ctx, unsigned char* pt, const unsigned char* ct, size_t len);
#endif /* ASCON_H */
