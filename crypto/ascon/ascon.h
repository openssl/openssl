/*********************************************************************
 *
 *  Temporary stub for build testing
 *  This is a placeholder for a cleanroom implementation of the ASCON algorithm
 *
 *****/
#ifndef ASCON_H
#define ASCON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define ASCON_AEAD128_KEY_LEN 16
#define ASCON_AEAD_NONCE_LEN 16
#define ASCON_AEAD_TAG_MIN_SECURE_LEN 16

/* Internal constants */
#define ASCON_RATE 8
#define ASCON_DOUBLE_RATE 16

/* Macros */
#define ASCON_API
#define ASCON_ASSERT(x) assert(x)

/**
 * @internal
 * States used to understand which function of the API was called before
 * for the input assertions and to known if the associated data has been
 * updated or not.
 */
typedef enum ascon_flow_e
{
    ASCON_FLOW_CLEANED = 0,
    ASCON_FLOW_HASH_INITIALISED,
    ASCON_FLOW_HASH_UPDATED,
    ASCON_FLOW_AEAD128_80pq_INITIALISED,
    ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED,
    ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED,
    ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED,
    ASCON_FLOW_AEAD128a_INITIALISED,
    ASCON_FLOW_AEAD128a_ASSOC_DATA_UPDATED,
    ASCON_FLOW_AEAD128a_ENCRYPT_UPDATED,
    ASCON_FLOW_AEAD128a_DECRYPT_UPDATED,
    ASCON_FLOW_HASHA_INITIALISED,
    ASCON_FLOW_HASHA_UPDATED,
} ascon_flow_t;

/* Sponge state structure */
typedef struct ascon_sponge_st {
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
} ascon_sponge_t;

/* Buffer state structure */
typedef struct ascon_bufstate_st {
    ascon_sponge_t sponge;
    uint8_t buffer[ASCON_DOUBLE_RATE];
    uint8_t buffer_len;
    ascon_flow_t flow_state;
    /** Unused padding to the next uint64_t (sponge.x0 or ctx.k0)
     * to avoid errors when compiling with `-Wpadding` on any platform. */
    uint8_t pad[6];
} ascon_bufstate_t;

/* AEAD context structure */
typedef struct ascon_aead_ctx_st {
    /** Cipher buffered sponge state. */
    ascon_bufstate_t bufstate;
    /** Copy of the secret key, to be used in the final step, first part. */
    uint64_t k0;
    /** Copy of the secret key, to be used in the final step, second part. */
    uint64_t k1;
    /** Copy of the secret key, to be used in the final step, third part,
     * used only in the Ascon80pq cipher. */
    uint64_t k2;
} ascon_aead_ctx_t;

void ascon_aead128_init(ascon_aead_ctx_t *ctx, const uint8_t key[ASCON_AEAD128_KEY_LEN], const uint8_t nonce[ASCON_AEAD_NONCE_LEN]);
size_t ascon_aead128_encrypt_update(ascon_aead_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t inlen);
size_t ascon_aead128_decrypt_update(ascon_aead_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t inlen);
size_t ascon_aead128_encrypt_final(ascon_aead_ctx_t *ctx, uint8_t *out, uint8_t *tag, size_t taglen);
size_t ascon_aead128_decrypt_final(ascon_aead_ctx_t *ctx, uint8_t *out, bool *is_valid, const uint8_t *tag, size_t taglen);
void ascon_aead128_assoc_data_update(ascon_aead_ctx_t *ctx, const uint8_t *aad, size_t aadlen);
void ascon_aead_cleanup(ascon_aead_ctx_t *ctx);

#endif