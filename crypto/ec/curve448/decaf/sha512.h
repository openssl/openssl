/**
 * @file decaf/shake.h
 * @copyright Public domain.
 * @author Mike Hamburg
 * @brief SHA2-512
 */

#ifndef __DECAF_SHA512_H__
#define __DECAF_SHA512_H__

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h> /* for NULL */

#include <decaf/common.h>

#ifdef __cplusplus
extern "C" {
#endif
    

typedef struct decaf_sha512_ctx_s {
    uint64_t state[8];
    uint8_t block[128];
    uint64_t bytes_processed;
} decaf_sha512_ctx_s, decaf_sha512_ctx_t[1];

void decaf_sha512_init(decaf_sha512_ctx_t ctx) DECAF_NONNULL DECAF_API_VIS;
void decaf_sha512_update(decaf_sha512_ctx_t ctx, const uint8_t *message, size_t length) DECAF_NONNULL DECAF_API_VIS;
void decaf_sha512_final(decaf_sha512_ctx_t ctx, uint8_t *out, size_t length) DECAF_NONNULL DECAF_API_VIS;

static inline void decaf_sha512_destroy(decaf_sha512_ctx_t ctx) {
    decaf_bzero(ctx,sizeof(*ctx));
}

static inline void decaf_sha512_hash(
    uint8_t *output,
    size_t output_len,
    const uint8_t *message,
    size_t message_len
) {
    decaf_sha512_ctx_t ctx;
    decaf_sha512_init(ctx);
    decaf_sha512_update(ctx,message,message_len);
    decaf_sha512_final(ctx,output,output_len);
    decaf_sha512_destroy(ctx);
}

#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __DECAF_SHA512_H__ */
