/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Implementation of buffering used for the Init-Update-Final paradigm
 * of both the AEAD ciphers and hashing.
 *
 * This file is based on LibAscon (CC0 1.0 license).
 * Original authors: see LibAscon AUTHORS.md file
 */

# include <stdint.h>
# include <stddef.h>
# include "crypto/ascon.h"
# include "ascon_internal.h"

/**
 * @internal
 * Simplistic clone of memcpy for small arrays.
 *
 * It should work faster than memcpy for very small amounts of bytes given
 * the reduced overhead.
 *
 * Initially implemented with a while-loop, but it triggers a
 * `-Werror=stringop-overflow=` warning in GCC v11. Replaced it with a for-loop
 * that does the exact same thing instead to make it work without deactivating
 * the warning. We instead let the optimiser figure out the best way to make it
 * as fast as possible.
 */
inline static void
small_cpy(uint8_t* const dst, const uint8_t* const src, const size_t amount)
{
    for (uint_fast8_t i = 0U; i < amount; i++)
    {
        dst[i] = src[i];
    }
}

ASCON_INLINE uint64_t
bigendian_decode_u64(const uint8_t* const bytes)
{
    uint64_t value = 0;
    value |= ((uint64_t) bytes[0]) << 56U;
    value |= ((uint64_t) bytes[1]) << 48U;
    value |= ((uint64_t) bytes[2]) << 40U;
    value |= ((uint64_t) bytes[3]) << 32U;
    value |= ((uint64_t) bytes[4]) << 24U;
    value |= ((uint64_t) bytes[5]) << 16U;
    value |= ((uint64_t) bytes[6]) << 8U;
    value |= ((uint64_t) bytes[7]);
    return value;
}

ASCON_INLINE void
bigendian_encode_u64(uint8_t* const bytes, const uint64_t value)
{
    bytes[0] = (uint8_t) (value >> 56U);
    bytes[1] = (uint8_t) (value >> 48U);
    bytes[2] = (uint8_t) (value >> 40U);
    bytes[3] = (uint8_t) (value >> 32U);
    bytes[4] = (uint8_t) (value >> 24U);
    bytes[5] = (uint8_t) (value >> 16U);
    bytes[6] = (uint8_t) (value >> 8U);
    bytes[7] = (uint8_t) (value);
}

ASCON_INLINE uint64_t
bigendian_decode_varlen(const uint8_t* const bytes, const uint_fast8_t n)
{
    uint64_t x = 0;
    /* Unsigned int should be the fastest unsigned on the machine.
     * Using it to avoid warnings about <<-operator with signed value. */
    for (unsigned int i = 0; i < n; i++)
    {
        x |= ((uint64_t) bytes[i]) << (56U - 8U * i);
    }
    return x;
}

ASCON_INLINE void
bigendian_encode_varlen(uint8_t* const bytes, const uint64_t x, const uint_fast8_t n)
{
    /* Unsigned int should be the fastest unsigned on the machine.
     * Using it to avoid warnings about <<-operator with signed value. */
    for (unsigned int i = 0; i < n; i++)
    {
        bytes[i] = (uint8_t) (x >> (56U - 8U * i));
    }
}

uint64_t
mask_most_signif_bytes(uint_fast8_t n)
{
    uint64_t x = 0;
    /* Unsigned int should be the fastest unsigned on the machine.
     * Using it to avoid warnings about <<-operator with signed value. */
    for (unsigned int i = 0; i < n; i++)
    {
        x |= 0xFFULL << (56U - 8U * i);
    }
    return x;
}

size_t
buffered_accumulation(ascon_bufstate_t* const ctx,
                      uint8_t* data_out,
                      const uint8_t* data_in,
                      absorb_fptr absorb,
                      size_t data_in_len,
                      const uint8_t rate)
{
    size_t fresh_out_bytes = 0;
    if (ctx->buffer_len > 0)
    {
        /* There is data in the buffer already.
         * Place as much as possible of the new data into the buffer. */
        const uint_fast8_t space_in_buf = (uint_fast8_t) (rate - ctx->buffer_len);
        const uint_fast8_t into_buffer = (uint_fast8_t) MIN(space_in_buf, data_in_len);
        small_cpy(&ctx->buffer[ctx->buffer_len], data_in, into_buffer);
        ctx->buffer_len = (uint8_t) (ctx->buffer_len + into_buffer);
        data_in += into_buffer;
        data_in_len -= into_buffer;
        if (ctx->buffer_len == rate)
        {
            /* The buffer was filled completely, thus absorb it. */
            absorb(&ctx->sponge, data_out, ctx->buffer);
            ctx->buffer_len = 0;
            data_out += rate;
            fresh_out_bytes += rate;
        }
        else
        {
            /* Do nothing.
             * The buffer contains some data, but it's not full yet
             * and there is no more data in this update call.
             * Keep it cached for the next update call or the digest call. */
        }
    }
    else
    {
        /* Do nothing.
         * The buffer contains no data, because this is the first update call
         * or because the last update had no less-than-a-block trailing data. */
    }
    /* Absorb remaining data (if any) one block at the time. */
    while (data_in_len >= rate)
    {
        absorb(&ctx->sponge, data_out, data_in);
        data_out += rate;
        data_in += rate;
        data_in_len -= rate;
        fresh_out_bytes += rate;
    }
    /* If there is any remaining less-than-a-block data to be absorbed,
     * cache it into the buffer for the next update call or digest call. */
    if (data_in_len > 0)
    {
        small_cpy(ctx->buffer, data_in, data_in_len);
        ctx->buffer_len = (uint8_t) data_in_len;
    }
    return fresh_out_bytes;
}

