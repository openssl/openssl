/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of the Apache Public License 2.0.
 * The terms of this licenses can be found at:
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of the license along with this
 * software. If not, it may be obtained at the above URL.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <prov/blake2.h>

#include "internal/argon2.h"
#include "core.h"

typedef struct argon2_param ARGON2_PARAM;

int ossl_alloc(uint8_t **memory, size_t bytes)
{
    if (memory == NULL)
        return -1;

    *memory = OPENSSL_zalloc(bytes);

    return memory != NULL;
}

void ossl_dealloc(uint8_t *memory, size_t bytes)
{
    if (bytes)
        OPENSSL_clear_free(memory, bytes);
    else
        OPENSSL_free(memory);
}

int ARGON2_Init(ARGON2_CTX *c, argon2_type type)
{
    memset(c, 0, sizeof(*c));

    c->outlen = 64;
    c->t_cost = 3;
    c->m_cost = ARGON2_MIN_MEMORY;
    c->lanes = 1;
    c->threads = 1;
    c->flags = ARGON2_DEFAULT_FLAGS;
    c->version = ARGON2_VERSION_NUMBER;
    c->type = type;

    /* Use OpenSSL facilities to (de)alloc memory. */
    c->allocate_cbk = ossl_alloc;
    c->free_cbk = ossl_dealloc;

    /**
     * There is a caveat here; when using Blake2b message digest, the reference
     * implementation overwrites Blake2b's param (namely the digest_length
     * field) by calling Blake2b init as follows:
     *
     *      blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);
     *
     *      blake2b_init(blake2b_state *S, size_t outlen) {
     *      +0      blake2b_param P;
     *              ...
     *      +13     P.digest_length = (uint8_t)outlen;
     *              ...
     *      }
     *
     * OpenSSL-provided Blake2b's init works pretty much the same way, with
     * one important distinction -- cannot specify outlen when using a message
     * digest; as the two values are equal, it seemed pointless to add this
     * value into the context. Note that it would have been possible to pass
     * this value via the custom ctrl calls that Blake2b MAC has. But then
     * again, in such a case a key is required -- this makes it a moot point
     * as Argon2 doesn't supply the key at all times.
     *
     * Therefore, it seem'd reasonable to not alter Blake2b's code for this
     * one change as these constants are equal are not likely to change.
     */
    if (ARGON2_PREHASH_DIGEST_LENGTH != BLAKE2B_DIGEST_LENGTH)
        return -1;

    return 1;
}

int ARGON2_Update(ARGON2_CTX *context, uint8_t *data, size_t datalen)
{
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;
    enum Argon2_ErrorCodes result;

    if (datalen > UINT32_MAX)
        return 0;

    if (data) {
        context->pwd = data;
        context->pwdlen = (uint32_t) datalen;
    }

    context->out = OPENSSL_zalloc(context->outlen+1);
    if (context->out == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /* 1. Validate all inputs */
    result = validate_inputs(context);

    if (ARGON2_OK != result) {
        return result;
    }

    if (Argon2_d != context->type && Argon2_i != context->type &&
        Argon2_id != context->type) {
        return ARGON2_INCORRECT_TYPE;
    }

    /* 2. Align memory size */
    /* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    /* Ensure that all segments have equal length */
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = context->type;

    if (instance.threads > instance.lanes) {
        instance.threads = instance.lanes;
    }

    /* 3. Initialization: Hashing inputs, allocating memory, filling first
     * blocks. */
    result = initialize(&instance, context);

    if (ARGON2_OK != result) {
        return 0;
    }

    /* 4. Filling memory */
    result = fill_memory_blocks(&instance);

    if (ARGON2_OK != result) {
        return 0;
    }

    /* 5. Finalization */
    finalize(context, &instance);

    return 1;
}

int ARGON2_Final(uint8_t *md, ARGON2_CTX *c)
{
    if (md == NULL || c == NULL) {
        return ARGON2_OUTPUT_PTR_NULL;
    }
    memcpy(md, c->out, c->outlen);
    return 1;
}
