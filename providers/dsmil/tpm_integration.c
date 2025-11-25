/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * TPM Integration Layer Implementation
 *
 * This module bridges the existing TPM2 implementation with the DSMIL
 * policy provider, providing hardware-backed cryptography for all profiles.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "tpm_integration.h"
#include "policy.h"
#include "events.h"

/*
 * Initialize TPM integration
 */
int dsmil_tpm_init(DSMIL_TPM_CTX *ctx, const DSMIL_POLICY_CTX *policy_ctx)
{
    tpm2_rc_t rc;
    tpm2_security_level_t min_security;
    tpm2_acceleration_flags_t accel_flags;

    if (ctx == NULL)
        return 0;

    /* Clear context */
    memset(ctx, 0, sizeof(*ctx));

    /* Determine TPM requirements based on profile */
    if (policy_ctx != NULL) {
        DSMIL_PROFILE profile = policy_ctx->profile;

        ctx->config.enabled = 1;  /* Enable by default */
        ctx->config.require_tpm_keys = dsmil_tpm_is_required_for_profile(profile);
        min_security = dsmil_tpm_get_min_security_for_profile(profile);
        accel_flags = dsmil_tpm_get_accel_flags_for_profile(profile);

        /* Profile-specific settings */
        switch (profile) {
        case DSMIL_PROFILE_WORLD_COMPAT:
            ctx->config.seal_session_keys = 0;  /* Optional */
            ctx->config.use_tpm_rng = 0;        /* Use software RNG */
            break;

        case DSMIL_PROFILE_DSMIL_SECURE:
            ctx->config.seal_session_keys = 1;  /* Seal long-term keys */
            ctx->config.use_tpm_rng = 1;        /* Prefer TPM RNG */
            break;

        case DSMIL_PROFILE_ATOMAL:
            ctx->config.seal_session_keys = 1;  /* Seal all keys */
            ctx->config.use_tpm_rng = 1;        /* Mandatory TPM RNG */
            ctx->config.require_tpm_keys = 1;   /* Mandatory TPM */
            break;

        default:
            ctx->config.enabled = 0;
            break;
        }

        ctx->config.min_security = min_security;
        ctx->config.accel_flags = accel_flags;
    } else {
        /* Default configuration */
        ctx->config.enabled = 1;
        ctx->config.require_tpm_keys = 0;
        ctx->config.seal_session_keys = 0;
        ctx->config.use_tpm_rng = 0;
        ctx->config.min_security = TPM2_SECURITY_STANDARD;
        ctx->config.accel_flags = TPM2_ACCEL_ALL;
    }

    /* Initialize TPM2 subsystem */
    if (ctx->config.enabled) {
        rc = tpm2_crypto_init(ctx->config.accel_flags, ctx->config.min_security);
        if (rc == TPM2_RC_SUCCESS) {
            ctx->initialized = 1;
            fprintf(stderr, "DSMIL TPM: Initialized successfully (security level: %d)\n",
                    ctx->config.min_security);
            return 1;
        } else if (rc == TPM2_RC_NOT_SUPPORTED) {
            /* TPM not available - continue in software mode */
            fprintf(stderr, "DSMIL TPM: Hardware not available, using software fallback\n");
            ctx->initialized = 0;

            if (ctx->config.require_tpm_keys) {
                fprintf(stderr, "DSMIL TPM: ERROR - TPM required but not available\n");
                return 0;
            }
        } else {
            fprintf(stderr, "DSMIL TPM: Initialization failed (rc=%u)\n", rc);
            ctx->initialized = 0;

            if (ctx->config.require_tpm_keys) {
                return 0;
            }
        }
    }

    return 1;
}

/*
 * Cleanup TPM integration
 */
void dsmil_tpm_cleanup(DSMIL_TPM_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->initialized) {
        tpm2_crypto_cleanup();
        ctx->initialized = 0;
    }

    fprintf(stderr, "DSMIL TPM: Cleanup complete (ops: %u, failures: %u, fallbacks: %u)\n",
            ctx->tpm_operations, ctx->tpm_failures, ctx->software_fallbacks);

    memset(ctx, 0, sizeof(*ctx));
}

/*
 * Configure TPM for security profile
 */
int dsmil_tpm_configure_for_profile(DSMIL_TPM_CTX *ctx, DSMIL_PROFILE profile)
{
    if (ctx == NULL)
        return 0;

    /* Update configuration based on profile */
    ctx->config.require_tpm_keys = dsmil_tpm_is_required_for_profile(profile);
    ctx->config.min_security = dsmil_tpm_get_min_security_for_profile(profile);
    ctx->config.accel_flags = dsmil_tpm_get_accel_flags_for_profile(profile);

    return 1;
}

/*
 * Enable/disable TPM
 */
void dsmil_tpm_set_enabled(DSMIL_TPM_CTX *ctx, int enabled)
{
    if (ctx != NULL) {
        ctx->config.enabled = enabled;
    }
}

/*
 * Check TPM availability
 */
int dsmil_tpm_is_available(const DSMIL_TPM_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    return ctx->initialized && ctx->config.enabled;
}

/*
 * Seal key to TPM
 */
int dsmil_tpm_seal_key(DSMIL_TPM_CTX *ctx,
                       const uint8_t *key_data,
                       size_t key_size,
                       uint8_t *sealed_blob,
                       size_t *sealed_blob_size)
{
    tpm2_rc_t rc;

    if (!dsmil_tpm_is_available(ctx)) {
        ctx->software_fallbacks++;
        return 0;
    }

    ctx->tpm_operations++;

    rc = tpm2_key_seal(key_data, key_size, sealed_blob, sealed_blob_size);
    if (rc == TPM2_RC_SUCCESS) {
        return 1;
    }

    ctx->tpm_failures++;
    ctx->software_fallbacks++;
    return 0;
}

/*
 * Unseal key from TPM
 */
int dsmil_tpm_unseal_key(DSMIL_TPM_CTX *ctx,
                         const uint8_t *sealed_blob,
                         size_t sealed_blob_size,
                         uint8_t *key_data,
                         size_t *key_size)
{
    tpm2_rc_t rc;

    if (!dsmil_tpm_is_available(ctx)) {
        ctx->software_fallbacks++;
        return 0;
    }

    ctx->tpm_operations++;

    rc = tpm2_key_unseal(sealed_blob, sealed_blob_size, key_data, key_size);
    if (rc == TPM2_RC_SUCCESS) {
        return 1;
    }

    ctx->tpm_failures++;
    return 0;
}

/*
 * Generate TPM-backed key
 */
int dsmil_tpm_generate_key(DSMIL_TPM_CTX *ctx,
                           tpm2_crypto_algorithm_t key_type,
                           uint32_t key_bits,
                           tpm2_key_handle_t *key_handle)
{
    tpm2_rc_t rc;

    if (!dsmil_tpm_is_available(ctx)) {
        ctx->software_fallbacks++;
        return 0;
    }

    ctx->tpm_operations++;

    rc = tpm2_key_create(key_type, key_bits, key_handle);
    if (rc == TPM2_RC_SUCCESS) {
        return 1;
    }

    ctx->tpm_failures++;
    ctx->software_fallbacks++;
    return 0;
}

/*
 * Determine key storage type
 */
DSMIL_KEY_STORAGE_TYPE dsmil_tpm_get_key_storage_type(
    const DSMIL_TPM_CTX *ctx,
    DSMIL_PROFILE profile,
    int is_long_term)
{
    if (!dsmil_tpm_is_available(ctx)) {
        return DSMIL_KEY_STORAGE_SOFTWARE;
    }

    switch (profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
        /* Optional TPM for long-term keys */
        return is_long_term ? DSMIL_KEY_STORAGE_TPM_BACKED :
                              DSMIL_KEY_STORAGE_SOFTWARE;

    case DSMIL_PROFILE_DSMIL_SECURE:
        /* Prefer TPM for long-term keys */
        return is_long_term ? DSMIL_KEY_STORAGE_TPM_BACKED :
                              DSMIL_KEY_STORAGE_SOFTWARE;

    case DSMIL_PROFILE_ATOMAL:
        /* Require TPM for all keys */
        return DSMIL_KEY_STORAGE_TPM_ONLY;

    default:
        return DSMIL_KEY_STORAGE_SOFTWARE;
    }
}

/*
 * TPM hash operation
 */
int dsmil_tpm_hash(DSMIL_TPM_CTX *ctx,
                   tpm2_crypto_algorithm_t hash_alg,
                   const uint8_t *data,
                   size_t data_size,
                   uint8_t *hash_out,
                   size_t *hash_size)
{
    tpm2_rc_t rc;

    if (!dsmil_tpm_is_available(ctx)) {
        ctx->software_fallbacks++;
        return 0;
    }

    ctx->tpm_operations++;

    rc = tpm2_crypto_hash(hash_alg, data, data_size, hash_out, hash_size);
    if (rc == TPM2_RC_SUCCESS) {
        return 1;
    }

    ctx->tpm_failures++;
    ctx->software_fallbacks++;
    return 0;
}

/*
 * TPM HMAC operation
 */
int dsmil_tpm_hmac(DSMIL_TPM_CTX *ctx,
                   tpm2_crypto_algorithm_t hmac_alg,
                   const uint8_t *key,
                   size_t key_size,
                   const uint8_t *data,
                   size_t data_size,
                   uint8_t *hmac_out,
                   size_t *hmac_size)
{
    tpm2_rc_t rc;

    if (!dsmil_tpm_is_available(ctx)) {
        ctx->software_fallbacks++;
        return 0;
    }

    ctx->tpm_operations++;

    rc = tpm2_crypto_hmac(hmac_alg, key, key_size, data, data_size,
                          hmac_out, hmac_size);
    if (rc == TPM2_RC_SUCCESS) {
        return 1;
    }

    ctx->tpm_failures++;
    ctx->software_fallbacks++;
    return 0;
}

/*
 * TPM random number generation
 */
int dsmil_tpm_random(DSMIL_TPM_CTX *ctx,
                     uint8_t *buffer,
                     size_t length)
{
    /* TPM RNG would be implemented via tpm2-tools or direct TPM2_GetRandom */
    if (!dsmil_tpm_is_available(ctx) || !ctx->config.use_tpm_rng) {
        ctx->software_fallbacks++;
        return 0;
    }

    ctx->tpm_operations++;

    /* TODO: Implement TPM2_GetRandom call */
    /* For now, fall back to software */
    ctx->software_fallbacks++;
    return 0;
}

/*
 * Get TPM statistics
 */
void dsmil_tpm_get_stats(const DSMIL_TPM_CTX *ctx,
                         uint32_t *operations,
                         uint32_t *failures,
                         uint32_t *fallbacks)
{
    if (ctx == NULL)
        return;

    if (operations != NULL)
        *operations = ctx->tpm_operations;
    if (failures != NULL)
        *failures = ctx->tpm_failures;
    if (fallbacks != NULL)
        *fallbacks = ctx->software_fallbacks;
}

/*
 * Reset TPM statistics
 */
void dsmil_tpm_reset_stats(DSMIL_TPM_CTX *ctx)
{
    if (ctx != NULL) {
        ctx->tpm_operations = 0;
        ctx->tpm_failures = 0;
        ctx->software_fallbacks = 0;
    }
}

/*
 * Check if TPM required for profile
 */
int dsmil_tpm_is_required_for_profile(DSMIL_PROFILE profile)
{
    switch (profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
        return 0;  /* Optional */

    case DSMIL_PROFILE_DSMIL_SECURE:
        return 0;  /* Recommended but not required */

    case DSMIL_PROFILE_ATOMAL:
        return 1;  /* Required */

    default:
        return 0;
    }
}

/*
 * Get minimum TPM security level for profile
 */
tpm2_security_level_t dsmil_tpm_get_min_security_for_profile(DSMIL_PROFILE profile)
{
    switch (profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
        return TPM2_SECURITY_BASELINE;  /* 112-bit */

    case DSMIL_PROFILE_DSMIL_SECURE:
        return TPM2_SECURITY_HIGH;      /* 192-bit */

    case DSMIL_PROFILE_ATOMAL:
        return TPM2_SECURITY_MAXIMUM;   /* 256-bit */

    default:
        return TPM2_SECURITY_STANDARD;  /* 128-bit */
    }
}

/*
 * Get TPM acceleration flags for profile
 */
tpm2_acceleration_flags_t dsmil_tpm_get_accel_flags_for_profile(DSMIL_PROFILE profile)
{
    switch (profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
        /* Use common accelerators */
        return TPM2_ACCEL_AES_NI | TPM2_ACCEL_SHA_NI | TPM2_ACCEL_AVX2;

    case DSMIL_PROFILE_DSMIL_SECURE:
        /* Use all except experimental */
        return TPM2_ACCEL_AES_NI | TPM2_ACCEL_SHA_NI | TPM2_ACCEL_AVX2 |
               TPM2_ACCEL_AVX512 | TPM2_ACCEL_NPU;

    case DSMIL_PROFILE_ATOMAL:
        /* Use all available accelerators including NPU/GNA */
        return TPM2_ACCEL_ALL;

    default:
        return TPM2_ACCEL_NONE;
    }
}
