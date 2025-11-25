/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * TPM Integration Layer for DSMIL Policy Provider
 *
 * This module integrates the existing TPM2 implementation with the DSMIL
 * policy provider, enabling hardware-backed key storage and cryptographic
 * operations for all security profiles.
 */

#ifndef DSMIL_TPM_INTEGRATION_H
#define DSMIL_TPM_INTEGRATION_H

#include "policy.h"
#include "tpm2_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TPM Configuration
 */
typedef struct dsmil_tpm_config_st {
    int enabled;                    /* TPM integration enabled */
    int require_tpm_keys;           /* Require TPM-backed keys */
    int seal_session_keys;          /* Seal TLS session keys to TPM */
    int use_tpm_rng;                /* Use TPM RNG for random numbers */
    tpm2_security_level_t min_security;  /* Minimum TPM security level */
    tpm2_acceleration_flags_t accel_flags;  /* Hardware acceleration flags */
} DSMIL_TPM_CONFIG;

/*
 * TPM Context (integrates with policy context)
 */
typedef struct dsmil_tpm_ctx_st {
    DSMIL_TPM_CONFIG config;
    int initialized;
    uint32_t tpm_operations;        /* Counter for TPM operations */
    uint32_t tpm_failures;          /* Counter for TPM failures */
    uint32_t software_fallbacks;    /* Counter for software fallbacks */
} DSMIL_TPM_CTX;

/*
 * Key Storage Options
 */
typedef enum {
    DSMIL_KEY_STORAGE_SOFTWARE = 0,   /* Software-only storage */
    DSMIL_KEY_STORAGE_TPM_BACKED,     /* TPM-backed storage */
    DSMIL_KEY_STORAGE_TPM_ONLY        /* TPM-only (no software fallback) */
} DSMIL_KEY_STORAGE_TYPE;

/*
 * Initialization and Cleanup
 */

/**
 * Initialize TPM integration
 *
 * @param ctx  TPM context to initialize
 * @param policy_ctx  Associated policy context
 * @return 1 on success, 0 on failure
 */
int dsmil_tpm_init(DSMIL_TPM_CTX *ctx, const DSMIL_POLICY_CTX *policy_ctx);

/**
 * Cleanup TPM integration
 *
 * @param ctx  TPM context to cleanup
 */
void dsmil_tpm_cleanup(DSMIL_TPM_CTX *ctx);

/*
 * Configuration
 */

/**
 * Set TPM configuration based on security profile
 *
 * @param ctx  TPM context
 * @param profile  Security profile
 * @return 1 on success, 0 on failure
 */
int dsmil_tpm_configure_for_profile(DSMIL_TPM_CTX *ctx, DSMIL_PROFILE profile);

/**
 * Enable/disable TPM integration
 *
 * @param ctx  TPM context
 * @param enabled  1 to enable, 0 to disable
 */
void dsmil_tpm_set_enabled(DSMIL_TPM_CTX *ctx, int enabled);

/**
 * Check if TPM is available and operational
 *
 * @param ctx  TPM context
 * @return 1 if TPM is available, 0 otherwise
 */
int dsmil_tpm_is_available(const DSMIL_TPM_CTX *ctx);

/*
 * Key Management
 */

/**
 * Seal a private key to TPM
 *
 * @param ctx  TPM context
 * @param key_data  Key material to seal
 * @param key_size  Size of key material
 * @param sealed_blob  Output buffer for sealed blob
 * @param sealed_blob_size  Input: buffer size, Output: actual size
 * @return 1 on success, 0 on failure
 */
int dsmil_tpm_seal_key(DSMIL_TPM_CTX *ctx,
                       const uint8_t *key_data,
                       size_t key_size,
                       uint8_t *sealed_blob,
                       size_t *sealed_blob_size);

/**
 * Unseal a private key from TPM
 *
 * @param ctx  TPM context
 * @param sealed_blob  Sealed blob
 * @param sealed_blob_size  Size of sealed blob
 * @param key_data  Output buffer for key material
 * @param key_size  Input: buffer size, Output: actual size
 * @return 1 on success, 0 on failure
 */
int dsmil_tpm_unseal_key(DSMIL_TPM_CTX *ctx,
                         const uint8_t *sealed_blob,
                         size_t sealed_blob_size,
                         uint8_t *key_data,
                         size_t *key_size);

/**
 * Generate key pair backed by TPM
 *
 * @param ctx  TPM context
 * @param key_type  Type of key (RSA, ECC, etc.)
 * @param key_bits  Key size in bits
 * @param key_handle  Output key handle
 * @return 1 on success, 0 on failure
 */
int dsmil_tpm_generate_key(DSMIL_TPM_CTX *ctx,
                           tpm2_crypto_algorithm_t key_type,
                           uint32_t key_bits,
                           tpm2_key_handle_t *key_handle);

/**
 * Determine key storage type based on profile and policy
 *
 * @param ctx  TPM context
 * @param profile  Security profile
 * @param is_long_term  1 if long-term key, 0 if ephemeral
 * @return Recommended key storage type
 */
DSMIL_KEY_STORAGE_TYPE dsmil_tpm_get_key_storage_type(
    const DSMIL_TPM_CTX *ctx,
    DSMIL_PROFILE profile,
    int is_long_term);

/*
 * Cryptographic Operations (TPM-accelerated)
 */

/**
 * Hash operation using TPM (if available)
 *
 * @param ctx  TPM context
 * @param hash_alg  Hash algorithm
 * @param data  Input data
 * @param data_size  Size of input data
 * @param hash_out  Output hash buffer
 * @param hash_size  Input: buffer size, Output: actual size
 * @return 1 on success, 0 on failure (falls back to software)
 */
int dsmil_tpm_hash(DSMIL_TPM_CTX *ctx,
                   tpm2_crypto_algorithm_t hash_alg,
                   const uint8_t *data,
                   size_t data_size,
                   uint8_t *hash_out,
                   size_t *hash_size);

/**
 * HMAC operation using TPM (if available)
 *
 * @param ctx  TPM context
 * @param hmac_alg  HMAC algorithm
 * @param key  HMAC key
 * @param key_size  Size of key
 * @param data  Input data
 * @param data_size  Size of input data
 * @param hmac_out  Output HMAC buffer
 * @param hmac_size  Input: buffer size, Output: actual size
 * @return 1 on success, 0 on failure (falls back to software)
 */
int dsmil_tpm_hmac(DSMIL_TPM_CTX *ctx,
                   tpm2_crypto_algorithm_t hmac_alg,
                   const uint8_t *key,
                   size_t key_size,
                   const uint8_t *data,
                   size_t data_size,
                   uint8_t *hmac_out,
                   size_t *hmac_size);

/**
 * Get random bytes from TPM RNG
 *
 * @param ctx  TPM context
 * @param buffer  Output buffer for random bytes
 * @param length  Number of bytes to generate
 * @return 1 on success, 0 on failure (falls back to software)
 */
int dsmil_tpm_random(DSMIL_TPM_CTX *ctx,
                     uint8_t *buffer,
                     size_t length);

/*
 * Statistics and Monitoring
 */

/**
 * Get TPM operation statistics
 *
 * @param ctx  TPM context
 * @param operations  Output: total TPM operations
 * @param failures  Output: failed TPM operations
 * @param fallbacks  Output: software fallbacks
 */
void dsmil_tpm_get_stats(const DSMIL_TPM_CTX *ctx,
                         uint32_t *operations,
                         uint32_t *failures,
                         uint32_t *fallbacks);

/**
 * Reset TPM statistics
 *
 * @param ctx  TPM context
 */
void dsmil_tpm_reset_stats(DSMIL_TPM_CTX *ctx);

/*
 * Profile-Specific Requirements
 */

/**
 * Check if TPM is required for profile
 *
 * @param profile  Security profile
 * @return 1 if TPM required, 0 otherwise
 */
int dsmil_tpm_is_required_for_profile(DSMIL_PROFILE profile);

/**
 * Get minimum TPM security level for profile
 *
 * @param profile  Security profile
 * @return Required TPM security level
 */
tpm2_security_level_t dsmil_tpm_get_min_security_for_profile(DSMIL_PROFILE profile);

/**
 * Map DSMIL profile to TPM acceleration flags
 *
 * @param profile  Security profile
 * @return Recommended acceleration flags
 */
tpm2_acceleration_flags_t dsmil_tpm_get_accel_flags_for_profile(DSMIL_PROFILE profile);

#ifdef __cplusplus
}
#endif

#endif /* DSMIL_TPM_INTEGRATION_H */
