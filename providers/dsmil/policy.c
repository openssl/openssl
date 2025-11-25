/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * DSMIL Policy Provider - Policy Enforcement Implementation
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "policy.h"
#include <openssl/crypto.h>

/*
 * Policy Context Structure
 */
struct dsmil_policy_ctx_st {
    OSSL_LIB_CTX *libctx;
    DSMIL_PROFILE profile;
    DSMIL_THREATCON threatcon;
    char *event_socket_path;
    int require_hybrid_kex;
    int min_security_bits;
};

/*
 * Profile name mapping
 */
static const char *profile_names[] = {
    DSMIL_PROFILE_NAME_WORLD,
    DSMIL_PROFILE_NAME_SECURE,
    DSMIL_PROFILE_NAME_ATOMAL
};

/*
 * Create new policy context
 */
DSMIL_POLICY_CTX *dsmil_policy_ctx_new(OSSL_LIB_CTX *libctx)
{
    DSMIL_POLICY_CTX *ctx;
    const char *profile_env;
    const char *threatcon_env;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = libctx;

    /* Default profile: WORLD_COMPAT */
    ctx->profile = DSMIL_PROFILE_WORLD_COMPAT;

    /* Check environment for profile override */
    profile_env = getenv("DSMIL_PROFILE");
    if (profile_env != NULL) {
        dsmil_policy_set_profile_str(ctx, profile_env);
    }

    /* Check THREATCON level */
    threatcon_env = getenv("THREATCON_LEVEL");
    if (threatcon_env != NULL) {
        if (strcmp(threatcon_env, "ELEVATED") == 0)
            ctx->threatcon = DSMIL_THREATCON_ELEVATED;
        else if (strcmp(threatcon_env, "HIGH") == 0)
            ctx->threatcon = DSMIL_THREATCON_HIGH;
        else if (strcmp(threatcon_env, "SEVERE") == 0)
            ctx->threatcon = DSMIL_THREATCON_SEVERE;
        else
            ctx->threatcon = DSMIL_THREATCON_NORMAL;
    } else {
        ctx->threatcon = DSMIL_THREATCON_NORMAL;
    }

    /* Default settings */
    ctx->require_hybrid_kex = 0;  /* Off for WORLD_COMPAT */
    ctx->min_security_bits = 128;
    ctx->event_socket_path = NULL;

    return ctx;
}

/*
 * Free policy context
 */
void dsmil_policy_ctx_free(DSMIL_POLICY_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->event_socket_path != NULL)
        OPENSSL_free(ctx->event_socket_path);

    OPENSSL_free(ctx);
}

/*
 * Get profile name
 */
const char *dsmil_policy_get_profile_name(const DSMIL_POLICY_CTX *ctx)
{
    if (ctx == NULL)
        return "UNKNOWN";

    if (ctx->profile >= 0 && ctx->profile <= DSMIL_PROFILE_ATOMAL)
        return profile_names[ctx->profile];

    return "UNKNOWN";
}

/*
 * Set profile
 */
int dsmil_policy_set_profile(DSMIL_POLICY_CTX *ctx, DSMIL_PROFILE profile)
{
    if (ctx == NULL)
        return 0;

    ctx->profile = profile;

    /* Adjust defaults based on profile */
    switch (profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
        ctx->require_hybrid_kex = 0;
        ctx->min_security_bits = 128;
        break;

    case DSMIL_PROFILE_DSMIL_SECURE:
        ctx->require_hybrid_kex = 1;  /* Hybrid mandatory */
        ctx->min_security_bits = 192;
        break;

    case DSMIL_PROFILE_ATOMAL:
        ctx->require_hybrid_kex = 1;  /* Hybrid or PQC-only */
        ctx->min_security_bits = 256;
        break;

    default:
        return 0;
    }

    return 1;
}

/*
 * Set profile from string
 */
int dsmil_policy_set_profile_str(DSMIL_POLICY_CTX *ctx, const char *profile_str)
{
    if (ctx == NULL || profile_str == NULL)
        return 0;

    if (strcmp(profile_str, DSMIL_PROFILE_NAME_WORLD) == 0)
        return dsmil_policy_set_profile(ctx, DSMIL_PROFILE_WORLD_COMPAT);
    else if (strcmp(profile_str, DSMIL_PROFILE_NAME_SECURE) == 0)
        return dsmil_policy_set_profile(ctx, DSMIL_PROFILE_DSMIL_SECURE);
    else if (strcmp(profile_str, DSMIL_PROFILE_NAME_ATOMAL) == 0)
        return dsmil_policy_set_profile(ctx, DSMIL_PROFILE_ATOMAL);

    return 0;
}

/*
 * Get THREATCON level
 */
DSMIL_THREATCON dsmil_policy_get_threatcon(const DSMIL_POLICY_CTX *ctx)
{
    if (ctx == NULL)
        return DSMIL_THREATCON_NORMAL;

    return ctx->threatcon;
}

/*
 * Check KEM algorithm
 *
 * TODO (Phase 2): Implement full algorithm checking
 */
DSMIL_DECISION dsmil_policy_check_kem(const DSMIL_POLICY_CTX *ctx,
                                       const char *kem_name,
                                       int is_hybrid)
{
    if (ctx == NULL || kem_name == NULL)
        return DSMIL_DECISION_BLOCKED;

    /* Basic policy enforcement skeleton */
    switch (ctx->profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
        /* All KEMs allowed, hybrid preferred but not required */
        return DSMIL_DECISION_ALLOWED;

    case DSMIL_PROFILE_DSMIL_SECURE:
        /* Hybrid mandatory */
        if (!is_hybrid) {
            fprintf(stderr, "DSMIL Policy: Blocking non-hybrid KEM in DSMIL_SECURE profile\n");
            return DSMIL_DECISION_BLOCKED;
        }
        return DSMIL_DECISION_ALLOWED;

    case DSMIL_PROFILE_ATOMAL:
        /* Hybrid or PQC-only, no pure classical */
        if (!is_hybrid && strstr(kem_name, "ML-KEM") == NULL) {
            fprintf(stderr, "DSMIL Policy: Blocking classical-only KEM in ATOMAL profile\n");
            return DSMIL_DECISION_BLOCKED;
        }
        return DSMIL_DECISION_ALLOWED;

    default:
        return DSMIL_DECISION_BLOCKED;
    }
}

/*
 * Check signature algorithm
 *
 * TODO (Phase 2): Implement full signature checking
 */
DSMIL_DECISION dsmil_policy_check_signature(const DSMIL_POLICY_CTX *ctx,
                                             const char *sig_name,
                                             int is_hybrid)
{
    if (ctx == NULL || sig_name == NULL)
        return DSMIL_DECISION_BLOCKED;

    /* Basic policy enforcement skeleton */
    switch (ctx->profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
        /* Classical signatures allowed */
        return DSMIL_DECISION_ALLOWED;

    case DSMIL_PROFILE_DSMIL_SECURE:
        /* Hybrid preferred but not strictly required */
        if (!is_hybrid) {
            fprintf(stderr, "DSMIL Policy: Classical signature in DSMIL_SECURE (allowed but logged)\n");
            return DSMIL_DECISION_DOWNGRADED;
        }
        return DSMIL_DECISION_ALLOWED;

    case DSMIL_PROFILE_ATOMAL:
        /* Hybrid or PQC-only required */
        if (!is_hybrid && strstr(sig_name, "ML-DSA") == NULL) {
            fprintf(stderr, "DSMIL Policy: Blocking classical-only signature in ATOMAL profile\n");
            return DSMIL_DECISION_BLOCKED;
        }
        return DSMIL_DECISION_ALLOWED;

    default:
        return DSMIL_DECISION_BLOCKED;
    }
}

/*
 * Check cipher suite
 *
 * TODO (Phase 2): Implement full cipher checking
 */
DSMIL_DECISION dsmil_policy_check_cipher(const DSMIL_POLICY_CTX *ctx,
                                          const char *cipher_name)
{
    if (ctx == NULL || cipher_name == NULL)
        return DSMIL_DECISION_BLOCKED;

    /* Basic policy enforcement skeleton */
    switch (ctx->profile) {
    case DSMIL_PROFILE_WORLD_COMPAT:
    case DSMIL_PROFILE_DSMIL_SECURE:
        /* AES-256-GCM and ChaCha20-Poly1305 allowed */
        if (strstr(cipher_name, "AES-256-GCM") != NULL ||
            strstr(cipher_name, "CHACHA20-POLY1305") != NULL)
            return DSMIL_DECISION_ALLOWED;
        break;

    case DSMIL_PROFILE_ATOMAL:
        /* Only AES-256-GCM (ensures AES-NI usage) */
        if (strstr(cipher_name, "AES-256-GCM") != NULL)
            return DSMIL_DECISION_ALLOWED;
        break;

    default:
        break;
    }

    return DSMIL_DECISION_BLOCKED;
}

/*
 * Check TLS version
 *
 * TODO (Phase 2): Implement TLS version checking with proper constants
 */
int dsmil_policy_check_tls_version(const DSMIL_POLICY_CTX *ctx, int version)
{
    if (ctx == NULL)
        return 0;

    /* All profiles require TLS 1.3 minimum */
    /* Version constants: TLS1_3_VERSION = 0x0304 */
    if (version < 0x0304)  /* TLS 1.3 */
        return 0;

    return 1;
}

/*
 * Implementation Notes:
 *
 * Phase 2 TODO:
 *  - Implement full algorithm name matching
 *  - Add property query filtering
 *  - Implement SNI/IP-based profile selection
 *  - Add configuration parameter handling
 *  - Integrate with OpenSSL property query system
 *
 * Phase 3 TODO:
 *  - Add event emission calls
 *  - Log policy decisions to DEFRAMEWORK
 *
 * This is a skeleton implementation demonstrating the architecture.
 * Full implementation will be completed in Phase 2 of the roadmap.
 */
