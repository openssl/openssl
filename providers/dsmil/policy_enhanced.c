/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * DSMIL Policy Provider - Enhanced Policy Implementation
 *
 * This file provides enhanced policy functions with event telemetry integration.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "policy.h"
#include "policy_enhanced.h"
#include "events.h"
#include <openssl/crypto.h>

/* Extended policy context (internal) */
typedef struct dsmil_policy_ctx_extended_st {
    OSSL_LIB_CTX *libctx;
    DSMIL_PROFILE profile;
    DSMIL_THREATCON threatcon;
    char *event_socket_path;
    int require_hybrid_kex;
    int min_security_bits;
    DSMIL_EVENT_CTX *event_ctx;  /* Event context for telemetry */
} DSMIL_POLICY_CTX_EXT;

/*
 * Set event context
 */
void dsmil_policy_set_event_ctx(DSMIL_POLICY_CTX *ctx, DSMIL_EVENT_CTX *event_ctx)
{
    DSMIL_POLICY_CTX_EXT *ext_ctx = (DSMIL_POLICY_CTX_EXT *)ctx;

    if (ext_ctx == NULL)
        return;

    ext_ctx->event_ctx = event_ctx;
}

/*
 * Get event context
 */
DSMIL_EVENT_CTX *dsmil_policy_get_event_ctx(const DSMIL_POLICY_CTX *ctx)
{
    const DSMIL_POLICY_CTX_EXT *ext_ctx = (const DSMIL_POLICY_CTX_EXT *)ctx;

    if (ext_ctx == NULL)
        return NULL;

    return ext_ctx->event_ctx;
}

/*
 * Get current profile
 */
DSMIL_PROFILE dsmil_policy_get_profile(const DSMIL_POLICY_CTX *ctx)
{
    const DSMIL_POLICY_CTX_EXT *ext_ctx = (const DSMIL_POLICY_CTX_EXT *)ctx;

    if (ext_ctx == NULL)
        return DSMIL_PROFILE_WORLD_COMPAT;

    return ext_ctx->profile;
}

/*
 * Check KEM with event emission
 */
DSMIL_DECISION dsmil_policy_check_kem_with_event(DSMIL_POLICY_CTX *ctx,
                                                  const char *kem_name,
                                                  int is_hybrid)
{
    DSMIL_DECISION decision;
    DSMIL_EVENT_CTX *event_ctx;

    /* Perform policy check */
    decision = dsmil_policy_check_kem(ctx, kem_name, is_hybrid);

    /* Emit event if we have event context */
    event_ctx = dsmil_policy_get_event_ctx(ctx);
    if (event_ctx != NULL) {
        if (decision == DSMIL_DECISION_ALLOWED) {
            dsmil_event_algorithm_negotiated(event_ctx,
                                             dsmil_policy_get_profile(ctx),
                                             "KEM",
                                             kem_name,
                                             is_hybrid);
        } else if (decision == DSMIL_DECISION_BLOCKED) {
            dsmil_event_policy_violation(event_ctx,
                                        dsmil_policy_get_profile(ctx),
                                        kem_name,
                                        "KEM algorithm blocked by policy");
        } else if (decision == DSMIL_DECISION_DOWNGRADED) {
            dsmil_event_downgrade_detected(event_ctx,
                                          dsmil_policy_get_profile(ctx),
                                          "hybrid-kem",
                                          kem_name);
        }
    }

    return decision;
}

/*
 * Check signature with event emission
 */
DSMIL_DECISION dsmil_policy_check_signature_with_event(DSMIL_POLICY_CTX *ctx,
                                                        const char *sig_name,
                                                        int is_hybrid)
{
    DSMIL_DECISION decision;
    DSMIL_EVENT_CTX *event_ctx;

    /* Perform policy check */
    decision = dsmil_policy_check_signature(ctx, sig_name, is_hybrid);

    /* Emit event if we have event context */
    event_ctx = dsmil_policy_get_event_ctx(ctx);
    if (event_ctx != NULL) {
        if (decision == DSMIL_DECISION_ALLOWED) {
            dsmil_event_algorithm_negotiated(event_ctx,
                                             dsmil_policy_get_profile(ctx),
                                             "Signature",
                                             sig_name,
                                             is_hybrid);
        } else if (decision == DSMIL_DECISION_BLOCKED) {
            dsmil_event_policy_violation(event_ctx,
                                        dsmil_policy_get_profile(ctx),
                                        sig_name,
                                        "Signature algorithm blocked by policy");
        } else if (decision == DSMIL_DECISION_DOWNGRADED) {
            dsmil_event_downgrade_detected(event_ctx,
                                          dsmil_policy_get_profile(ctx),
                                          "hybrid-signature",
                                          sig_name);
        }
    }

    return decision;
}

/*
 * Check cipher with event emission
 */
DSMIL_DECISION dsmil_policy_check_cipher_with_event(DSMIL_POLICY_CTX *ctx,
                                                     const char *cipher_name)
{
    DSMIL_DECISION decision;
    DSMIL_EVENT_CTX *event_ctx;

    /* Perform policy check */
    decision = dsmil_policy_check_cipher(ctx, cipher_name);

    /* Emit event if we have event context */
    event_ctx = dsmil_policy_get_event_ctx(ctx);
    if (event_ctx != NULL) {
        if (decision == DSMIL_DECISION_ALLOWED) {
            dsmil_event_algorithm_negotiated(event_ctx,
                                             dsmil_policy_get_profile(ctx),
                                             "Cipher",
                                             cipher_name,
                                             0);  /* Ciphers aren't hybrid */
        } else if (decision == DSMIL_DECISION_BLOCKED) {
            dsmil_event_policy_violation(event_ctx,
                                        dsmil_policy_get_profile(ctx),
                                        cipher_name,
                                        "Cipher suite blocked by policy");
        }
    }

    return decision;
}

/*
 * Implementation Notes:
 *
 * Phase 2 & 3 Integration:
 *  - Enhanced policy functions automatically emit telemetry events
 *  - Event context is stored in policy context for easy access
 *  - All policy decisions are logged for DEFRAMEWORK
 *  - Events are non-blocking (fire-and-forget)
 *  - Failed event emission doesn't affect crypto operations
 *
 * Usage:
 *  - Link event context during provider initialization
 *  - Use *_with_event() functions for policy checks with telemetry
 *  - Original dsmil_policy_check_*() functions still available for simple use
 */
