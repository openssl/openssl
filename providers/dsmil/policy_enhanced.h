/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * DSMIL Policy Provider - Enhanced Policy Functions
 *
 * Additional functions for Phase 2 & 3 implementation
 */

#ifndef DSMIL_POLICY_ENHANCED_H
# define DSMIL_POLICY_ENHANCED_H

# include "policy.h"

/* Forward declaration for event context */
typedef struct dsmil_event_ctx_st DSMIL_EVENT_CTX;

/*
 * Event Context Integration
 */

/* Set event context for telemetry */
void dsmil_policy_set_event_ctx(DSMIL_POLICY_CTX *ctx, DSMIL_EVENT_CTX *event_ctx);

/* Get event context */
DSMIL_EVENT_CTX *dsmil_policy_get_event_ctx(const DSMIL_POLICY_CTX *ctx);

/*
 * Profile Retrieval
 */

/* Get current profile (enum) */
DSMIL_PROFILE dsmil_policy_get_profile(const DSMIL_POLICY_CTX *ctx);

/*
 * Enhanced Policy Checks with Event Emission
 */

/* Check KEM with automatic event emission */
DSMIL_DECISION dsmil_policy_check_kem_with_event(DSMIL_POLICY_CTX *ctx,
                                                  const char *kem_name,
                                                  int is_hybrid);

/* Check signature with automatic event emission */
DSMIL_DECISION dsmil_policy_check_signature_with_event(DSMIL_POLICY_CTX *ctx,
                                                        const char *sig_name,
                                                        int is_hybrid);

/* Check cipher with automatic event emission */
DSMIL_DECISION dsmil_policy_check_cipher_with_event(DSMIL_POLICY_CTX *ctx,
                                                     const char *cipher_name);

#endif /* DSMIL_POLICY_ENHANCED_H */
