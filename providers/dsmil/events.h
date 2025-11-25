/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * DSMIL Policy Provider - Event Telemetry System
 *
 * This module handles event emission to DEFRAMEWORK via Unix socket.
 */

#ifndef DSMIL_EVENTS_H
# define DSMIL_EVENTS_H

# include <stddef.h>
# include "policy.h"

/*
 * Event Types
 */
typedef enum {
    DSMIL_EVENT_HANDSHAKE_START = 0,
    DSMIL_EVENT_HANDSHAKE_COMPLETE,
    DSMIL_EVENT_HANDSHAKE_FAILED,
    DSMIL_EVENT_POLICY_VIOLATION,
    DSMIL_EVENT_DOWNGRADE_DETECTED,
    DSMIL_EVENT_ALGORITHM_NEGOTIATED,
    DSMIL_EVENT_KEY_OPERATION
} DSMIL_EVENT_TYPE;

/*
 * Event Context
 */
typedef struct dsmil_event_ctx_st DSMIL_EVENT_CTX;

/*
 * Event Context Functions
 */

/* Create event context */
DSMIL_EVENT_CTX *dsmil_event_ctx_new(const char *socket_path);

/* Free event context */
void dsmil_event_ctx_free(DSMIL_EVENT_CTX *ctx);

/* Check if events are enabled */
int dsmil_event_is_enabled(const DSMIL_EVENT_CTX *ctx);

/*
 * Event Emission Functions
 */

/* Emit handshake start event */
int dsmil_event_handshake_start(DSMIL_EVENT_CTX *ctx,
                                 DSMIL_PROFILE profile,
                                 const char *protocol,
                                 const char *peer_info);

/* Emit handshake complete event */
int dsmil_event_handshake_complete(DSMIL_EVENT_CTX *ctx,
                                    DSMIL_PROFILE profile,
                                    const char *protocol,
                                    const char *protocol_version,
                                    const char *kex_type,
                                    const char *cipher_suite,
                                    const char *signature_type,
                                    const char *peer_info);

/* Emit handshake failed event */
int dsmil_event_handshake_failed(DSMIL_EVENT_CTX *ctx,
                                  DSMIL_PROFILE profile,
                                  const char *reason);

/* Emit policy violation event */
int dsmil_event_policy_violation(DSMIL_EVENT_CTX *ctx,
                                  DSMIL_PROFILE profile,
                                  const char *algorithm,
                                  const char *reason);

/* Emit downgrade detected event */
int dsmil_event_downgrade_detected(DSMIL_EVENT_CTX *ctx,
                                    DSMIL_PROFILE profile,
                                    const char *from_algorithm,
                                    const char *to_algorithm);

/* Emit algorithm negotiated event */
int dsmil_event_algorithm_negotiated(DSMIL_EVENT_CTX *ctx,
                                      DSMIL_PROFILE profile,
                                      const char *algorithm_type,
                                      const char *algorithm_name,
                                      int is_hybrid);

/* Emit key operation event */
int dsmil_event_key_operation(DSMIL_EVENT_CTX *ctx,
                               const char *operation,
                               const char *key_type);

/*
 * Generic Event Emission
 */

/* Emit generic event with JSON payload */
int dsmil_event_emit_json(DSMIL_EVENT_CTX *ctx,
                          DSMIL_EVENT_TYPE type,
                          const char *json_payload);

/*
 * Event Format Helpers
 */

/* Create JSON event payload */
char *dsmil_event_create_json(DSMIL_EVENT_TYPE type,
                               DSMIL_PROFILE profile,
                               const char *protocol,
                               const char *details);

/* Free JSON string */
void dsmil_event_free_json(char *json);

/*
 * Statistics
 */

/* Get event statistics */
typedef struct {
    unsigned long total_events;
    unsigned long handshake_events;
    unsigned long policy_violations;
    unsigned long downgrades;
    unsigned long failed_emissions;
} DSMIL_EVENT_STATS;

int dsmil_event_get_stats(const DSMIL_EVENT_CTX *ctx,
                          DSMIL_EVENT_STATS *stats);

#endif /* DSMIL_EVENTS_H */
