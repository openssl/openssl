/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * DSMIL Policy Provider - Event Telemetry Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <openssl/crypto.h>
#include "events.h"

/* Event context structure */
struct dsmil_event_ctx_st {
    char *socket_path;
    int socket_fd;
    int enabled;
    DSMIL_EVENT_STATS stats;
};

/* Event type names for JSON */
static const char *event_type_names[] = {
    "handshake_start",
    "handshake_complete",
    "handshake_failed",
    "policy_violation",
    "downgrade_detected",
    "algorithm_negotiated",
    "key_operation"
};

/* Profile names for JSON */
static const char *profile_names[] = {
    "WORLD_COMPAT",
    "DSMIL_SECURE",
    "ATOMAL"
};

/*
 * Get current timestamp in ISO 8601 format
 */
static void get_iso_timestamp(char *buf, size_t buflen)
{
    time_t now;
    struct tm *tm_info;

    time(&now);
    tm_info = gmtime(&now);
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", tm_info);
}

/*
 * Connect to Unix socket (lazy connection)
 */
static int event_connect_socket(DSMIL_EVENT_CTX *ctx)
{
    struct sockaddr_un addr;
    int fd;

    if (ctx == NULL || ctx->socket_path == NULL)
        return -1;

    /* Already connected */
    if (ctx->socket_fd >= 0)
        return ctx->socket_fd;

    /* Create socket */
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "DSMIL Events: Failed to create socket: %s\n",
                strerror(errno));
        return -1;
    }

    /* Set up address */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ctx->socket_path, sizeof(addr.sun_path) - 1);

    /* Connect (for DGRAM, this just sets default destination) */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "DSMIL Events: Failed to connect to %s: %s\n",
                ctx->socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    ctx->socket_fd = fd;
    return fd;
}

/*
 * Create event context
 */
DSMIL_EVENT_CTX *dsmil_event_ctx_new(const char *socket_path)
{
    DSMIL_EVENT_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->socket_fd = -1;
    ctx->enabled = 1; /* Enabled by default */
    memset(&ctx->stats, 0, sizeof(ctx->stats));

    if (socket_path != NULL) {
        ctx->socket_path = OPENSSL_strdup(socket_path);
        if (ctx->socket_path == NULL) {
            OPENSSL_free(ctx);
            return NULL;
        }
    } else {
        /* Default socket path */
        ctx->socket_path = OPENSSL_strdup("/run/crypto-events.sock");
        if (ctx->socket_path == NULL) {
            OPENSSL_free(ctx);
            return NULL;
        }
    }

    /* Try to connect (non-fatal if it fails) */
    event_connect_socket(ctx);

    return ctx;
}

/*
 * Free event context
 */
void dsmil_event_ctx_free(DSMIL_EVENT_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->socket_fd >= 0)
        close(ctx->socket_fd);

    if (ctx->socket_path != NULL)
        OPENSSL_free(ctx->socket_path);

    OPENSSL_free(ctx);
}

/*
 * Check if events are enabled
 */
int dsmil_event_is_enabled(const DSMIL_EVENT_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    return ctx->enabled;
}

/*
 * Send event to socket
 */
static int event_send(DSMIL_EVENT_CTX *ctx, const char *json)
{
    int fd;
    ssize_t sent;

    if (ctx == NULL || json == NULL || !ctx->enabled)
        return 0;

    fd = event_connect_socket(ctx);
    if (fd < 0) {
        ctx->stats.failed_emissions++;
        return -1;
    }

    sent = send(fd, json, strlen(json), 0);
    if (sent < 0) {
        fprintf(stderr, "DSMIL Events: Failed to send event: %s\n",
                strerror(errno));
        ctx->stats.failed_emissions++;
        return -1;
    }

    ctx->stats.total_events++;
    return 1;
}

/*
 * Create JSON event payload
 */
char *dsmil_event_create_json(DSMIL_EVENT_TYPE type,
                               DSMIL_PROFILE profile,
                               const char *protocol,
                               const char *details)
{
    char timestamp[32];
    char *json;
    size_t json_size;

    get_iso_timestamp(timestamp, sizeof(timestamp));

    /* Estimate size */
    json_size = 512 + (details ? strlen(details) : 0);
    json = OPENSSL_malloc(json_size);
    if (json == NULL)
        return NULL;

    snprintf(json, json_size,
             "{"
             "\"version\":\"1.0\","
             "\"timestamp\":\"%s\","
             "\"event_type\":\"%s\","
             "\"profile\":\"%s\","
             "\"protocol\":\"%s\""
             "%s%s%s"
             "}",
             timestamp,
             event_type_names[type],
             profile_names[profile],
             protocol ? protocol : "unknown",
             details ? "," : "",
             details ? details : "",
             details ? "" : "");

    return json;
}

/*
 * Free JSON string
 */
void dsmil_event_free_json(char *json)
{
    if (json != NULL)
        OPENSSL_free(json);
}

/*
 * Emit generic JSON event
 */
int dsmil_event_emit_json(DSMIL_EVENT_CTX *ctx,
                          DSMIL_EVENT_TYPE type,
                          const char *json_payload)
{
    return event_send(ctx, json_payload);
}

/*
 * Emit handshake start event
 */
int dsmil_event_handshake_start(DSMIL_EVENT_CTX *ctx,
                                 DSMIL_PROFILE profile,
                                 const char *protocol,
                                 const char *peer_info)
{
    char details[256];
    char *json;
    int ret;

    snprintf(details, sizeof(details),
             "\"peer\":\"%s\"",
             peer_info ? peer_info : "unknown");

    json = dsmil_event_create_json(DSMIL_EVENT_HANDSHAKE_START,
                                    profile, protocol, details);
    if (json == NULL)
        return -1;

    ret = event_send(ctx, json);
    dsmil_event_free_json(json);

    if (ret > 0)
        ctx->stats.handshake_events++;

    return ret;
}

/*
 * Emit handshake complete event
 */
int dsmil_event_handshake_complete(DSMIL_EVENT_CTX *ctx,
                                    DSMIL_PROFILE profile,
                                    const char *protocol,
                                    const char *protocol_version,
                                    const char *kex_type,
                                    const char *cipher_suite,
                                    const char *signature_type,
                                    const char *peer_info)
{
    char details[512];
    char *json;
    int ret;

    snprintf(details, sizeof(details),
             "\"protocol_version\":\"%s\","
             "\"kex\":{\"type\":\"%s\"},"
             "\"cipher_suite\":\"%s\","
             "\"signature\":{\"type\":\"%s\"},"
             "\"peer\":{\"info\":\"%s\"}",
             protocol_version ? protocol_version : "unknown",
             kex_type ? kex_type : "unknown",
             cipher_suite ? cipher_suite : "unknown",
             signature_type ? signature_type : "unknown",
             peer_info ? peer_info : "unknown");

    json = dsmil_event_create_json(DSMIL_EVENT_HANDSHAKE_COMPLETE,
                                    profile, protocol, details);
    if (json == NULL)
        return -1;

    ret = event_send(ctx, json);
    dsmil_event_free_json(json);

    if (ret > 0)
        ctx->stats.handshake_events++;

    return ret;
}

/*
 * Emit handshake failed event
 */
int dsmil_event_handshake_failed(DSMIL_EVENT_CTX *ctx,
                                  DSMIL_PROFILE profile,
                                  const char *reason)
{
    char details[256];
    char *json;
    int ret;

    snprintf(details, sizeof(details),
             "\"reason\":\"%s\"",
             reason ? reason : "unknown");

    json = dsmil_event_create_json(DSMIL_EVENT_HANDSHAKE_FAILED,
                                    profile, "TLS", details);
    if (json == NULL)
        return -1;

    ret = event_send(ctx, json);
    dsmil_event_free_json(json);

    if (ret > 0)
        ctx->stats.handshake_events++;

    return ret;
}

/*
 * Emit policy violation event
 */
int dsmil_event_policy_violation(DSMIL_EVENT_CTX *ctx,
                                  DSMIL_PROFILE profile,
                                  const char *algorithm,
                                  const char *reason)
{
    char details[256];
    char *json;
    int ret;

    snprintf(details, sizeof(details),
             "\"algorithm\":\"%s\","
             "\"reason\":\"%s\"",
             algorithm ? algorithm : "unknown",
             reason ? reason : "policy violation");

    json = dsmil_event_create_json(DSMIL_EVENT_POLICY_VIOLATION,
                                    profile, "TLS", details);
    if (json == NULL)
        return -1;

    ret = event_send(ctx, json);
    dsmil_event_free_json(json);

    if (ret > 0)
        ctx->stats.policy_violations++;

    return ret;
}

/*
 * Emit downgrade detected event
 */
int dsmil_event_downgrade_detected(DSMIL_EVENT_CTX *ctx,
                                    DSMIL_PROFILE profile,
                                    const char *from_algorithm,
                                    const char *to_algorithm)
{
    char details[256];
    char *json;
    int ret;

    snprintf(details, sizeof(details),
             "\"from\":\"%s\","
             "\"to\":\"%s\"",
             from_algorithm ? from_algorithm : "unknown",
             to_algorithm ? to_algorithm : "unknown");

    json = dsmil_event_create_json(DSMIL_EVENT_DOWNGRADE_DETECTED,
                                    profile, "TLS", details);
    if (json == NULL)
        return -1;

    ret = event_send(ctx, json);
    dsmil_event_free_json(json);

    if (ret > 0)
        ctx->stats.downgrades++;

    return ret;
}

/*
 * Emit algorithm negotiated event
 */
int dsmil_event_algorithm_negotiated(DSMIL_EVENT_CTX *ctx,
                                      DSMIL_PROFILE profile,
                                      const char *algorithm_type,
                                      const char *algorithm_name,
                                      int is_hybrid)
{
    char details[256];
    char *json;
    int ret;

    snprintf(details, sizeof(details),
             "\"algorithm_type\":\"%s\","
             "\"algorithm_name\":\"%s\","
             "\"is_hybrid\":%s",
             algorithm_type ? algorithm_type : "unknown",
             algorithm_name ? algorithm_name : "unknown",
             is_hybrid ? "true" : "false");

    json = dsmil_event_create_json(DSMIL_EVENT_ALGORITHM_NEGOTIATED,
                                    profile, "TLS", details);
    if (json == NULL)
        return -1;

    ret = event_send(ctx, json);
    dsmil_event_free_json(json);

    return ret;
}

/*
 * Emit key operation event
 */
int dsmil_event_key_operation(DSMIL_EVENT_CTX *ctx,
                               const char *operation,
                               const char *key_type)
{
    char details[256];
    char *json;
    int ret;

    snprintf(details, sizeof(details),
             "\"operation\":\"%s\","
             "\"key_type\":\"%s\"",
             operation ? operation : "unknown",
             key_type ? key_type : "unknown");

    json = dsmil_event_create_json(DSMIL_EVENT_KEY_OPERATION,
                                    DSMIL_PROFILE_WORLD_COMPAT,
                                    "CRYPTO", details);
    if (json == NULL)
        return -1;

    ret = event_send(ctx, json);
    dsmil_event_free_json(json);

    return ret;
}

/*
 * Get event statistics
 */
int dsmil_event_get_stats(const DSMIL_EVENT_CTX *ctx,
                          DSMIL_EVENT_STATS *stats)
{
    if (ctx == NULL || stats == NULL)
        return 0;

    memcpy(stats, &ctx->stats, sizeof(*stats));
    return 1;
}

/*
 * Implementation Notes:
 *
 * - Events are sent via Unix datagram socket (SOCK_DGRAM)
 * - Non-blocking and fire-and-forget (no ACK required)
 * - Failures are logged but don't block crypto operations
 * - JSON format for easy parsing by DEFRAMEWORK
 * - Timestamps in ISO 8601 format (UTC)
 * - Connection is lazy (established on first event)
 * - Statistics track event emission success/failure
 */
