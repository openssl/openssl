/*
 * Copyright 2025 DSMIL Security Team. All Rights Reserved.
 *
 * DSMIL Policy Provider - Policy Enforcement Header
 *
 * This header defines the policy enforcement interface for the
 * DSMIL security profiles (WORLD_COMPAT, DSMIL_SECURE, ATOMAL).
 */

#ifndef DSMIL_POLICY_H
# define DSMIL_POLICY_H

# include <openssl/core.h>
# include <openssl/params.h>

/*
 * Security Profiles
 */
typedef enum {
    DSMIL_PROFILE_WORLD_COMPAT = 0,    /* Public internet, backwards compatible */
    DSMIL_PROFILE_DSMIL_SECURE = 1,    /* Internal/allies, hybrid mandatory */
    DSMIL_PROFILE_ATOMAL = 2           /* Highest security, PQC/hybrid only */
} DSMIL_PROFILE;

/*
 * THREATCON Levels (DEFCON-style threat condition)
 */
typedef enum {
    DSMIL_THREATCON_NORMAL = 0,        /* Standard operation */
    DSMIL_THREATCON_ELEVATED = 1,      /* Increased vigilance */
    DSMIL_THREATCON_HIGH = 2,          /* High threat, enhanced security */
    DSMIL_THREATCON_SEVERE = 3         /* Maximum security, performance secondary */
} DSMIL_THREATCON;

/*
 * Algorithm Decision
 */
typedef enum {
    DSMIL_DECISION_ALLOWED = 0,        /* Algorithm allowed */
    DSMIL_DECISION_BLOCKED = 1,        /* Algorithm blocked by policy */
    DSMIL_DECISION_DOWNGRADED = 2,     /* Classical fallback (logged) */
    DSMIL_DECISION_FORCED_HYBRID = 3   /* Forced to hybrid */
} DSMIL_DECISION;

/*
 * Policy Context
 */
typedef struct dsmil_policy_ctx_st DSMIL_POLICY_CTX;

/*
 * Policy Context Functions
 */

/* Create new policy context */
DSMIL_POLICY_CTX *dsmil_policy_ctx_new(OSSL_LIB_CTX *libctx);

/* Free policy context */
void dsmil_policy_ctx_free(DSMIL_POLICY_CTX *ctx);

/* Get current profile name (for logging) */
const char *dsmil_policy_get_profile_name(const DSMIL_POLICY_CTX *ctx);

/* Set security profile from config */
int dsmil_policy_set_profile(DSMIL_POLICY_CTX *ctx, DSMIL_PROFILE profile);

/* Set security profile from string */
int dsmil_policy_set_profile_str(DSMIL_POLICY_CTX *ctx, const char *profile_str);

/* Get THREATCON level from environment */
DSMIL_THREATCON dsmil_policy_get_threatcon(const DSMIL_POLICY_CTX *ctx);

/*
 * Algorithm Policy Decisions
 */

/* Check if KEM algorithm is allowed */
DSMIL_DECISION dsmil_policy_check_kem(const DSMIL_POLICY_CTX *ctx,
                                       const char *kem_name,
                                       int is_hybrid);

/* Check if signature algorithm is allowed */
DSMIL_DECISION dsmil_policy_check_signature(const DSMIL_POLICY_CTX *ctx,
                                             const char *sig_name,
                                             int is_hybrid);

/* Check if cipher suite is allowed */
DSMIL_DECISION dsmil_policy_check_cipher(const DSMIL_POLICY_CTX *ctx,
                                          const char *cipher_name);

/* Check if TLS version is allowed */
int dsmil_policy_check_tls_version(const DSMIL_POLICY_CTX *ctx,
                                    int version);

/*
 * Property Query Filtering
 */

/* Filter property query based on policy */
int dsmil_policy_filter_properties(const DSMIL_POLICY_CTX *ctx,
                                     const char *properties,
                                     char *filtered_properties,
                                     size_t max_len);

/*
 * SNI/IP-based Profile Selection (Phase 2)
 */

/* Select profile based on SNI */
DSMIL_PROFILE dsmil_policy_select_profile_sni(const char *sni);

/* Select profile based on peer IP */
DSMIL_PROFILE dsmil_policy_select_profile_ip(const char *ip_addr);

/*
 * Event Emission (Phase 3)
 */

/* Emit policy decision event */
/* void dsmil_policy_emit_event(const DSMIL_POLICY_CTX *ctx,
                                const char *event_type,
                                const char *details); */

/*
 * Configuration Parameters
 */

/* OSSL_PARAM keys for DSMIL policy provider */
# define DSMIL_PARAM_PROFILE            "profile"
# define DSMIL_PARAM_EVENT_SOCKET       "event_socket"
# define DSMIL_PARAM_THREATCON_ENV      "threatcon_env"
# define DSMIL_PARAM_REQUIRE_HYBRID_KEX "require_hybrid_kex"
# define DSMIL_PARAM_MIN_SECURITY_BITS  "min_security_bits"

/*
 * Profile Names
 */
# define DSMIL_PROFILE_NAME_WORLD       "WORLD_COMPAT"
# define DSMIL_PROFILE_NAME_SECURE      "DSMIL_SECURE"
# define DSMIL_PROFILE_NAME_ATOMAL      "ATOMAL"

#endif /* DSMIL_POLICY_H */
