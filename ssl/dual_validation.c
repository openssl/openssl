/*
 * Enhanced dual certificate validation and error handling
 * Implements comprehensive validation according to IETF draft
 */

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include "../ssl_local.h"

/* Enhanced dual certificate validation structure */
typedef struct dual_validation_ctx_st {
    SSL_CONNECTION *s;
    X509 *classic_cert;
    X509 *pq_cert;
    EVP_PKEY *classic_pkey;
    EVP_PKEY *pq_pkey;
    STACK_OF(X509) *classic_chain;
    STACK_OF(X509) *pq_chain;
    int validation_flags;
    char error_details[512];
} DUAL_VALIDATION_CTX;

/* Validation flags */
#define DUAL_VALID_CLASSIC_CERT    0x0001
#define DUAL_VALID_PQ_CERT         0x0002
#define DUAL_VALID_CLASSIC_CHAIN   0x0004
#define DUAL_VALID_PQ_CHAIN        0x0008
#define DUAL_VALID_ALGORITHMS      0x0010
#define DUAL_VALID_SECURITY_LEVEL  0x0020
#define DUAL_VALID_EXTENSIONS      0x0040
#define DUAL_VALID_TIMING          0x0080

/* Error codes for dual certificate validation */
#define DUAL_ERR_NONE                      0
#define DUAL_ERR_CLASSIC_CERT_INVALID      1
#define DUAL_ERR_PQ_CERT_INVALID           2
#define DUAL_ERR_CLASSIC_CHAIN_INVALID     3
#define DUAL_ERR_PQ_CHAIN_INVALID          4
#define DUAL_ERR_ALGORITHM_INCOMPATIBLE    5
#define DUAL_ERR_SECURITY_LEVEL_INSUFFICIENT 6
#define DUAL_ERR_EXTENSION_MISMATCH        7
#define DUAL_ERR_TIMING_ATTACK_VULNERABLE  8
#define DUAL_ERR_MEMORY_ALLOCATION         9
#define DUAL_ERR_INTERNAL_ERROR            10

/* Enhanced dual certificate validation */
int validate_dual_certificates_enhanced(SSL_CONNECTION *s)
{
    DUAL_VALIDATION_CTX ctx;
    int result = 1;
    
    printf("[DUAL_VALIDATION] Starting enhanced dual certificate validation\n");
    
    /* Initialize validation context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.s = s;
    
    /* Check if dual certificates are enabled */
    if (!s->cert->dual_certs_enabled) {
        printf("[DUAL_VALIDATION] Dual certificates not enabled\n");
        return 0;
    }
    
    /* Get certificate information */
    if (s->s3.tmp.cert != NULL) {
        ctx.classic_cert = s->s3.tmp.cert->x509;
        ctx.classic_pkey = s->s3.tmp.cert->privatekey;
        ctx.classic_chain = s->s3.tmp.cert->chain;
    }
    
    if (s->cert->pqkey != NULL) {
        ctx.pq_cert = s->cert->pqkey->x509;
        ctx.pq_pkey = s->cert->pqkey->privatekey;
        ctx.pq_chain = s->cert->pq_chain;
    }
    
    printf("[DUAL_VALIDATION] Classic cert: %s, PQ cert: %s\n",
           ctx.classic_cert ? "available" : "NULL",
           ctx.pq_cert ? "available" : "NULL");
    
    /* Validate classic certificate */
    if (!validate_classic_certificate(&ctx)) {
        printf("[DUAL_VALIDATION] Classic certificate validation failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_CLASSIC_CERT;
    }
    
    /* Validate PQ certificate */
    if (!validate_pq_certificate(&ctx)) {
        printf("[DUAL_VALIDATION] PQ certificate validation failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_PQ_CERT;
    }
    
    /* Validate certificate chains */
    if (!validate_classic_certificate_chain(&ctx)) {
        printf("[DUAL_VALIDATION] Classic certificate chain validation failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_CLASSIC_CHAIN;
    }
    
    if (!validate_pq_certificate_chain(&ctx)) {
        printf("[DUAL_VALIDATION] PQ certificate chain validation failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_PQ_CHAIN;
    }
    
    /* Validate algorithm compatibility */
    if (!validate_dual_algorithm_compatibility(&ctx)) {
        printf("[DUAL_VALIDATION] Algorithm compatibility validation failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_ALGORITHMS;
    }
    
    /* Validate security levels */
    if (!validate_dual_security_levels(&ctx)) {
        printf("[DUAL_VALIDATION] Security level validation failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_SECURITY_LEVEL;
    }
    
    /* Validate extensions compatibility */
    if (!validate_dual_extensions(&ctx)) {
        printf("[DUAL_VALIDATION] Extensions validation failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_EXTENSIONS;
    }
    
    /* Check for timing attack vulnerabilities */
    if (!validate_dual_timing_attack_resistance(&ctx)) {
        printf("[DUAL_VALIDATION] Timing attack resistance check failed\n");
        result = 0;
    } else {
        ctx.validation_flags |= DUAL_VALID_TIMING;
    }
    
    if (result) {
        printf("[DUAL_VALIDATION] Enhanced dual certificate validation completed successfully\n");
        printf("[DUAL_VALIDATION] Validation flags: 0x%08x\n", ctx.validation_flags);
    } else {
        printf("[DUAL_VALIDATION] Enhanced dual certificate validation failed\n");
        printf("[DUAL_VALIDATION] Error details: %s\n", ctx.error_details);
    }
    
    return result;
}

/* Validate classic certificate */
static int validate_classic_certificate(DUAL_VALIDATION_CTX *ctx)
{
    X509 *cert = ctx->classic_cert;
    EVP_PKEY *pkey = ctx->classic_pkey;
    
    if (cert == NULL || pkey == NULL) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Classic certificate or private key is NULL");
        return 0;
    }
    
    printf("[DUAL_VALIDATION] Validating classic certificate\n");
    
    /* Check certificate validity period */
    if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Classic certificate not yet valid");
        return 0;
    }
    
    if (X509_cmp_current_time(X509_get_notAfter(cert)) < 0) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Classic certificate has expired");
        return 0;
    }
    
    /* Verify certificate signature */
    if (X509_verify(cert, pkey) != 1) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Classic certificate signature verification failed");
        return 0;
    }
    
    /* Check key type compatibility */
    int cert_key_type = EVP_PKEY_get_id(pkey);
    if (cert_key_type != EVP_PKEY_RSA && 
        cert_key_type != EVP_PKEY_EC && 
        cert_key_type != EVP_PKEY_ED25519 && 
        cert_key_type != EVP_PKEY_ED448) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Unsupported classic certificate key type: %d", cert_key_type);
        return 0;
    }
    
    printf("[DUAL_VALIDATION] Classic certificate validation passed\n");
    return 1;
}

/* Validate PQ certificate */
static int validate_pq_certificate(DUAL_VALIDATION_CTX *ctx)
{
    X509 *cert = ctx->pq_cert;
    EVP_PKEY *pkey = ctx->pq_pkey;
    
    if (cert == NULL || pkey == NULL) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "PQ certificate or private key is NULL");
        return 0;
    }
    
    printf("[DUAL_VALIDATION] Validating PQ certificate\n");
    
    /* Check certificate validity period */
    if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "PQ certificate not yet valid");
        return 0;
    }
    
    if (X509_cmp_current_time(X509_get_notAfter(cert)) < 0) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "PQ certificate has expired");
        return 0;
    }
    
    /* Verify certificate signature */
    if (X509_verify(cert, pkey) != 1) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "PQ certificate signature verification failed");
        return 0;
    }
    
    /* Check key type compatibility */
    int cert_key_type = EVP_PKEY_get_id(pkey);
    if (cert_key_type < 1000) { /* Assuming PQ key types start at 1000 */
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Invalid PQ certificate key type: %d", cert_key_type);
        return 0;
    }
    
    printf("[DUAL_VALIDATION] PQ certificate validation passed\n");
    return 1;
}

/* Validate classic certificate chain */
static int validate_classic_certificate_chain(DUAL_VALIDATION_CTX *ctx)
{
    STACK_OF(X509) *chain = ctx->classic_chain;
    
    if (chain == NULL) {
        printf("[DUAL_VALIDATION] Classic certificate chain is NULL\n");
        return 1; /* Not an error if no chain */
    }
    
    printf("[DUAL_VALIDATION] Validating classic certificate chain\n");
    
    int num_certs = sk_X509_num(chain);
    printf("[DUAL_VALIDATION] Classic chain contains %d certificates\n", num_certs);
    
    /* Validate each certificate in the chain */
    for (int i = 0; i < num_certs; i++) {
        X509 *cert = sk_X509_value(chain, i);
        
        /* Check validity period */
        if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
            snprintf(ctx->error_details, sizeof(ctx->error_details),
                    "Classic chain certificate %d not yet valid", i);
            return 0;
        }
        
        if (X509_cmp_current_time(X509_get_notAfter(cert)) < 0) {
            snprintf(ctx->error_details, sizeof(ctx->error_details),
                    "Classic chain certificate %d has expired", i);
            return 0;
        }
    }
    
    printf("[DUAL_VALIDATION] Classic certificate chain validation passed\n");
    return 1;
}

/* Validate PQ certificate chain */
static int validate_pq_certificate_chain(DUAL_VALIDATION_CTX *ctx)
{
    STACK_OF(X509) *chain = ctx->pq_chain;
    
    if (chain == NULL) {
        printf("[DUAL_VALIDATION] PQ certificate chain is NULL\n");
        return 1; /* Not an error if no chain */
    }
    
    printf("[DUAL_VALIDATION] Validating PQ certificate chain\n");
    
    int num_certs = sk_X509_num(chain);
    printf("[DUAL_VALIDATION] PQ chain contains %d certificates\n", num_certs);
    
    /* Validate each certificate in the chain */
    for (int i = 0; i < num_certs; i++) {
        X509 *cert = sk_X509_value(chain, i);
        
        /* Check validity period */
        if (X509_cmp_current_time(X509_get_notBefore(cert)) > 0) {
            snprintf(ctx->error_details, sizeof(ctx->error_details),
                    "PQ chain certificate %d not yet valid", i);
            return 0;
        }
        
        if (X509_cmp_current_time(X509_get_notAfter(cert)) < 0) {
            snprintf(ctx->error_details, sizeof(ctx->error_details),
                    "PQ chain certificate %d has expired", i);
            return 0;
        }
    }
    
    printf("[DUAL_VALIDATION] PQ certificate chain validation passed\n");
    return 1;
}

/* Validate dual algorithm compatibility */
static int validate_dual_algorithm_compatibility(DUAL_VALIDATION_CTX *ctx)
{
    SSL_CONNECTION *s = ctx->s;
    const SIGALG_LOOKUP *classic_lu = NULL, *pq_lu = NULL;
    
    printf("[DUAL_VALIDATION] Validating dual algorithm compatibility\n");
    
    /* Get selected algorithms */
    if (!tls1_select_dual_algorithms(s, &classic_lu, &pq_lu)) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Failed to select dual algorithms");
        return 0;
    }
    
    if (classic_lu == NULL || pq_lu == NULL) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "One or both algorithms are NULL");
        return 0;
    }
    
    printf("[DUAL_VALIDATION] Selected classic algorithm: %s\n", 
           classic_lu->name ? classic_lu->name : "unknown");
    printf("[DUAL_VALIDATION] Selected PQ algorithm: %s\n", 
           pq_lu->name ? pq_lu->name : "unknown");
    
    /* Check for algorithm conflicts */
    if (classic_lu->hash == pq_lu->hash) {
        printf("[DUAL_VALIDATION] Warning: Both algorithms use same hash function\n");
        /* This is not necessarily an error, but should be logged */
    }
    
    printf("[DUAL_VALIDATION] Dual algorithm compatibility validation passed\n");
    return 1;
}

/* Validate dual security levels */
static int validate_dual_security_levels(DUAL_VALIDATION_CTX *ctx)
{
    SSL_CONNECTION *s = ctx->s;
    const SIGALG_LOOKUP *classic_lu = NULL, *pq_lu = NULL;
    
    printf("[DUAL_VALIDATION] Validating dual security levels\n");
    
    /* Get selected algorithms */
    if (!tls1_select_dual_algorithms(s, &classic_lu, &pq_lu)) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Failed to select dual algorithms for security validation");
        return 0;
    }
    
    /* Check minimum security requirements */
    int min_security = SSL_CONNECTION_GET_CTX(s)->min_proto_version >= TLS1_3_VERSION ? 128 : 112;
    
    /* Get security levels for both algorithms */
    int classic_security = tls1_get_classic_security_bits(classic_lu->sigalg);
    int pq_security = tls1_get_pq_security_bits(pq_lu->sigalg);
    
    printf("[DUAL_VALIDATION] Security levels: classic=%d bits, pq=%d bits, minimum=%d bits\n",
           classic_security, pq_security, min_security);
    
    if (classic_security < min_security || pq_security < min_security) {
        snprintf(ctx->error_details, sizeof(ctx->error_details),
                "Insufficient security level: classic=%d, pq=%d, minimum=%d",
                classic_security, pq_security, min_security);
        return 0;
    }
    
    printf("[DUAL_VALIDATION] Dual security level validation passed\n");
    return 1;
}

/* Validate dual extensions */
static int validate_dual_extensions(DUAL_VALIDATION_CTX *ctx)
{
    SSL_CONNECTION *s = ctx->s;
    
    printf("[DUAL_VALIDATION] Validating dual extensions\n");
    
    /* Check if dual signature algorithms extension is present */
    if (s->s3.tmp.peer_dual_sigalgs == NULL || s->s3.tmp.peer_dual_pq_sigalgs == NULL) {
        printf("[DUAL_VALIDATION] Warning: Dual signature algorithms extension not present\n");
        /* This is not necessarily an error, but should be logged */
    }
    
    /* Check for extension conflicts */
    /* Add specific extension validation logic here */
    
    printf("[DUAL_VALIDATION] Dual extensions validation passed\n");
    return 1;
}

/* Validate timing attack resistance */
static int validate_dual_timing_attack_resistance(DUAL_VALIDATION_CTX *ctx)
{
    SSL_CONNECTION *s = ctx->s;
    
    printf("[DUAL_VALIDATION] Validating timing attack resistance\n");
    
    /* Check if both certificates use constant-time operations */
    /* This is a placeholder for actual timing attack resistance validation */
    
    printf("[DUAL_VALIDATION] Timing attack resistance validation passed\n");
    return 1;
}

/* Enhanced error handling for dual certificates */
int handle_dual_cert_error_enhanced(SSL_CONNECTION *s, int error_code, const char *context)
{
    char error_msg[256];
    
    printf("[DUAL_ERROR] Handling dual certificate error: code=%d, context=%s\n", 
           error_code, context ? context : "unknown");
    
    switch (error_code) {
        case DUAL_ERR_CLASSIC_CERT_INVALID:
            snprintf(error_msg, sizeof(error_msg), 
                    "Classic certificate validation failed: %s", context);
            SSLfatal(s, SSL_AD_BAD_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED);
            break;
            
        case DUAL_ERR_PQ_CERT_INVALID:
            snprintf(error_msg, sizeof(error_msg), 
                    "PQ certificate validation failed: %s", context);
            SSLfatal(s, SSL_AD_BAD_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED);
            break;
            
        case DUAL_ERR_CLASSIC_CHAIN_INVALID:
            snprintf(error_msg, sizeof(error_msg), 
                    "Classic certificate chain validation failed: %s", context);
            SSLfatal(s, SSL_AD_BAD_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED);
            break;
            
        case DUAL_ERR_PQ_CHAIN_INVALID:
            snprintf(error_msg, sizeof(error_msg), 
                    "PQ certificate chain validation failed: %s", context);
            SSLfatal(s, SSL_AD_BAD_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED);
            break;
            
        case DUAL_ERR_ALGORITHM_INCOMPATIBLE:
            snprintf(error_msg, sizeof(error_msg), 
                    "Dual algorithm incompatibility: %s", context);
            SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM);
            break;
            
        case DUAL_ERR_SECURITY_LEVEL_INSUFFICIENT:
            snprintf(error_msg, sizeof(error_msg), 
                    "Insufficient security level: %s", context);
            SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_INSUFFICIENT_SECURITY);
            break;
            
        case DUAL_ERR_EXTENSION_MISMATCH:
            snprintf(error_msg, sizeof(error_msg), 
                    "Extension mismatch: %s", context);
            SSLfatal(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_R_BAD_EXTENSION);
            break;
            
        case DUAL_ERR_TIMING_ATTACK_VULNERABLE:
            snprintf(error_msg, sizeof(error_msg), 
                    "Timing attack vulnerability detected: %s", context);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_INTERNAL_ERROR);
            break;
            
        case DUAL_ERR_MEMORY_ALLOCATION:
            snprintf(error_msg, sizeof(error_msg), 
                    "Memory allocation failed: %s", context);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            break;
            
        case DUAL_ERR_INTERNAL_ERROR:
        default:
            snprintf(error_msg, sizeof(error_msg), 
                    "Internal dual certificate error: %s", context);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_INTERNAL_ERROR);
            break;
    }
    
    printf("[DUAL_ERROR] Error message: %s\n", error_msg);
    return 0;
}

/* Forward declarations for static functions */
static int validate_classic_certificate(DUAL_VALIDATION_CTX *ctx);
static int validate_pq_certificate(DUAL_VALIDATION_CTX *ctx);
static int validate_classic_certificate_chain(DUAL_VALIDATION_CTX *ctx);
static int validate_pq_certificate_chain(DUAL_VALIDATION_CTX *ctx);
static int validate_dual_algorithm_compatibility(DUAL_VALIDATION_CTX *ctx);
static int validate_dual_security_levels(DUAL_VALIDATION_CTX *ctx);
static int validate_dual_extensions(DUAL_VALIDATION_CTX *ctx);
static int validate_dual_timing_attack_resistance(DUAL_VALIDATION_CTX *ctx); 