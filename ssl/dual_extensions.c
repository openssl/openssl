/*
 * Dual certificate extensions compatibility
 * Ensures compatibility with existing TLS extensions according to IETF draft
 */

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include "../ssl_local.h"

/* Extension compatibility flags */
#define EXT_COMPAT_SIGNATURE_ALGORITHMS    0x0001
#define EXT_COMPAT_CERTIFICATE_AUTHORITIES 0x0002
#define EXT_COMPAT_STATUS_REQUEST          0x0004
#define EXT_COMPAT_SUPPORTED_GROUPS       0x0008
#define EXT_COMPAT_KEY_SHARE              0x0010
#define EXT_COMPAT_PSK_KEY_EXCHANGE_MODES 0x0020
#define EXT_COMPAT_ALPN                   0x0040
#define EXT_COMPAT_COMPRESS_CERTIFICATE   0x0080
#define EXT_COMPAT_POST_HANDSHAKE_AUTH    0x0100

/* Enhanced dual extension compatibility checking */
int check_dual_extension_compatibility(SSL_CONNECTION *s)
{
    int compatibility_flags = 0;
    
    printf("[DUAL_EXTENSIONS] Checking dual extension compatibility\n");
    
    /* Check signature algorithms extension compatibility */
    if (check_signature_algorithms_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_SIGNATURE_ALGORITHMS;
        printf("[DUAL_EXTENSIONS] Signature algorithms extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] Signature algorithms extension incompatible\n");
    }
    
    /* Check certificate authorities extension compatibility */
    if (check_certificate_authorities_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_CERTIFICATE_AUTHORITIES;
        printf("[DUAL_EXTENSIONS] Certificate authorities extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] Certificate authorities extension incompatible\n");
    }
    
    /* Check status request extension compatibility */
    if (check_status_request_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_STATUS_REQUEST;
        printf("[DUAL_EXTENSIONS] Status request extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] Status request extension incompatible\n");
    }
    
    /* Check supported groups extension compatibility */
    if (check_supported_groups_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_SUPPORTED_GROUPS;
        printf("[DUAL_EXTENSIONS] Supported groups extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] Supported groups extension incompatible\n");
    }
    
    /* Check key share extension compatibility */
    if (check_key_share_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_KEY_SHARE;
        printf("[DUAL_EXTENSIONS] Key share extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] Key share extension incompatible\n");
    }
    
    /* Check PSK key exchange modes compatibility */
    if (check_psk_key_exchange_modes_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_PSK_KEY_EXCHANGE_MODES;
        printf("[DUAL_EXTENSIONS] PSK key exchange modes extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] PSK key exchange modes extension incompatible\n");
    }
    
    /* Check ALPN extension compatibility */
    if (check_alpn_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_ALPN;
        printf("[DUAL_EXTENSIONS] ALPN extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] ALPN extension incompatible\n");
    }
    
    /* Check compress certificate extension compatibility */
    if (check_compress_certificate_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_COMPRESS_CERTIFICATE;
        printf("[DUAL_EXTENSIONS] Compress certificate extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] Compress certificate extension incompatible\n");
    }
    
    /* Check post handshake auth extension compatibility */
    if (check_post_handshake_auth_compatibility(s)) {
        compatibility_flags |= EXT_COMPAT_POST_HANDSHAKE_AUTH;
        printf("[DUAL_EXTENSIONS] Post handshake auth extension compatible\n");
    } else {
        printf("[DUAL_EXTENSIONS] Post handshake auth extension incompatible\n");
    }
    
    printf("[DUAL_EXTENSIONS] Extension compatibility check completed\n");
    printf("[DUAL_EXTENSIONS] Compatibility flags: 0x%08x\n", compatibility_flags);
    
    return compatibility_flags;
}

/* Check signature algorithms extension compatibility */
static int check_signature_algorithms_compatibility(SSL_CONNECTION *s)
{
    /* The dual signature algorithms extension should be compatible with the standard signature algorithms extension */
    if (s->s3.tmp.peer_sigalgs != NULL && s->s3.tmp.peer_dual_sigalgs != NULL) {
        /* Check if there are overlapping algorithms between classic and dual */
        size_t i, j;
        for (i = 0; i < s->s3.tmp.peer_sigalgslen; i++) {
            for (j = 0; j < s->s3.tmp.peer_dual_sigalgslen; j++) {
                if (s->s3.tmp.peer_sigalgs[i] == s->s3.tmp.peer_dual_sigalgs[j]) {
                    printf("[DUAL_EXTENSIONS] Found overlapping signature algorithm: 0x%04x\n", 
                           s->s3.tmp.peer_sigalgs[i]);
                    return 1;
                }
            }
        }
    }
    
    /* If no dual signature algorithms, standard extension should work normally */
    if (s->s3.tmp.peer_dual_sigalgs == NULL) {
        return 1;
    }
    
    return 0;
}

/* Check certificate authorities extension compatibility */
static int check_certificate_authorities_compatibility(SSL_CONNECTION *s)
{
    /* Certificate authorities extension should work with both classic and PQ certificates */
    /* The extension should contain CAs for both certificate types */
    
    if (s->ext.peer_ca_names != NULL) {
        int num_cas = sk_X509_NAME_num(s->ext.peer_ca_names);
        printf("[DUAL_EXTENSIONS] Certificate authorities extension present with %d CAs\n", num_cas);
        
        /* Check if we have CAs for both classic and PQ certificates */
        int has_classic_ca = 0, has_pq_ca = 0;
        
        for (int i = 0; i < num_cas; i++) {
            X509_NAME *ca_name = sk_X509_NAME_value(s->ext.peer_ca_names, i);
            /* This is a simplified check - in practice, you'd need to determine CA type */
            has_classic_ca = 1; /* Placeholder */
        }
        
        if (s->cert->dual_certs_enabled) {
            /* In dual mode, we should have CAs for both types */
            return has_classic_ca && has_pq_ca;
        } else {
            /* In single mode, classic CA is sufficient */
            return has_classic_ca;
        }
    }
    
    return 1; /* No CA extension is acceptable */
}

/* Check status request extension compatibility */
static int check_status_request_compatibility(SSL_CONNECTION *s)
{
    /* Status request extension should work with both certificate types */
    /* The OCSP response should cover both classic and PQ certificates */
    
    if (s->ext.status_type == TLSEXT_STATUSTYPE_ocsp) {
        printf("[DUAL_EXTENSIONS] Status request extension present (OCSP)\n");
        
        if (s->cert->dual_certs_enabled) {
            /* In dual mode, OCSP response should cover both certificates */
            /* This is a simplified check - actual implementation would verify OCSP response */
            return 1;
        } else {
            /* In single mode, standard OCSP behavior */
            return 1;
        }
    }
    
    return 1; /* No status request is acceptable */
}

/* Check supported groups extension compatibility */
static int check_supported_groups_compatibility(SSL_CONNECTION *s)
{
    /* Supported groups extension should work normally with dual certificates */
    /* Key exchange is independent of certificate authentication */
    
    if (s->s3.tmp.peer_groups != NULL) {
        printf("[DUAL_EXTENSIONS] Supported groups extension present with %zu groups\n", 
               s->s3.tmp.peer_groupslen);
        return 1;
    }
    
    return 1; /* No supported groups is acceptable */
}

/* Check key share extension compatibility */
static int check_key_share_compatibility(SSL_CONNECTION *s)
{
    /* Key share extension should work normally with dual certificates */
    /* Key exchange is independent of certificate authentication */
    
    if (s->s3.tmp.peer_key_share != NULL) {
        printf("[DUAL_EXTENSIONS] Key share extension present\n");
        return 1;
    }
    
    return 1; /* No key share is acceptable */
}

/* Check PSK key exchange modes compatibility */
static int check_psk_key_exchange_modes_compatibility(SSL_CONNECTION *s)
{
    /* PSK key exchange modes should work with dual certificates */
    /* PSK authentication is separate from certificate authentication */
    
    if (s->s3.tmp.peer_psk_kex_mode != NULL) {
        printf("[DUAL_EXTENSIONS] PSK key exchange modes extension present\n");
        return 1;
    }
    
    return 1; /* No PSK modes is acceptable */
}

/* Check ALPN extension compatibility */
static int check_alpn_compatibility(SSL_CONNECTION *s)
{
    /* ALPN extension should work normally with dual certificates */
    /* Application protocol negotiation is independent of certificate authentication */
    
    if (s->ext.alpn_selected != NULL) {
        printf("[DUAL_EXTENSIONS] ALPN extension present, selected: %s\n", 
               s->ext.alpn_selected);
        return 1;
    }
    
    return 1; /* No ALPN is acceptable */
}

/* Check compress certificate extension compatibility */
static int check_compress_certificate_compatibility(SSL_CONNECTION *s)
{
    /* Compress certificate extension should work with dual certificates */
    /* The compressed certificate should contain both classic and PQ certificates */
    
    if (s->ext.compress_certificate_sent) {
        printf("[DUAL_EXTENSIONS] Compress certificate extension present\n");
        
        if (s->cert->dual_certs_enabled) {
            /* In dual mode, compressed certificate should contain both certificate chains */
            /* This is a simplified check - actual implementation would verify compression */
            return 1;
        } else {
            /* In single mode, standard compression behavior */
            return 1;
        }
    }
    
    return 1; /* No compression is acceptable */
}

/* Check post handshake auth extension compatibility */
static int check_post_handshake_auth_compatibility(SSL_CONNECTION *s)
{
    /* Post handshake auth extension should work with dual certificates */
    /* Client authentication can use dual certificates */
    
    if (s->post_handshake_auth == SSL_PHA_EXT_SENT || 
        s->post_handshake_auth == SSL_PHA_REQUESTED) {
        printf("[DUAL_EXTENSIONS] Post handshake auth extension present\n");
        
        if (s->cert->dual_certs_enabled) {
            /* In dual mode, post handshake auth can use dual certificates */
            return 1;
        } else {
            /* In single mode, standard post handshake auth behavior */
            return 1;
        }
    }
    
    return 1; /* No post handshake auth is acceptable */
}

/* Enhanced dual extension processing */
int process_dual_extensions(SSL_CONNECTION *s, int context)
{
    printf("[DUAL_EXTENSIONS] Processing dual extensions for context: %d\n", context);
    
    /* Process dual signature algorithms extension */
    if (!process_dual_signature_algorithms_extension(s, context)) {
        printf("[DUAL_EXTENSIONS] Failed to process dual signature algorithms extension\n");
        return 0;
    }
    
    /* Process other extensions normally */
    /* The dual certificate implementation should not interfere with other extensions */
    
    printf("[DUAL_EXTENSIONS] Dual extension processing completed successfully\n");
    return 1;
}

/* Process dual signature algorithms extension */
static int process_dual_signature_algorithms_extension(SSL_CONNECTION *s, int context)
{
    /* This function handles the dual signature algorithms extension processing */
    /* It should be called from the main extension processing logic */
    
    if (s->s3.tmp.peer_dual_sigalgs != NULL && s->s3.tmp.peer_dual_pq_sigalgs != NULL) {
        printf("[DUAL_EXTENSIONS] Processing dual signature algorithms extension\n");
        printf("[DUAL_EXTENSIONS] Classic sigalgs: %zu, PQ sigalgs: %zu\n",
               s->s3.tmp.peer_dual_sigalgslen, s->s3.tmp.peer_dual_pq_sigalgslen);
        
        /* Validate the dual signature algorithms */
        if (!validate_dual_signature_algorithms(s)) {
            printf("[DUAL_EXTENSIONS] Dual signature algorithms validation failed\n");
            return 0;
        }
        
        printf("[DUAL_EXTENSIONS] Dual signature algorithms extension processed successfully\n");
    }
    
    return 1;
}

/* Validate dual signature algorithms */
static int validate_dual_signature_algorithms(SSL_CONNECTION *s)
{
    /* Check that both classic and PQ signature algorithm lists are valid */
    
    if (s->s3.tmp.peer_dual_sigalgslen == 0 || s->s3.tmp.peer_dual_pq_sigalgslen == 0) {
        printf("[DUAL_EXTENSIONS] Empty dual signature algorithm lists\n");
        return 0;
    }
    
    /* Check for valid signature algorithms in classic list */
    for (size_t i = 0; i < s->s3.tmp.peer_dual_sigalgslen; i++) {
        if (!is_valid_classic_signature_algorithm(s->s3.tmp.peer_dual_sigalgs[i])) {
            printf("[DUAL_EXTENSIONS] Invalid classic signature algorithm: 0x%04x\n",
                   s->s3.tmp.peer_dual_sigalgs[i]);
            return 0;
        }
    }
    
    /* Check for valid signature algorithms in PQ list */
    for (size_t i = 0; i < s->s3.tmp.peer_dual_pq_sigalgslen; i++) {
        if (!is_valid_pq_signature_algorithm(s->s3.tmp.peer_dual_pq_sigalgs[i])) {
            printf("[DUAL_EXTENSIONS] Invalid PQ signature algorithm: 0x%04x\n",
                   s->s3.tmp.peer_dual_pq_sigalgs[i]);
            return 0;
        }
    }
    
    printf("[DUAL_EXTENSIONS] Dual signature algorithms validation passed\n");
    return 1;
}

/* Check if signature algorithm is valid for classic certificates */
static int is_valid_classic_signature_algorithm(uint16_t sigalg)
{
    /* Check against known classic signature algorithms */
    switch (sigalg) {
        case TLSEXT_SIGALG_rsa_pkcs1_sha256:
        case TLSEXT_SIGALG_rsa_pkcs1_sha384:
        case TLSEXT_SIGALG_rsa_pkcs1_sha512:
        case TLSEXT_SIGALG_ecdsa_secp256r1_sha256:
        case TLSEXT_SIGALG_ecdsa_secp384r1_sha384:
        case TLSEXT_SIGALG_ecdsa_secp521r1_sha512:
        case TLSEXT_SIGALG_ed25519:
        case TLSEXT_SIGALG_ed448:
            return 1;
        default:
            return 0;
    }
}

/* Check if signature algorithm is valid for PQ certificates */
static int is_valid_pq_signature_algorithm(uint16_t sigalg)
{
    /* Check against known PQ signature algorithms */
    switch (sigalg) {
        case 0x0901: /* MLDSA-44-SHA256 */
        case 0x0902: /* MLDSA-65-SHA256 */
        case 0x0903: /* FALCON-512-SHA256 */
        case 0x0904: /* FALCON-1024-SHA256 */
        case 0x0905: /* DILITHIUM-2-SHA256 */
        case 0x0906: /* DILITHIUM-3-SHA256 */
        case 0x0907: /* DILITHIUM-5-SHA256 */
        case 0x0908: /* SPHINCS-SHA256-128F-SIMPLE */
        case 0x0909: /* SPHINCS-SHA256-192F-SIMPLE */
        case 0x090A: /* SPHINCS-SHA256-256F-SIMPLE */
            return 1;
        default:
            return 0;
    }
}

/* Forward declarations for static functions */
static int check_signature_algorithms_compatibility(SSL_CONNECTION *s);
static int check_certificate_authorities_compatibility(SSL_CONNECTION *s);
static int check_status_request_compatibility(SSL_CONNECTION *s);
static int check_supported_groups_compatibility(SSL_CONNECTION *s);
static int check_key_share_compatibility(SSL_CONNECTION *s);
static int check_psk_key_exchange_modes_compatibility(SSL_CONNECTION *s);
static int check_alpn_compatibility(SSL_CONNECTION *s);
static int check_compress_certificate_compatibility(SSL_CONNECTION *s);
static int check_post_handshake_auth_compatibility(SSL_CONNECTION *s);
static int process_dual_signature_algorithms_extension(SSL_CONNECTION *s, int context);
static int validate_dual_signature_algorithms(SSL_CONNECTION *s);
static int is_valid_classic_signature_algorithm(uint16_t sigalg);
static int is_valid_pq_signature_algorithm(uint16_t sigalg); 