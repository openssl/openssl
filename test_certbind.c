#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include "include/openssl/v3_certbind.h"

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Initialize certbind extension
    if (!v3_certbind_init()) {
        fprintf(stderr, "Failed to initialize certbind extension\n");
        return 1;
    }
    
    // Create a test CSR
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to create private key\n");
        return 1;
    }
    
    // Generate a test RSA key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create key context\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate RSA key\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);
    
    // Create a test CSR
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "Failed to create CSR\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    // Set the public key
    if (!X509_REQ_set_pubkey(req, pkey)) {
        fprintf(stderr, "Failed to set public key in CSR\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    // Create a test certificate (this would normally be loaded from a file)
    X509 *test_cert = X509_new();
    if (!test_cert) {
        fprintf(stderr, "Failed to create test certificate\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    // Set some basic certificate fields
    X509_set_version(test_cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(test_cert), 12345);
    X509_gmtime_adj(X509_get_notBefore(test_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(test_cert), 365*24*60*60);
    
    // Create a test subject name
    X509_NAME *name = X509_get_subject_name(test_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Test Certificate", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "Test Organization", -1, -1, 0);
    X509_set_issuer_name(test_cert, name);
    X509_set_subject_name(test_cert, name);
    
    // Set the public key
    X509_set_pubkey(test_cert, pkey);
    
    // Sign the certificate
    if (!X509_sign(test_cert, pkey, EVP_sha256())) {
        fprintf(stderr, "Failed to sign test certificate\n");
        X509_free(test_cert);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    printf("Test certificate created successfully\n");
    
    // Test adding relatedCertRequest to CSR
    const char *test_uri = "file:///tmp/test_cert.pem";
    if (add_related_cert_request_to_csr(req, pkey, test_cert, test_uri, EVP_sha256())) {
        printf("Successfully added relatedCertRequest to CSR\n");
        
        // Test verification
        if (verify_related_cert_request(req)) {
            printf("Successfully verified relatedCertRequest\n");
        } else {
            printf("Failed to verify relatedCertRequest\n");
        }
    } else {
        printf("Failed to add relatedCertRequest to CSR\n");
    }
    
    // Test adding RelatedCertificate extension
    X509 *new_cert = X509_new();
    if (new_cert) {
        X509_set_version(new_cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(new_cert), 67890);
        X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
        X509_gmtime_adj(X509_get_notAfter(new_cert), 365*24*60*60);
        
        X509_NAME *new_name = X509_get_subject_name(new_cert);
        X509_NAME_add_entry_by_txt(new_name, "CN", MBSTRING_ASC, "New Certificate", -1, -1, 0);
        X509_NAME_add_entry_by_txt(new_name, "O", MBSTRING_ASC, "New Organization", -1, -1, 0);
        X509_set_issuer_name(new_cert, new_name);
        X509_set_subject_name(new_cert, new_name);
        X509_set_pubkey(new_cert, pkey);
        
        if (add_related_certificate_extension(new_cert, test_cert, EVP_sha256(), "file:///tmp/test_cert.pem")) {
            printf("Successfully added RelatedCertificate extension\n");
            
            // Test verification
            if (verify_related_certificate_extension(new_cert, test_cert)) {
                printf("Successfully verified RelatedCertificate extension\n");
            } else {
                printf("Failed to verify RelatedCertificate extension\n");
            }
        } else {
            printf("Failed to add RelatedCertificate extension\n");
        }
        
        X509_free(new_cert);
    }
    
    // Test 11: Test adding RelatedCertificate extension with URI
    printf("\n=== Test 11: Adding RelatedCertificate extension with URI ===\n");
    X509 *new_cert_with_uri = X509_new();
    if (new_cert_with_uri) {
        X509_set_version(new_cert_with_uri, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(new_cert_with_uri), 11111);
        X509_gmtime_adj(X509_get_notBefore(new_cert_with_uri), 0);
        X509_gmtime_adj(X509_get_notAfter(new_cert_with_uri), 365*24*60*60);
        
        X509_NAME *new_name_with_uri = X509_get_subject_name(new_cert_with_uri);
        X509_NAME_add_entry_by_txt(new_name_with_uri, "CN", MBSTRING_ASC, "New Certificate With URI", -1, -1, 0);
        X509_NAME_add_entry_by_txt(new_name_with_uri, "O", MBSTRING_ASC, "New Organization With URI", -1, -1, 0);
        X509_set_issuer_name(new_cert_with_uri, new_name_with_uri);
        X509_set_subject_name(new_cert_with_uri, new_name_with_uri);
        X509_set_pubkey(new_cert_with_uri, pkey);
        
        const char *test_uri_for_extension = "file:///tmp/test_cert_with_uri.pem";
        if (add_related_certificate_extension(new_cert_with_uri, test_cert, EVP_sha256(), test_uri_for_extension)) {
            printf("Successfully added RelatedCertificate extension with URI\n");
            
            // Test verification
            if (verify_related_certificate_extension(new_cert_with_uri, test_cert)) {
                printf("Successfully verified RelatedCertificate extension with URI\n");
            } else {
                printf("Failed to verify RelatedCertificate extension with URI\n");
            }
            
            // Print the extension to see the URI
            BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
            if (bio) {
                print_related_certificate_extension(bio, new_cert_with_uri, 0);
                BIO_free(bio);
            }
        } else {
            printf("Failed to add RelatedCertificate extension with URI\n");
        }
        
        X509_free(new_cert_with_uri);
    }
    
    // Test 12: Test extracting URI from CSR and using it in certificate
    printf("\n=== Test 12: Extract URI from CSR and use in certificate ===\n");
    X509 *new_cert_from_csr = X509_new();
    if (new_cert_from_csr) {
        X509_set_version(new_cert_from_csr, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(new_cert_from_csr), 22222);
        X509_gmtime_adj(X509_get_notBefore(new_cert_from_csr), 0);
        X509_gmtime_adj(X509_get_notAfter(new_cert_from_csr), 365*24*60*60);
        
        X509_NAME *new_name_from_csr = X509_get_subject_name(new_cert_from_csr);
        X509_NAME_add_entry_by_txt(new_name_from_csr, "CN", MBSTRING_ASC, "New Certificate From CSR", -1, -1, 0);
        X509_NAME_add_entry_by_txt(new_name_from_csr, "O", MBSTRING_ASC, "New Organization From CSR", -1, -1, 0);
        X509_set_issuer_name(new_cert_from_csr, new_name_from_csr);
        X509_set_subject_name(new_cert_from_csr, new_name_from_csr);
        X509_set_pubkey(new_cert_from_csr, pkey);
        
        // Extract URI from the CSR we created earlier
        char *extracted_uri = extract_uri_from_related_cert_request(req);
        if (extracted_uri) {
            printf("Extracted URI from CSR: %s\n", extracted_uri);
            
            if (add_related_certificate_extension(new_cert_from_csr, test_cert, EVP_sha256(), extracted_uri)) {
                printf("Successfully added RelatedCertificate extension with extracted URI\n");
                
                // Print the extension to see the URI
                BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
                if (bio) {
                    print_related_certificate_extension(bio, new_cert_from_csr, 0);
                    BIO_free(bio);
                }
            } else {
                printf("Failed to add RelatedCertificate extension with extracted URI\n");
            }
            
            OPENSSL_free(extracted_uri);
        } else {
            printf("Failed to extract URI from CSR\n");
        }
        
        X509_free(new_cert_from_csr);
    }
    
    // Cleanup
    X509_free(test_cert);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    
    printf("Test completed\n");
    return 0;
} 