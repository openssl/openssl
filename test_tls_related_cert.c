#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/v3_certbind.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Initialize the RelatedCertificate extension
    if (!v3_certbind_init()) {
        fprintf(stderr, "Failed to initialize RelatedCertificate extension\n");
        return 1;
    }
    
    // Generate CA key and certificate
    EVP_PKEY *ca_key = EVP_PKEY_new();
    EVP_PKEY *server_key = EVP_PKEY_new();
    EVP_PKEY *related_key = EVP_PKEY_new();
    
    // Generate RSA keys
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &ca_key);
    EVP_PKEY_CTX_free(ctx);
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &server_key);
    EVP_PKEY_CTX_free(ctx);
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &related_key);
    EVP_PKEY_CTX_free(ctx);
    
    // Create CA certificate
    X509 *ca_cert = X509_new();
    X509_set_version(ca_cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(ca_cert), 365 * 24 * 3600);
    X509_set_pubkey(ca_cert, ca_key);
    
    X509_NAME *ca_name = X509_get_subject_name(ca_cert);
    X509_NAME_add_entry_by_txt(ca_name, "C", MBSTRING_ASC, (unsigned char *)"FR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(ca_name, "ST", MBSTRING_ASC, (unsigned char *)"Test State", -1, -1, 0);
    X509_NAME_add_entry_by_txt(ca_name, "L", MBSTRING_ASC, (unsigned char *)"Test City", -1, -1, 0);
    X509_NAME_add_entry_by_txt(ca_name, "O", MBSTRING_ASC, (unsigned char *)"Test Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(ca_name, "OU", MBSTRING_ASC, (unsigned char *)"Test Unit", -1, -1, 0);
    X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, (unsigned char *)"Test CA", -1, -1, 0);
    
    X509_set_issuer_name(ca_cert, ca_name);
    
    // Add basic constraints extension
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, ca_cert, ca_cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &v3ctx, NID_basic_constraints, "CA:TRUE");
    X509_add_ext(ca_cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Sign CA certificate
    X509_sign(ca_cert, ca_key, EVP_sha256());
    
    // Create related certificate
    X509 *related_cert = X509_new();
    X509_set_version(related_cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(related_cert), 2);
    X509_gmtime_adj(X509_get_notBefore(related_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(related_cert), 365 * 24 * 3600);
    X509_set_pubkey(related_cert, related_key);
    
    X509_NAME *related_name = X509_get_subject_name(related_cert);
    X509_NAME_add_entry_by_txt(related_name, "C", MBSTRING_ASC, (unsigned char *)"FR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(related_name, "ST", MBSTRING_ASC, (unsigned char *)"Test State", -1, -1, 0);
    X509_NAME_add_entry_by_txt(related_name, "L", MBSTRING_ASC, (unsigned char *)"Test City", -1, -1, 0);
    X509_NAME_add_entry_by_txt(related_name, "O", MBSTRING_ASC, (unsigned char *)"Test Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(related_name, "OU", MBSTRING_ASC, (unsigned char *)"Test Unit", -1, -1, 0);
    X509_NAME_add_entry_by_txt(related_name, "CN", MBSTRING_ASC, (unsigned char *)"Related Cert", -1, -1, 0);
    
    X509_set_issuer_name(related_cert, ca_name);
    X509_sign(related_cert, ca_key, EVP_sha256());
    
    // Save related certificate to file
    FILE *related_file = fopen("related_cert.pem", "w");
    PEM_write_X509(related_file, related_cert);
    fclose(related_file);
    
    // Create server certificate with RelatedCertificate extension
    X509 *server_cert = X509_new();
    X509_set_version(server_cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(server_cert), 3);
    X509_gmtime_adj(X509_get_notBefore(server_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(server_cert), 365 * 24 * 3600);
    X509_set_pubkey(server_cert, server_key);
    
    X509_NAME *server_name = X509_get_subject_name(server_cert);
    X509_NAME_add_entry_by_txt(server_name, "C", MBSTRING_ASC, (unsigned char *)"FR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(server_name, "ST", MBSTRING_ASC, (unsigned char *)"Test State", -1, -1, 0);
    X509_NAME_add_entry_by_txt(server_name, "L", MBSTRING_ASC, (unsigned char *)"Test City", -1, -1, 0);
    X509_NAME_add_entry_by_txt(server_name, "O", MBSTRING_ASC, (unsigned char *)"Test Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(server_name, "OU", MBSTRING_ASC, (unsigned char *)"Test Unit", -1, -1, 0);
    X509_NAME_add_entry_by_txt(server_name, "CN", MBSTRING_ASC, (unsigned char *)"Test Server", -1, -1, 0);
    
    X509_set_issuer_name(server_cert, ca_name);
    
    // Add RelatedCertificate extension
    if (!add_related_certificate_extension(server_cert, related_cert, EVP_sha256(), "file:related_cert.pem")) {
        fprintf(stderr, "Failed to add RelatedCertificate extension\n");
        return 1;
    }
    
    // Sign server certificate
    X509_sign(server_cert, ca_key, EVP_sha256());
    
    // Save certificates and keys
    FILE *ca_file = fopen("ca_cert.pem", "w");
    PEM_write_X509(ca_file, ca_cert);
    fclose(ca_file);
    
    FILE *ca_key_file = fopen("ca_key.pem", "w");
    PEM_write_PrivateKey(ca_key_file, ca_key, NULL, NULL, 0, NULL, NULL);
    fclose(ca_key_file);
    
    FILE *server_file = fopen("server_cert.pem", "w");
    PEM_write_X509(server_file, server_cert);
    fclose(server_file);
    
    FILE *server_key_file = fopen("server_key.pem", "w");
    PEM_write_PrivateKey(server_key_file, server_key, NULL, NULL, 0, NULL, NULL);
    fclose(server_key_file);
    
    // Create certificate chain file
    FILE *chain_file = fopen("server_chain.pem", "w");
    PEM_write_X509(chain_file, server_cert);
    PEM_write_X509(chain_file, ca_cert);
    fclose(chain_file);
    
    printf("Certificates generated successfully:\n");
    printf("- ca_cert.pem: CA certificate\n");
    printf("- ca_key.pem: CA private key\n");
    printf("- server_cert.pem: Server certificate with RelatedCertificate extension\n");
    printf("- server_key.pem: Server private key\n");
    printf("- server_chain.pem: Server certificate chain\n");
    printf("- related_cert.pem: Related certificate\n");
    
    // Clean up
    X509_free(ca_cert);
    X509_free(server_cert);
    X509_free(related_cert);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(related_key);
    
    return 0;
} 