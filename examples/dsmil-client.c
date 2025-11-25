/*
 * dsmil-client.c - Example TLS client using DSMIL security profiles
 *
 * This example demonstrates:
 *  - Using different security profiles
 *  - Detecting hybrid vs classical handshakes
 *  - Reading THREATCON from environment
 *  - Event telemetry integration
 *
 * Compile:
 *   gcc -o dsmil-client dsmil-client.c \
 *       -I/opt/openssl-dsmil/include \
 *       -L/opt/openssl-dsmil/lib64 \
 *       -lssl -lcrypto
 *
 * Run:
 *   export OPENSSL_CONF=/opt/openssl-dsmil/ssl/dsmil-secure.cnf
 *   export THREATCON_LEVEL=NORMAL
 *   ./dsmil-client example.com 443
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* ANSI color codes */
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_RESET   "\033[0m"

void print_security_info(SSL *ssl)
{
    const char *version = SSL_get_version(ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    const char *cipher_name = SSL_CIPHER_get_name(cipher);
    X509 *cert = SSL_get_peer_certificate(ssl);

    printf("\n" COLOR_BLUE "=== TLS Connection Info ===" COLOR_RESET "\n");
    printf("  Protocol: %s\n", version);
    printf("  Cipher:   %s\n", cipher_name);

    /* Check if hybrid crypto was used */
    if (strstr(cipher_name, "ML-KEM") != NULL ||
        strstr(cipher_name, "MLKEM") != NULL) {
        printf(COLOR_GREEN "  ✓ Hybrid/PQC Key Exchange Detected" COLOR_RESET "\n");
    } else {
        printf(COLOR_YELLOW "  ⚠ Classical Key Exchange Only" COLOR_RESET "\n");
    }

    if (cert != NULL) {
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        printf("  Server:   %s\n", subject);

        /* Check for PQC in certificate */
        int pkey_type = EVP_PKEY_id(X509_get0_pubkey(cert));
        if (pkey_type == EVP_PKEY_ML_DSA) {
            printf(COLOR_GREEN "  ✓ PQC Certificate (ML-DSA)" COLOR_RESET "\n");
        } else if (pkey_type == EVP_PKEY_EC) {
            printf(COLOR_YELLOW "  ⚠ Classical Certificate (ECDSA)" COLOR_RESET "\n");
        }

        X509_free(cert);
    }

    printf("\n");
}

void print_profile_info(void)
{
    const char *profile = getenv("DSMIL_PROFILE");
    const char *threatcon = getenv("THREATCON_LEVEL");
    const char *config = getenv("OPENSSL_CONF");

    printf("\n" COLOR_BLUE "=== DSMIL Configuration ===" COLOR_RESET "\n");
    printf("  Profile:   %s\n", profile ? profile : "default");
    printf("  THREATCON: %s\n", threatcon ? threatcon : "NORMAL");
    printf("  Config:    %s\n", config ? config : "default");
    printf("\n");
}

int create_socket(const char *hostname, const char *port)
{
    struct addrinfo hints, *result, *rp;
    int sockfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &result) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;

        close(sockfd);
    }

    freeaddrinfo(result);

    if (rp == NULL) {
        fprintf(stderr, "Could not connect to %s:%s\n", hostname, port);
        return -1;
    }

    return sockfd;
}

int main(int argc, char *argv[])
{
    const char *hostname;
    const char *port;
    int sockfd;
    SSL_CTX *ctx;
    SSL *ssl;
    int ret;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        fprintf(stderr, "\nExample:\n");
        fprintf(stderr, "  export OPENSSL_CONF=configs/dsmil-secure.cnf\n");
        fprintf(stderr, "  export THREATCON_LEVEL=NORMAL\n");
        fprintf(stderr, "  %s example.com 443\n", argv[0]);
        return 1;
    }

    hostname = argv[1];
    port = argv[2];

    printf(COLOR_BLUE "DSMIL TLS Client Example" COLOR_RESET "\n");
    printf("Connecting to %s:%s\n", hostname, port);

    print_profile_info();

    /* Initialize OpenSSL */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* Create SSL context */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Set minimum TLS version to 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    /* Load default CA certificates */
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Warning: Could not load default CA certificates\n");
    }

    /* Create TCP connection */
    sockfd = create_socket(hostname, port);
    if (sockfd < 0) {
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Create SSL object */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, hostname);

    /* Perform TLS handshake */
    printf("Performing TLS handshake...\n");
    ret = SSL_connect(ssl);
    if (ret != 1) {
        fprintf(stderr, COLOR_RED "TLS handshake failed\n" COLOR_RESET);
        ERR_print_errors_fp(stderr);

        /* Check if it's a policy violation */
        unsigned long err = ERR_get_error();
        if (err != 0) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);

            if (strstr(err_buf, "DSMIL") != NULL) {
                fprintf(stderr, "\n" COLOR_YELLOW "Possible DSMIL policy violation:" COLOR_RESET "\n");
                fprintf(stderr, "  - Server may not support required hybrid crypto\n");
                fprintf(stderr, "  - Try WORLD_COMPAT profile for compatibility\n");
                fprintf(stderr, "  - Or check THREATCON level\n");
            }
        }

        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf(COLOR_GREEN "✓ TLS handshake successful\n" COLOR_RESET);

    /* Print security information */
    print_security_info(ssl);

    /* Send HTTP request */
    const char *request = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n";
    char buf[4096];
    snprintf(buf, sizeof(buf), request, hostname);

    SSL_write(ssl, buf, strlen(buf));

    /* Read response (just first chunk) */
    printf(COLOR_BLUE "=== Server Response ===" COLOR_RESET "\n");
    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        /* Print just the first line (HTTP status) */
        char *newline = strchr(buf, '\n');
        if (newline) *newline = '\0';
        printf("%s\n", buf);
        printf("... (response truncated)\n");
    }

    printf("\n");

    /* Cleanup */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    printf(COLOR_GREEN "✓ Connection closed successfully\n" COLOR_RESET);

    return 0;
}

/*
 * Example Usage:
 *
 * 1. Test with WORLD_COMPAT profile:
 *    export OPENSSL_CONF=configs/world.cnf
 *    ./dsmil-client google.com 443
 *
 * 2. Test with DSMIL_SECURE profile:
 *    export OPENSSL_CONF=configs/dsmil-secure.cnf
 *    export THREATCON_LEVEL=NORMAL
 *    ./dsmil-client internal-server.local 443
 *
 * 3. Test with ATOMAL profile (internal only):
 *    export OPENSSL_CONF=configs/atomal.cnf
 *    export THREATCON_LEVEL=HIGH
 *    ./dsmil-client high-security-server.local 443
 *
 * Expected Behavior:
 *  - WORLD_COMPAT: Should connect to most servers
 *  - DSMIL_SECURE: May fail on servers without hybrid crypto
 *  - ATOMAL: Only works with DSMIL-aware servers
 */
