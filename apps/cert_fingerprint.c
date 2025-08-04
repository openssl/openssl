#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include "apps.h"
#include "progs.h"
#include "opt.h"

#define OPT_IN         1
#define OPT_SHA256     2
#define OPT_SHA1       3
#define OPT_NO_COLONS  4

const OPTIONS cert_fingerprint_options[] = {
    { "help", OPT_HELP, '-', "Display this summary" },
    { "in",   OPT_IN, '<', "Input PEM certificate file" },
    { "sha256", OPT_SHA256, '-', "Use SHA-256 fingerprint (default)" },
    { "sha1",   OPT_SHA1, '-', "Use SHA-1 fingerprint" },
    { "no-colons", OPT_NO_COLONS, '-', "Omit colons from output (lowercase)" },
    { NULL }
};

int cert_fingerprint_main(int argc, char **argv)
{
    const char *infile = NULL;
    int no_colons = 0;
    const EVP_MD *md = EVP_sha256(); // default

    // Basic arg parsing
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-in") && i + 1 < argc) {
            infile = argv[++i];
        } else if (!strcmp(argv[i], "-sha256")) {
            md = EVP_sha256();
        } else if (!strcmp(argv[i], "-sha1")) {
            md = EVP_sha1();
        } else if (!strcmp(argv[i], "-no-colons")) {
            no_colons = 1;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!infile) {
        fprintf(stderr, "Usage: openssl cert-fingerprint -in file.pem [-sha256] [-no-colons]\n");
        return 1;
    }

    FILE *fp = fopen(infile, "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert) {
        fprintf(stderr, "Failed to parse certificate\n");
        return 1;
    }

    unsigned char mdout[EVP_MAX_MD_SIZE];
    unsigned int mdlen;

    if (!X509_digest(cert, md, mdout, &mdlen)) {
        fprintf(stderr, "Failed to compute digest\n");
        X509_free(cert);
        return 1;
    }

    for (unsigned int i = 0; i < mdlen; i++) {
        printf(no_colons ? "%02x" : "%02X%c", mdout[i], no_colons ? '\0' : (i < mdlen - 1 ? ':' : '\n'));
    }
    if (no_colons) printf("\n");

    X509_free(cert);
    return 0;
}
