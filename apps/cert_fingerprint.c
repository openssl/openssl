#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "apps.h"
#include "opt.h"

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_IN
} OPTION_CHOICE;

const OPTIONS cert_fingerprint_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input certificate file (PEM format)"},
    {NULL}
};

int cert_fingerprint_main(int argc, char **argv)
{
    BIO *bio_err = NULL, *bio_out = NULL, *in = NULL;
    X509 *cert = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    const EVP_MD *digest = EVP_sha256();
    char *infile = NULL;
    int ret = 1;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (!opt_init(argc, argv, cert_fingerprint_options))
        return 1;

    OPTION_CHOICE o;
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_HELP:
            opt_help(cert_fingerprint_options);
            return 0;
        default:
            BIO_printf(bio_err, "Unknown option\n");
            return 1;
        }
    }

    if (infile == NULL) {
        BIO_printf(bio_err, "No input file provided with -in\n");
        return 1;
    }

    in = BIO_new_file(infile, "r");
    if (!in) {
        BIO_printf(bio_err, "Error opening file: %s\n", infile);
        goto end;
    }

    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (!cert) {
        BIO_printf(bio_err, "Error reading certificate from: %s\n", infile);
        goto end;
    }

    if (!X509_digest(cert, digest, md, &n)) {
        BIO_printf(bio_err, "Error computing fingerprint\n");
        goto end;
    }

    for (unsigned int i = 0; i < n; i++)
        BIO_printf(bio_out, "%02x", md[i]);
    BIO_printf(bio_out, "\n");

    ret = 0;

end:
    BIO_free(in);
    X509_free(cert);
    return ret;
}
