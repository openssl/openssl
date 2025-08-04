#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "apps.h"
#include "progs.h"
#include "opt.h"

#define DEFAULT_DIGEST EVP_sha256()

/* Command-line options enum */
enum {
    OPT_HELP = 1,
    OPT_IN,
    OPT_SHA256,
    OPT_SHA1,
    OPT_NO_COLONS
};

/* Define options array */
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
    BIO *in = NULL;
    X509 *cert = NULL;
    const EVP_MD *md = DEFAULT_DIGEST;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    char *infile = NULL;
    int no_colons = 0;
    int i, o;

    /* Parse command-line options */
    if (!opt_init(argc, argv, cert_fingerprint_options))
    return 1;

while ((o = opt_next()) != -1) {  // use -1 instead of OPT_EOF if not defined
        switch (o) {
        case OPT_HELP:
            opt_help(cert_fingerprint_options);
            return 0;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_SHA1:
            md = EVP_sha1();
            break;
        case OPT_SHA256:
            md = EVP_sha256();
            break;
        case OPT_NO_COLONS:
            no_colons = 1;
            break;
        default:
            return 1;
        }
    }

    /* Open input file */
    in = bio_open_default(infile, 'r', FORMAT_PEM);
    if (in == NULL)
        return 1;

    /* Read certificate */
    cert = PEM_read_bio_X509(in, NULL, 0, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Error reading certificate from %s\n", infile);
        BIO_free(in);
        return 1;
    }

    /* Compute fingerprint */
    if (!X509_digest(cert, md, digest, &digest_len)) {
        BIO_printf(bio_err, "Error computing certificate fingerprint\n");
        X509_free(cert);
        BIO_free(in);
        return 1;
    }

    /* Print fingerprint */
    for (i = 0; i < (int)digest_len; i++) {
        if (no_colons)
            BIO_printf(bio_out, "%02x", digest[i]);
        else
            BIO_printf(bio_out, "%02X%c", digest[i], (i + 1 == digest_len) ? '\n' : ':');
    }

    X509_free(cert);
    BIO_free(in);
    return 0;
}
