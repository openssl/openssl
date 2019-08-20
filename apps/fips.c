/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/provider.h>

static const char *progname = "openssl-fips";

/*
 * Print usage and return failing status code.
 */
static int usage(void)
{
    fprintf(stderr, "Usage error; use one of these invocations:\n");
    fprintf(stderr,
            "  %s verify {module-path} {hmac-key} {hmac-value}\n", progname);
    fprintf(stderr,
            "  %s calculate {module-path} {hmac-key}\n", progname);
    return 1;
}


/*
 * Print system error (perror) and openssl error stack and return a
 * failure exit status.
 */
static int errors(int e, const char *text)
{
    if (e)
        perror("System error");
    if (text != NULL)
        fprintf(stderr, "%s\n", text);
    ERR_print_errors_fp(stderr);
    return 1;
}


/*
 * Calculate the HMAC based on of the file |path| with the |key| (a text
 * string, not a binary array of bytes). Fill in |hmac| with the value,
 * and |*sp| with the size. Return the exit status.
 */
static int do_hmac(const char *path, const char *key,
                   unsigned char *hmac, size_t *sp)
{
    HMAC_CTX *hctx;
    size_t s;
    char buff[BUFSIZ];
    OSSL_PROVIDER *provider = NULL;
    FILE *in;

    /* Load the specified provider. */
    if ((provider = OSSL_PROVIDER_load(NULL, path)) == NULL)
        return errors(0, "Can't load provider");
    /* TODO(3.0) Enforce FIPS mode. XXX */

    /* Create context. */
    hctx = HMAC_CTX_new();
    if (hctx == NULL)
        return errors(0, "HMAC_CTX_new failed");
    if (!HMAC_Init_ex(hctx, key, (int)strlen(key), EVP_sha256(), NULL))
        return errors(0, "HMAC_Init_ex failed");

    /* Read file. */
    if ((in = fopen(path, "r")) == NULL)
        return errors(1, path);
    while ((s = fread(buff, 1, sizeof(buff), in)) != 0) {
        if (ferror(in))
            return errors(1, "read error");
        if (!HMAC_Update(hctx, (unsigned char *)buff, (int)s))
            return errors(0, "HMAC_Update failed");
    }
    fclose(in);

    if (!HMAC_Final(hctx, hmac, NULL))
        return errors(0, "HMAC_Final failed");
    if ((*sp = HMAC_size(hctx)) == 0)
        return errors(0, "HMAC_size failed");

    HMAC_CTX_free(hctx);
    OSSL_PROVIDER_unload(provider);
    return 0;
}


/*
 * Return the printable representation of a nibble.
 */
static char ch2nib(unsigned char uc)
{
    char buff[128];

    switch (uc) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': case 'a': return 0x0A;
    case 'B': case 'b': return 0x0B;
    case 'C': case 'c': return 0x0C;
    case 'D': case 'd': return 0x0D;
    case 'E': case 'e': return 0x0E;
    case 'F': case 'f': return 0x0F;
    }
    sprintf(buff, "Bad character |%c|", uc);
    return errors(0, buff);
}

/*
 * Return the printable representation of a nibble.
 */
static char nib2ch(unsigned char uc)
{
    char buff[128];

    switch (uc & 0x0F) {
    case 0x0: return '0';
    case 0x1: return '1';
    case 0x2: return '2';
    case 0x3: return '3';
    case 0x4: return '4';
    case 0x5: return '5';
    case 0x6: return '6';
    case 0x7: return '7';
    case 0x8: return '8';
    case 0x9: return '9';
    case 0xA: return 'A';
    case 0xB: return 'B';
    case 0xC: return 'C';
    case 0xD: return 'D';
    case 0xE: return 'E';
    case 0xF: return 'F';
    }
    sprintf(buff, "Bad number 0x%x\n", uc);
    return errors(0, buff);
}

/*
 * Verify the FIPS module signature and return appropriate exit code.
 */
static int do_verify(char *argv[])
{
    const char *path, *key, *value;
    unsigned char hmac[256], verify[256];
    size_t i, s, s2;

    /* Check args. */
    if ((path = *argv++) == NULL
            || (key = *argv++) == NULL
            || (value = *argv++) == NULL
            || *argv != NULL)
        return usage();

    if (do_hmac(path, key, hmac, &s) != 0)
        return errors(0, "Calculation failed");

    /* Convert value to binary, check size. */
    for (i = 0, s2 = s * 2; i < s2; i += 2) {
        if (value[i] == '\0' || value[i + 1] == '\0')
            return errors(0, "Wrong digest size");
        verify[i / 2] = (ch2nib(value[i]) << 4) | ch2nib(value[i + 1]);
    }
    if (value[i] != '\0')
        return errors(0, "Result too long");

    if (memcmp(hmac, verify, s) != 0)
        return errors(0, "Mismatch");

    /* TODO(3.0) run KAT startup tests. XXX */

    return 0;
}


/*
 * Calculate the HMAC value of an executable given the key and
 * print it out.
 */
static int do_calculate(char *argv[])
{
    const char *path, *key;
    size_t i, s;
    unsigned char uc, hmac[256];

    /* Check args. */
    if ((path = *argv++) == NULL
            || (key = *argv++) == NULL
            || *argv != NULL)
        return usage();

    if (do_hmac(path, key, hmac, &s) != 0)
        return errors(0, "Calculation failed");

    for (i = 0; i < s; i++) {
        uc = hmac[i];
        printf("%c%c", nib2ch(uc >> 4), nib2ch(uc));
    }
    putchar('\n');

    return 0;
}

int main(int argc, char *argv[])
{
    const char *p;

    if ((p = *++argv) == NULL)
        return usage();
    ++argv;

    OPENSSL_init_crypto((uint64_t)0, NULL);
    if (strcmp(p, "verify") == 0)
        return do_verify(argv);
    if (strcmp(p, "calculate") == 0)
        return do_calculate(argv);
    return usage();
}
