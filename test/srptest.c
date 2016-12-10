/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_SRP

# include <stdio.h>

int main(int argc, char *argv[])
{
    printf("No SRP support\n");
    return (0);
}

#else

# include <openssl/srp.h>
# include <openssl/rand.h>
# include <openssl/err.h>

static void showbn(const char *name, const BIGNUM *bn)
{
    fputs(name, stdout);
    fputs(" = ", stdout);
    BN_print_fp(stdout, bn);
    putc('\n', stdout);
}

# define RANDOM_SIZE 32         /* use 256 bits on each side */

static int run_srp(const char *username, const char *client_pass,
                   const char *server_pass)
{
    int ret = -1;
    BIGNUM *s = NULL;
    BIGNUM *v = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *u = NULL;
    BIGNUM *x = NULL;
    BIGNUM *Apub = NULL;
    BIGNUM *Bpub = NULL;
    BIGNUM *Kclient = NULL;
    BIGNUM *Kserver = NULL;
    unsigned char rand_tmp[RANDOM_SIZE];
    /* use builtin 1024-bit params */
    const SRP_gN *GN = SRP_get_default_gN("1024");

    if (GN == NULL) {
        fprintf(stderr, "Failed to get SRP parameters\n");
        return -1;
    }
    /* Set up server's password entry */
    if (!SRP_create_verifier_BN(username, server_pass, &s, &v, GN->N, GN->g)) {
        fprintf(stderr, "Failed to create SRP verifier\n");
        return -1;
    }

    showbn("N", GN->N);
    showbn("g", GN->g);
    showbn("Salt", s);
    showbn("Verifier", v);

    /* Server random */
    RAND_bytes(rand_tmp, sizeof(rand_tmp));
    b = BN_bin2bn(rand_tmp, sizeof(rand_tmp), NULL);
    /* TODO - check b != 0 */
    showbn("b", b);

    /* Server's first message */
    Bpub = SRP_Calc_B(b, GN->N, GN->g, v);
    showbn("B", Bpub);

    if (!SRP_Verify_B_mod_N(Bpub, GN->N)) {
        fprintf(stderr, "Invalid B\n");
        return -1;
    }

    /* Client random */
    RAND_bytes(rand_tmp, sizeof(rand_tmp));
    a = BN_bin2bn(rand_tmp, sizeof(rand_tmp), NULL);
    /* TODO - check a != 0 */
    showbn("a", a);

    /* Client's response */
    Apub = SRP_Calc_A(a, GN->N, GN->g);
    showbn("A", Apub);

    if (!SRP_Verify_A_mod_N(Apub, GN->N)) {
        fprintf(stderr, "Invalid A\n");
        return -1;
    }

    /* Both sides calculate u */
    u = SRP_Calc_u(Apub, Bpub, GN->N);

    /* Client's key */
    x = SRP_Calc_x(s, username, client_pass);
    Kclient = SRP_Calc_client_key(GN->N, Bpub, GN->g, x, a, u);
    showbn("Client's key", Kclient);

    /* Server's key */
    Kserver = SRP_Calc_server_key(Apub, v, u, b, GN->N);
    showbn("Server's key", Kserver);

    if (BN_cmp(Kclient, Kserver) == 0) {
        ret = 0;
    } else {
        fprintf(stderr, "Keys mismatch\n");
        ret = 1;
    }

    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

int main(int argc, char **argv)
{
    BIO *bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);


    /* "Negative" test, expect a mismatch */
    if (run_srp("alice", "password1", "password2") == 0) {
        fprintf(stderr, "Mismatched SRP run failed\n");
        return 1;
    }

    /* "Positive" test, should pass */
    if (run_srp("alice", "password", "password") != 0) {
        fprintf(stderr, "Plain SRP run failed\n");
        return 1;
    }

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(bio_err) <= 0)
        return 1;
#endif
    BIO_free(bio_err);

    return 0;
}
#endif
