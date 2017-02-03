/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/dtls1.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssltestlib.h"

/* for SSL_USE_ETM() */
#include "../ssl/ssl_locl.h"

static int debug = 0;

static unsigned int clnt_psk_callback(SSL *ssl, const char *hint,
                                      char *ident, unsigned int max_ident_len,
                                      unsigned char *psk,
                                      unsigned int max_psk_len)
{
    BIO_snprintf(ident, max_ident_len, "psk");

    if (max_psk_len > 20)
        max_psk_len = 20;
    memset(psk, 0x5a, max_psk_len);

    return max_psk_len;
}

static unsigned int srvr_psk_callback(SSL *ssl, const char *identity,
                                      unsigned char *psk,
                                      unsigned int max_psk_len)
{
    if (max_psk_len > 20)
        max_psk_len = 20;
    memset(psk, 0x5a, max_psk_len);
    return max_psk_len;
}

static int mtu_test(SSL_CTX *ctx, const char *cs, int no_etm)
{
    SSL *srvr_ssl = NULL, *clnt_ssl = NULL;
    BIO *sc_bio = NULL;
    int i;
    size_t s;
    size_t mtus[30];
    unsigned char buf[600];
    int rv = 0;

    memset(buf, 0x5a, sizeof(buf));

    if (create_ssl_objects(ctx, ctx, &srvr_ssl, &clnt_ssl, NULL, NULL) != 1)
        goto out;

    if (no_etm)
        SSL_set_options(srvr_ssl, SSL_OP_NO_ENCRYPT_THEN_MAC);

    if (SSL_set_cipher_list(srvr_ssl, cs) != 1 ||
        SSL_set_cipher_list(clnt_ssl, cs) != 1) {
        ERR_print_errors_fp(stdout);
        goto out;
    }
    sc_bio = SSL_get_rbio(srvr_ssl);

    if (create_ssl_connection(clnt_ssl, srvr_ssl) != 1)
        goto out;

    if (debug)
        printf("Channel established\n");

    /* For record MTU values between 500 and 539, call DTLS_get_data_mtu()
     * to query the payload MTU which will fit. */
    for (i = 0; i < 30; i++) {
        SSL_set_mtu(clnt_ssl, 500 + i);
        mtus[i] = DTLS_get_data_mtu(clnt_ssl);
        if (debug)
            printf("%s%s payload MTU for record mtu %d = %"OSSLzu"\n",
                   cs, no_etm ? "-noEtM":"", 500 + i, mtus[i]);
        if (mtus[i] == 0) {
            fprintf(stderr,
                    "payload MTU failed with record MTU %d for %s\n",
                    500 + i, cs);
            goto out;
        }
    }

    /* Now get out of the way */
    SSL_set_mtu(clnt_ssl, 1000);

    /* Now for all values in the range of payload MTUs, send
     * a payload of that size and see what actual record size
     * we end up with. */
    for (s = mtus[0]; s <= mtus[29]; s++) {
        size_t reclen;
        if (SSL_write(clnt_ssl, buf, s) != (int)s) {
            ERR_print_errors_fp(stdout);
            goto out;
        }
        reclen = BIO_read(sc_bio, buf, sizeof(buf));
        if (debug)
            printf("record %"OSSLzu" for payload %"OSSLzu"\n", reclen, s);

        for (i = 0; i < 30; i++) {
            /* DTLS_get_data_mtu() with record MTU 500+i returned mtus[i] ... */

            if (s <= mtus[i] && reclen > (size_t)(500 + i)) {
                /* We sent a packet smaller than or equal to mtus[j] and
                 * that made a record *larger* than the record MTU 500+j! */
                fprintf(stderr,
                        "%s: Payload MTU %"OSSLzu" reported for record MTU %d\n"
                        "but sending a payload of %"OSSLzu" made a record of %"OSSLzu"(too large)\n",
                        cs, mtus[i], 500 + i, s, reclen);
                goto out;
            }
            if (s > mtus[i] && reclen <= (size_t)(500 + i)) {
                /* We sent a *larger* packet than mtus[i] and that *still*
                 * fits within the record MTU 500+i, so DTLS_get_data_mtu()
                 * was overly pessimistic. */
                fprintf(stderr,
                        "%s: Payload MTU %"OSSLzu" reported for record MTU %d\n"
                        "but sending a payload of %"OSSLzu" made a record of %"OSSLzu" (too small)\n",
                        cs, mtus[i], 500 + i, s, reclen);
                goto out;
            }
        }
    }
    rv = 1;
    if (SSL_USE_ETM(clnt_ssl))
        rv = 2;
 out:
    SSL_free(clnt_ssl);
    SSL_free(srvr_ssl);
    return rv;
}

int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
    STACK_OF(SSL_CIPHER) *ciphers;
    int i, rv = 0;

    SSL_CTX_set_psk_server_callback(ctx, srvr_psk_callback);
    SSL_CTX_set_psk_client_callback(ctx, clnt_psk_callback);
    SSL_CTX_set_security_level(ctx, 0);

    /* We only care about iterating over each enc/mac; we don't
     * want to repeat the test for each auth/kx variant.
     * So keep life simple and only do (non-DH) PSK. */
    if (!SSL_CTX_set_cipher_list(ctx, "PSK")) {
        fprintf(stderr, "Failed to set PSK cipher list\n");
        goto out;
    }

    ciphers = SSL_CTX_get_ciphers(ctx);
    for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        const char *cipher_name = SSL_CIPHER_get_name(cipher);

        /* As noted above, only one test for each enc/mac variant. */
        if (strncmp(cipher_name, "PSK-", 4))
            continue;

        rv = mtu_test(ctx, cipher_name, 0);
        if (!rv)
            break;

        printf("DTLS MTU test OK for %s\n", cipher_name);
        if (rv == 1)
            continue;

        /* mtu_test() returns 2 if it used Encrypt-then-MAC */
        rv = mtu_test(ctx, cipher_name, 1);
        if (!rv)
            break;

        printf("DTLS MTU test OK for %s without Encrypt-then-MAC\n", cipher_name);
    }
 out:
    SSL_CTX_free(ctx);

    return !rv;
}
