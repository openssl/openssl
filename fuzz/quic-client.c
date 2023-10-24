/*
 * Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "fuzzer.h"
#include "internal/sockets.h"
#include "internal/time.h"
#include "internal/quic_ssl.h"

/* unused, to avoid warning. */
static int idx;

static OSSL_TIME fake_now;

static OSSL_TIME fake_now_cb(void *arg)
{
    return fake_now;
}

int FuzzerInitialize(int *argc, char ***argv)
{
    STACK_OF(SSL_COMP) *comp_methods;

    FuzzerSetRand();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ASYNC, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    comp_methods = SSL_COMP_get_compression_methods();
    if (comp_methods != NULL)
        sk_SSL_COMP_sort(comp_methods);

    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    SSL *client = NULL;
    BIO *in;
    BIO *out;
    SSL_CTX *ctx;
    BIO_ADDR *peer_addr = NULL;
    struct in_addr ina = {0};
    struct timeval tv;

    if (len == 0)
        return 0;

    /* This only fuzzes the initial flow from the client so far. */
    ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (ctx == NULL)
        goto end;

    client = SSL_new(ctx);
    if (client == NULL)
        goto end;

    fake_now = ossl_ms2time(1);
    if (!ossl_quic_conn_set_override_now_cb(client, fake_now_cb, NULL))
        goto end;

    peer_addr = BIO_ADDR_new();
    if (peer_addr == NULL)
        goto end;

    ina.s_addr = htonl(0x7f000001UL);

    if (!BIO_ADDR_rawmake(peer_addr, AF_INET, &ina, sizeof(ina), htons(4433)))
       goto end;

    SSL_set_tlsext_host_name(client, "localhost");
    in = BIO_new(BIO_s_dgram_mem());
    if (in == NULL)
        goto end;
    out = BIO_new(BIO_s_dgram_mem());
    if (out == NULL) {
        BIO_free(in);
        goto end;
    }
    if (!BIO_dgram_set_caps(out, BIO_DGRAM_CAP_HANDLES_DST_ADDR)) {
        BIO_free(in);
        BIO_free(out);
        goto end;
    }
    SSL_set_bio(client, in, out);
    if (SSL_set_alpn_protos(client, (const unsigned char *)"\x08ossltest", 9) != 0)
        goto end;
    if (SSL_set1_initial_peer_addr(client, peer_addr) != 1)
        goto end;
    SSL_set_connect_state(client);

    for (;;) {
        size_t size;
        uint64_t nxtpktms = 0;
        OSSL_TIME nxtpkt = ossl_time_zero(), nxttimeout;
        int isinf, ret;

        if (len >= 2) {
            nxtpktms = buf[0] + (buf[1] << 8);
            nxtpkt = ossl_time_add(fake_now, ossl_ms2time(nxtpktms));
            len -= 2;
            buf += 2;
        }

        for (;;) {
            if ((ret = SSL_do_handshake(client)) == 1) {
                /*
                * Keep reading application data until there are no more
                * datagrams to inject or a fatal error occurs
                */
                uint8_t tmp[1024];

                ret = SSL_read(client, tmp, sizeof(tmp));
            }
            if (ret <= 0) {
                switch (SSL_get_error(client, ret)) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    break;
                default:
                    goto end;
                }
            }

            if (!SSL_get_event_timeout(client, &tv, &isinf))
                goto end;

            if (isinf) {
                fake_now = nxtpkt;
                break;
            } else {
                nxttimeout = ossl_time_add(fake_now,
                                           ossl_time_from_timeval(tv));
                if (len > 3 && ossl_time_compare(nxttimeout, nxtpkt) >= 0) {
                    fake_now = nxtpkt;
                    break;
                }
                fake_now = nxttimeout;
            }
        }

        if (len <= 3)
            break;

        size = buf[0] + (buf[1] << 8);
        if (size > len - 2)
            break;

        if (size > 0)
            BIO_write(in, buf+2, size);
        len -= size + 2;
        buf += size + 2;
    }
 end:
    SSL_free(client);
    ERR_clear_error();
    SSL_CTX_free(ctx);
    BIO_ADDR_free(peer_addr);

    return 0;
}

void FuzzerCleanup(void)
{
    FuzzerClearRand();
}
