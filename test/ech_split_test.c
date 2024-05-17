/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include <openssl/ech.h>
#include <internal/ech_helpers.h>

#ifndef OPENSSL_NO_ECH

# define OSSL_ECH_MAX_LINELEN 1000 /* for a sanity check */
# define DEF_CERTS_DIR "test/certs"
# define MAXLOOPS 1000000

static OSSL_LIB_CTX *libctx = NULL;
static int verbose = 0;
# undef MORETESTS
/* this'll come soon, but not yet */
# ifdef MORETESTS
static int testcase = 0;
static int testiter = 0;
# endif
static char *certsdir = NULL;
static char *fe_cert = NULL;
static char *fe_privkey = NULL;
static char *be_privkey = NULL;
static char *be_cert = NULL;
static char *echkeyfile = NULL;
static char *echconfig = NULL;
static size_t echconfiglen = 0;
static unsigned char *bin_echconfig;
static size_t bin_echconfiglen = 0;

/* bit for the bitmask field */
# define SPLIT_NOMINAL 0
# define SPLIT_GREASE 1
# define SPLIT_HRR (1 << 1)
# define SPLIT_EARLY (1 << 2)

typedef struct SPLIT_testcase {
    char *descrip; /* descriptor */
    int bitmask; /* bitmask of things to do */
    int exp_rv; /* return from create 3way */
    int exp_err;
    int exp_cli_status;
    int exp_fe_status;
    int exp_be_status;
} SPLIT_TESTCASE;

static SPLIT_TESTCASE testcases[] = {
    { "nominal split", SPLIT_NOMINAL, 1, SSL_ERROR_NONE,
      SSL_ECH_STATUS_SUCCESS,
      SSL_ECH_STATUS_NOT_TRIED,
      SSL_ECH_STATUS_BACKEND},
    { "grease", SPLIT_GREASE, 1, SSL_ERROR_NONE,
      SSL_ECH_STATUS_GREASE_ECH,
      SSL_ECH_STATUS_GREASE,
      SSL_ECH_STATUS_NOT_CONFIGURED},
    { "hrr", SPLIT_HRR, 1, SSL_ERROR_NONE,
      SSL_ECH_STATUS_SUCCESS,
      SSL_ECH_STATUS_NOT_TRIED,
      SSL_ECH_STATUS_BACKEND},
    { "hrr and grease", SPLIT_HRR | SPLIT_GREASE, 1, SSL_ERROR_NONE,
      SSL_ECH_STATUS_GREASE_ECH,
      SSL_ECH_STATUS_GREASE,
      SSL_ECH_STATUS_NOT_CONFIGURED},
    { "early data", SPLIT_EARLY, 1, SSL_ERROR_NONE,
      SSL_ECH_STATUS_SUCCESS,
      SSL_ECH_STATUS_NOT_TRIED,
      SSL_ECH_STATUS_BACKEND},
    /*
     * the one below doesn't actually do early data, as that's
     * rejected due to HRR, but it'll work out in the end
     */
    { "HRR + early data", SPLIT_HRR | SPLIT_EARLY, 1,
      SSL_R_BINDER_DOES_NOT_VERIFY,
      SSL_ECH_STATUS_SUCCESS,
      SSL_ECH_STATUS_NOT_TRIED,
      SSL_ECH_STATUS_BACKEND},
};

/*
 * return the bas64 encoded ECHConfigList from an ECH PEM file
 *
 * note - this isn't really needed as an offical API because
 * real clients will use DNS or scripting clients who need
 * this can do it easier with shell commands
 *
 * the caller should free the returned string
 */
static char *echconfiglist_from_PEM(const char *file)
{
    BIO *in = NULL;
    char *ecl_string = NULL;
    char lnbuf[OSSL_ECH_MAX_LINELEN];
    int readbytes = 0;

    if (!TEST_ptr(in = BIO_new(BIO_s_file()))
        || !TEST_int_ge(BIO_read_filename(in, file), 0))
        goto out;
    /* read 4 lines before the one we want */
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    readbytes = BIO_get_line(in, lnbuf, OSSL_ECH_MAX_LINELEN);
    if (readbytes <= 0 || readbytes >= OSSL_ECH_MAX_LINELEN)
        goto out;
    ecl_string = OPENSSL_malloc(readbytes + 1);
    if (ecl_string == NULL)
        goto out;
    memcpy(ecl_string, lnbuf, readbytes);
    /* zap any '\n' or '\r' at the end if present */
    while (readbytes >= 0
           && (ecl_string[readbytes - 1] == '\n'
               || ecl_string[readbytes - 1] == '\r')) {
        ecl_string[readbytes - 1] = '\0';
        readbytes--;
    }
    if (readbytes == 0)
        goto out;
    BIO_free_all(in);
    return ecl_string;
out:
    BIO_free_all(in);
    return NULL;
}

/*
 * type we use for exdata in our BIO to route
 * data to backend
 */
typedef enum FE_ech_mode {
    SPLIT_LOCAL, /* front-end to process */
    SPLIT_FWD /* send to backend */
} FE_ECH_MODE;

typedef struct {
    FE_ECH_MODE ech_mode;
    unsigned char *hrrtok;
    size_t toklen;
    SSL_CTX *fe_ctx;
    SSL *cli_ssl;
    SSL *be_ssl;
    SSL *fe_ssl;
} ROUTE2BE;

typedef enum SPLIT_marker {
    SPLIT_NONE,
    SPLIT_FE,
    SPLIT_BE
} SPLIT_MARKER;

static void copy_flags(BIO *bio)
{
    int flags;
    BIO *next = BIO_next(bio);

    flags = BIO_test_flags(next, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_RWS);
    BIO_set_flags(bio, flags);
}

/*
 * filter to do split-mode ECH front-end decrypt
 */
static int tls_split_write(BIO *bio, const char *outer, int outerl)
{
    int ret = 0, is_ch = 0, is_ch2 = 0, dec_ok = 0, chlen = 0;
    BIO *next = BIO_next(bio), *rbio;
    size_t innerlen = 0, ccslen = 0, msg2sendlen = 0, extras = 0;
    unsigned char *inner = NULL;
    char *inner_sni = NULL, *outer_sni = NULL;
    ROUTE2BE *rbe = NULL;
    unsigned char *msg2send = NULL, *tmp = NULL;
    SPLIT_MARKER *position = NULL;

    if ((rbe = (ROUTE2BE *)BIO_get_ex_data(bio, 1)) == NULL)
        goto end;
    if ((position = (SPLIT_MARKER *)BIO_get_ex_data(bio, 2)) == NULL)
        goto end;
    if (verbose)
        TEST_info("calling tls_split_write from %s",
                  *position == SPLIT_FE ? "front-end" : "backend");

    if (outerl > SSL3_RT_HEADER_LENGTH
        && outer[0] == SSL3_RT_HANDSHAKE
        && outer[5] == SSL3_MT_CLIENT_HELLO) {
        /*
         * len of 1st record layer message (incl. header) that may be
         * a CH, but that could be followed by early data
         */
        chlen =
            SSL3_RT_HEADER_LENGTH
            + ((unsigned char)outer[3] << 8)
            + (unsigned char)outer[4];
        is_ch = 1;
        if (verbose) {
            TEST_info("outer CH len incl record layer is %d", outerl);
            TEST_info("CH is %d of that", chlen);
        }
    }
    /* check for change-cipher-spec then CH (happens with HRR) */
    if (outerl > SSL3_RT_HEADER_LENGTH
        && outer[0] == SSL3_RT_CHANGE_CIPHER_SPEC
        && outer[6] == SSL3_RT_HANDSHAKE
        && outer[11] == SSL3_MT_CLIENT_HELLO) {
        /*
         * len of 1st record layer message (incl. header) that may be
         * a CH, but that could be followed by early data
         */
        ccslen = 6;
        chlen =
            SSL3_RT_HEADER_LENGTH
            + ((unsigned char)outer[9] << 8)
            + (unsigned char)outer[10];
        is_ch = 1;
        is_ch2 = 1;
        if (verbose) {
            TEST_info("outer CH preceeded by CCS");
            TEST_info("outer CH len incl record layer is %d", outerl);
            TEST_info("CH is %d of that", chlen);
        }
    }

    if (is_ch == 1 && *position == SPLIT_FE) {
        unsigned char *chstart = (unsigned char *)outer, *inp = NULL;

        /* outer has to be longer than inner, so this is safe */
        inner = OPENSSL_malloc(outerl);
        if (inner == NULL)
            goto end;
        memset(inner, 0xAA, innerlen);
        inp = inner;
        innerlen = outerl;
        if (is_ch2 == 1) {
            memcpy(inner, outer, 6);
            inp += 6;
            innerlen -= 6;
            chstart += 6;
        }
        if (!TEST_true(SSL_CTX_ech_raw_decrypt(rbe->fe_ctx, &dec_ok,
                                               &inner_sni, &outer_sni,
                                               chstart, chlen,
                                               inp, &innerlen,
                                               &rbe->hrrtok, &rbe->toklen)))
            goto end;
        if (dec_ok == 1) {
            if (verbose)
                TEST_info("inner CH len incl record layer is %d",
                          (int)innerlen);
            /* we've decrypted, so route to backend in future */
            rbe->ech_mode = SPLIT_FWD;
            msg2send = inner;
            msg2sendlen = innerlen;
            if (is_ch2 == 1)
                msg2sendlen += 6;
            OPENSSL_free(inner_sni);
            OPENSSL_free(outer_sni);
            extras = outerl - (chlen + ccslen);
            if (extras != 0) {
                /* append to msg2send as needed */
                if (verbose)
                    TEST_info("writing additional %d octets from after CH",
                              (int)extras);
                tmp = OPENSSL_realloc(msg2send, msg2sendlen + extras);
                if (tmp == NULL)
                    goto end;
                msg2send = tmp;
                memcpy(msg2send + msg2sendlen, outer + chlen + ccslen, extras);
                msg2sendlen += extras;
            } else {
                if (verbose)
                    TEST_info("nothing to write after inner");
            }
        } else {
            OPENSSL_free(inner);
            inner = NULL;
            if (verbose)
                TEST_info("inner CH didn't decrypt");
        }
    } else {
        msg2send = (unsigned char *)outer;
        msg2sendlen = outerl;
    }
    if (rbe->ech_mode == SPLIT_FWD) {
        /* send to/from backend */
        if (*position == SPLIT_FE) {
            /* send recovered plaintext to BE */
            rbio = SSL_get_rbio(rbe->be_ssl);
            if (rbio == NULL)
                return 0;
            ret = BIO_write(rbio, msg2send, (int)msg2sendlen);
            if (dec_ok)
                OPENSSL_free(msg2send);
            if (verbose)
                TEST_info("send %d octets to BE", (int)msg2sendlen);
        } else if (*position == SPLIT_BE) {
            /* send BE message to client */
            rbio = SSL_get_rbio(rbe->cli_ssl);
            if (rbio == NULL)
                return 0;
            ret = BIO_write(rbio, outer, outerl);
            if (verbose)
                TEST_info("send %d octets to CLI", outerl);
        } else {
            /* send message as rx'd */
            ret = BIO_write(next, outer, outerl);
            if (verbose)
                TEST_info("send %d octets locally (%s)", outerl,
                          *position == SPLIT_FE ? "FE" : "BE");
        }
        copy_flags(bio);
        /*
         * Weirdly, we need to return the original length of the
         * outer CH here or else the "unused" 182 octets turn up
         * as a badly encoded record layer message.
         * In the nominal test case right now, the original outer
         * CH length is 441, the inner CH length is 259 and the
         * 182 is the difference.
         * It took a surprising amount of trial-and-error to
         * figure that out, and I'm not sure it's really right,
         * but hey, it works, for now;-)
         */
        return outerl;
    }
end:
    if (dec_ok) {
        if (inner != msg2send)
            OPENSSL_free(msg2send);
        OPENSSL_free(inner);
    }
    ret = BIO_write(next, outer, outerl);
    copy_flags(bio);
    return ret;
}

# undef SPLITREAD
# ifdef SPLITREAD
/*
 * This was an attempt to intercept and route reads, but
 * turns out not to be needed (so far). It's probably
 * broken too, but will leave here 'till fuller set of
 * tests attempted.
 */
static int tls_split_read(BIO *bio, char *out, int outl)
{
    int ret;
    BIO *next = BIO_next(bio), *rbio = NULL;
    ROUTE2BE *rbe = NULL;
    SPLIT_MARKER *position = NULL;

    if ((rbe = (ROUTE2BE *)BIO_get_ex_data(bio, 1)) == NULL)
        goto end;
    if ((position = (SPLIT_MARKER *)BIO_get_ex_data(bio, 2)) == NULL)
        goto end;
    if (verbose)
        TEST_info("calling tls_split_read from %s (%d octets)",
                  *position == SPLIT_FE ? "front-end" : "backend",
                  outl);
    if (rbe->ech_mode == SPLIT_FWD && *position == SPLIT_BE) {
        rbio = SSL_get_rbio(rbe->fe_ssl);
        if (rbio == NULL)
            goto end;
        ret = BIO_read(next, out, outl);
        if (ret > 0) {
            ret = BIO_write(rbio, out, outl);
        }
        copy_flags(bio);
        return ret;
    }
    if (rbe->ech_mode == SPLIT_FWD && *position == SPLIT_FE) {
        rbio = SSL_get_rbio(rbe->be_ssl);
        if (rbio == NULL)
            goto end;
        ret = BIO_read(next, out, outl);
        if (ret > 0) {
            ret = BIO_write(rbio, out, outl);
        }
        copy_flags(bio);
        return ret;
    }

end:
    ret = BIO_read(next, out, outl);
    copy_flags(bio);
    return ret;
}
# endif

/*
 * This and others below are NOOP filters as we only mess
 * with things via the write filter method
 */
static int tls_noop_read(BIO *bio, char *out, int outl)
{
    int ret;
    BIO *next = BIO_next(bio);
    ROUTE2BE *rbe = NULL;
    SPLIT_MARKER *position = NULL;

    if ((rbe = (ROUTE2BE *)BIO_get_ex_data(bio, 1)) == NULL)
        goto end;
    if ((position = (SPLIT_MARKER *)BIO_get_ex_data(bio, 2)) == NULL)
        goto end;
    if (verbose)
        TEST_info("calling tls_noop_read from %s (%d octets)",
                  *position == SPLIT_FE ? "front-end" : "backend",
                  outl);

end:
    ret = BIO_read(next, out, outl);
    copy_flags(bio);

    return ret;
}

static long tls_noop_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret;
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    switch (cmd) {
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;
    }
    return ret;
}

static int tls_noop_gets(BIO *bio, char *buf, int size)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_noop_puts(BIO *bio, const char *str)
{
    /* We don't support this - not needed anyway */
    return -1;
}

static int tls_noop_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int tls_noop_free(BIO *bio)
{
    BIO_set_init(bio, 0);

    return 1;
}

# define BIO_TYPE_CUSTOM_SPLIT (0x80 | BIO_TYPE_FILTER)

static BIO_METHOD *method_split_mode = NULL;

/* Note: Not thread safe! */
static const BIO_METHOD *bio_f_tls_split_mode(void)
{
    if (method_split_mode == NULL) {
        method_split_mode = BIO_meth_new(BIO_TYPE_CUSTOM_SPLIT,
                                         "TLS ECH split-mode filter");
        if (method_split_mode == NULL
            || !BIO_meth_set_write(method_split_mode, tls_split_write)
            || !BIO_meth_set_read(method_split_mode, tls_noop_read)
            || !BIO_meth_set_puts(method_split_mode, tls_noop_puts)
            || !BIO_meth_set_gets(method_split_mode, tls_noop_gets)
            || !BIO_meth_set_ctrl(method_split_mode, tls_noop_ctrl)
            || !BIO_meth_set_create(method_split_mode, tls_noop_new)
            || !BIO_meth_set_destroy(method_split_mode, tls_noop_free))
            return NULL;
    }
    return method_split_mode;
}

static void bio_f_tls_split_mode_free(void)
{
    BIO_meth_free(method_split_mode);
}

/*
 * Modified from test/helpers/ssltestlib.c to add in the 3rd
 * (backend) server.
 * Create an SSL connection, but does not read any post-handshake
 * NewSessionTicket messages.
 * If |read| is set and we're using DTLS then we will attempt to SSL_read on
 * the connection once we've completed one half of it, to ensure any retransmits
 * get triggered.
 * We stop the connection attempt (and return a failure value) if either peer
 * has SSL_get_error() return the value in the |want| parameter. The connection
 * attempt could be restarted by a subsequent call to this function.
 */
static int create_3way_ssl_connection(SSL *serverssl, SSL *fe_ssl,
                                      SSL *clientssl, int want)
{
    int retc = -1, rets = -1, ret_fe = -1, err, abortctr = 0, ret = 0;
    int clienterr = 0, servererr = 0, fe_err = 0;
    int i;
    unsigned char buf;
    size_t readbytes;

    do {
        err = SSL_ERROR_WANT_WRITE;
        while (!clienterr && retc <= 0 && err == SSL_ERROR_WANT_WRITE) {
            retc = SSL_connect(clientssl);
            if (retc <= 0)
                err = SSL_get_error(clientssl, retc);
        }

        if (!clienterr && retc <= 0 && err != SSL_ERROR_WANT_READ) {
            TEST_info("SSL_connect() failed %d, %d", retc, err);
            if (want != SSL_ERROR_SSL)
                TEST_openssl_errors();
            clienterr = 1;
        }
        if (want != SSL_ERROR_NONE && err == want)
            goto err;

        err = SSL_ERROR_WANT_WRITE;
        while (!fe_err && ret_fe <= 0 && err == SSL_ERROR_WANT_WRITE) {
            ret_fe = SSL_accept(fe_ssl);
            if (ret_fe <= 0)
                err = SSL_get_error(fe_ssl, ret_fe);
        }
        err = SSL_ERROR_WANT_WRITE;
        while (!servererr && rets <= 0 && err == SSL_ERROR_WANT_WRITE) {
            rets = SSL_accept(serverssl);
            if (rets <= 0)
                err = SSL_get_error(serverssl, rets);
        }

        if (!servererr && !fe_err && rets <= 0 && ret_fe <= 0
                && err != SSL_ERROR_WANT_READ
                && err != SSL_ERROR_WANT_X509_LOOKUP) {
            TEST_info("SSL_accept() failed %d, %d, %d", rets, ret_fe, err);
            if (want != SSL_ERROR_SSL)
                TEST_openssl_errors();
            if (rets <= 0)
                servererr = 1;
            if (ret_fe <= 0)
                fe_err = 1;
        }
        if (want != SSL_ERROR_NONE && err == want)
            goto err;
        if (clienterr && (servererr || fe_err))
            goto err;
        if (++abortctr == MAXLOOPS) {
            TEST_info("No progress made");
            goto err;
        }
    } while (retc <= 0 || (rets <= 0 && ret_fe <= 0));

    /*
     * We attempt to read some data on the client side which we expect to fail.
     * This will ensure we have received the NewSessionTicket in TLSv1.3 where
     * appropriate. We do this twice because there are 2 NewSessionTickets.
     */
    for (i = 0; i < 2; i++) {
        if (SSL_read_ex(clientssl, &buf, sizeof(buf), &readbytes) > 0) {
            if (!TEST_ulong_eq(readbytes, 0))
                goto err;
        } else if (!TEST_int_eq(SSL_get_error(clientssl, 0),
                                SSL_ERROR_WANT_READ)) {
            goto err;
        }
    }
    ret = 1;
 err:
    return ret;
}
/*
 * Split-mode test: Client sends to server but we use filters
 * to do a raw decrypt then re-inject the decrytped inner for
 * the server.
 */
static int ech_split_mode(int idx)
{
    int res = 0, three_rv = 0;
    SSL_CTX *cctx = NULL, *fe_ctx = NULL, *sctx = NULL, *dummy = NULL;
    SSL *clientssl = NULL, *fe_ssl = NULL, *serverssl = NULL;
    int clientstatus, fe_status, serverstatus;
    char *cinner = NULL, *couter = NULL, *sinner = NULL, *souter = NULL;
    char *fe_inner = NULL, *fe_outer = NULL;
    BIO *c_to_s_fbio = NULL, *s_to_c_fbio = NULL;
    BIO *c_to_s_bio = NULL, *s_to_c_bio = NULL;
    ROUTE2BE *rbe = NULL;
    SPLIT_MARKER fe_marker = SPLIT_FE, be_marker = SPLIT_BE;
    SPLIT_TESTCASE *st = NULL;
    size_t written = 0, readbytes = 0;
    unsigned char ed[21], buf[1024];
    SSL_SESSION *sess = NULL;

    st = &testcases[idx];

    if (verbose)
        TEST_info("Running %s", st->descrip);

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &fe_ctx, &cctx, fe_cert, fe_privkey)))
        goto end;

    if (st->bitmask & SPLIT_EARLY) {
        /* just to keep the format checker happy :-) */
        int lrv = 0;

        if (!TEST_true(SSL_CTX_set_options(fe_ctx, SSL_OP_NO_ANTI_REPLAY)))
            goto end;
        if (!TEST_true(SSL_CTX_set_max_early_data(fe_ctx,
                                                  SSL3_RT_MAX_PLAIN_LENGTH)))
            goto end;
        lrv = SSL_CTX_set_recv_max_early_data(fe_ctx, SSL3_RT_MAX_PLAIN_LENGTH);
        if (!TEST_true(lrv))
            goto end;
    }

    if (!TEST_true(SSL_CTX_ech_server_enable_file(fe_ctx, echkeyfile,
                                                  SSL_ECH_USE_FOR_RETRY)))
        goto end;
    /* use this for code re-use but throw away dummy client ctx */
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &dummy, be_cert, be_privkey)))
        goto end;
    SSL_CTX_free(dummy);
    dummy = NULL;

    if (st->bitmask & SPLIT_EARLY) {
        /* just to keep the format checker happy :-) */
        int lrv = 0;

        if (!TEST_true(SSL_CTX_set_options(sctx, SSL_OP_NO_ANTI_REPLAY)))
            goto end;
        if (!TEST_true(SSL_CTX_set_max_early_data(sctx,
                                                  SSL3_RT_MAX_PLAIN_LENGTH)))
            goto end;
        lrv = SSL_CTX_set_recv_max_early_data(sctx, SSL3_RT_MAX_PLAIN_LENGTH);
        if (!TEST_true(lrv))
            goto end;
    }
    if (st->bitmask & SPLIT_GREASE) {
        if (!TEST_true(SSL_CTX_set_options(cctx, SSL_OP_ECH_GREASE)))
            goto end;
    } else {
        if (!TEST_true(SSL_CTX_ech_set1_echconfig(cctx,
                                                  (unsigned char *)echconfig,
                                                  echconfiglen)))
            goto end;
    }
    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_split_mode())))
        goto end;
    if (!TEST_ptr(s_to_c_fbio = BIO_new(bio_f_tls_split_mode())))
        goto end;
    if (!TEST_true(create_ssl_objects(fe_ctx, cctx, &fe_ssl,
                                      &clientssl, NULL, c_to_s_fbio)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    /* setup backend server */
    if (!TEST_ptr(serverssl = SSL_new(sctx)))
        goto end;
    if (!TEST_ptr(s_to_c_bio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(s_to_c_bio = BIO_push(s_to_c_fbio, s_to_c_bio)))
        goto end;
    if (!TEST_ptr(c_to_s_bio = BIO_new(BIO_s_mem())))
        goto end;
    BIO_set_mem_eof_return(s_to_c_bio, -1);
    BIO_set_mem_eof_return(c_to_s_bio, -1);
    SSL_set_bio(serverssl, c_to_s_bio, s_to_c_bio);
    BIO_up_ref(s_to_c_bio);
    BIO_up_ref(c_to_s_bio);
    if (!TEST_ptr((rbe = (ROUTE2BE *)OPENSSL_malloc(sizeof(ROUTE2BE)))))
        goto end;
    rbe->ech_mode = SPLIT_LOCAL;
    rbe->cli_ssl = clientssl;
    rbe->be_ssl = serverssl;
    rbe->fe_ssl = fe_ssl;
    rbe->fe_ctx = fe_ctx;
    rbe->hrrtok = NULL;
    rbe->toklen = 0;
    if (!TEST_true(BIO_set_ex_data(c_to_s_fbio, 1, rbe)))
        goto end;
    if (!TEST_true(BIO_set_ex_data(c_to_s_fbio, 2, &fe_marker)))
        goto end;
    if (!TEST_true(BIO_set_ex_data(s_to_c_fbio, 1, rbe)))
        goto end;
    if (!TEST_true(BIO_set_ex_data(s_to_c_fbio, 2, &be_marker)))
        goto end;
    if (st->bitmask & SPLIT_HRR) {
        if (!TEST_true(SSL_set1_groups_list(serverssl, "P-384")))
            goto end;
    }

    three_rv = create_3way_ssl_connection(serverssl, fe_ssl, clientssl,
                                          st->exp_err);
    if (!TEST_int_eq(three_rv, st->exp_rv))
        goto end;
    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, st->exp_be_status))
        goto end;
    fe_status = SSL_ech_get_status(fe_ssl, &fe_inner, &fe_outer);
    if (verbose)
        TEST_info("fe_server status %d, %s, %s",
                  fe_status, fe_inner, fe_outer);
    if (!TEST_int_eq(fe_status, st->exp_fe_status))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, st->exp_cli_status))
        goto end;

    if (!(st->bitmask & SPLIT_EARLY)) {
        res = 1; /* we're done */
        goto end;
    }

    /* do 2nd session with early data */
    if (verbose)
        TEST_info("Storing session");
    sess = SSL_get1_session(clientssl);

    OPENSSL_free(rbe->hrrtok);
    rbe->hrrtok = NULL;
    rbe->toklen = 0;
    OPENSSL_free(fe_inner);
    OPENSSL_free(fe_outer);
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    fe_inner = fe_outer = sinner = souter = cinner = couter = NULL;
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_free(fe_ssl);
    serverssl = clientssl = fe_ssl = NULL;
    BIO_free_all(c_to_s_bio);
    BIO_free_all(s_to_c_bio);
    c_to_s_bio = s_to_c_bio = NULL;
    c_to_s_fbio = s_to_c_fbio = NULL;
    OPENSSL_free(rbe);

    memset(ed, 'A', sizeof(ed));

    if (!TEST_ptr(c_to_s_fbio = BIO_new(bio_f_tls_split_mode())))
        goto end;
    if (!TEST_ptr(s_to_c_fbio = BIO_new(bio_f_tls_split_mode())))
        goto end;
    if (!TEST_true(create_ssl_objects(fe_ctx, cctx, &fe_ssl,
                                      &clientssl, NULL, c_to_s_fbio)))
        goto end;
    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    /* setup backend server */
    if (!TEST_ptr(serverssl = SSL_new(sctx)))
        goto end;
    if (!TEST_ptr(s_to_c_bio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(s_to_c_bio = BIO_push(s_to_c_fbio, s_to_c_bio)))
        goto end;
    if (!TEST_ptr(c_to_s_bio = BIO_new(BIO_s_mem())))
        goto end;
    BIO_set_mem_eof_return(s_to_c_bio, -1);
    BIO_set_mem_eof_return(c_to_s_bio, -1);
    SSL_set_bio(serverssl, c_to_s_bio, s_to_c_bio);
    BIO_up_ref(s_to_c_bio);
    BIO_up_ref(c_to_s_bio);
    if (!TEST_ptr((rbe = (ROUTE2BE *)OPENSSL_malloc(sizeof(ROUTE2BE)))))
        goto end;
    rbe->ech_mode = SPLIT_LOCAL;
    rbe->cli_ssl = clientssl;
    rbe->be_ssl = serverssl;
    rbe->fe_ssl = fe_ssl;
    rbe->fe_ctx = fe_ctx;
    rbe->hrrtok = NULL;
    rbe->toklen = 0;
    if (!TEST_true(BIO_set_ex_data(c_to_s_fbio, 1, rbe)))
        goto end;
    if (!TEST_true(BIO_set_ex_data(c_to_s_fbio, 2, &fe_marker)))
        goto end;
    if (!TEST_true(BIO_set_ex_data(s_to_c_fbio, 1, rbe)))
        goto end;
    if (!TEST_true(BIO_set_ex_data(s_to_c_fbio, 2, &be_marker)))
        goto end;
    if (st->bitmask & SPLIT_HRR) {
        if (!TEST_true(SSL_set1_groups_list(serverssl, "P-384")))
            goto end;
    }

    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example")))
        goto end;
    if (!TEST_true(SSL_set_session(clientssl, sess)))
        goto end;
    if (st->bitmask & SPLIT_EARLY) {
        if (!TEST_true(SSL_write_early_data(clientssl, ed, sizeof(ed),
                                            &written)))
            goto end;
        if (!TEST_size_t_eq(written, sizeof(ed)))
            goto end;

    }
    if ((st->bitmask & SPLIT_EARLY) && !(st->bitmask & SPLIT_HRR)) {
        if (!TEST_int_eq(SSL_read_early_data(serverssl, buf,
                                             sizeof(buf), &readbytes),
                         SSL_READ_EARLY_DATA_SUCCESS))
            goto end;
        if (!TEST_size_t_eq(written, readbytes))
            goto end;
        /*
         * Server should be able to write data, and client should be able to
         * read it.
         */
        if (!TEST_true(SSL_write_early_data(serverssl, ed, sizeof(ed),
                                            &written))
                || !TEST_size_t_eq(written, sizeof(ed))
                || !TEST_true(SSL_read_ex(clientssl, buf, sizeof(buf),
                                          &readbytes))
                || !TEST_mem_eq(buf, readbytes, ed, sizeof(ed)))
            goto end;
    } else if ((st->bitmask & SPLIT_EARLY) && (st->bitmask & SPLIT_HRR)) {
        if (!TEST_int_eq(SSL_read_early_data(serverssl, buf,
                                             sizeof(buf), &readbytes),
                         SSL_READ_EARLY_DATA_FINISH))
            goto end;
    }

    three_rv = create_3way_ssl_connection(serverssl, fe_ssl, clientssl,
                                          st->exp_err);
    if (!TEST_int_eq(three_rv, st->exp_rv))
        goto end;

    serverstatus = SSL_ech_get_status(serverssl, &sinner, &souter);
    if (verbose)
        TEST_info("server status %d, %s, %s",
                  serverstatus, sinner, souter);
    if (!TEST_int_eq(serverstatus, st->exp_be_status))
        goto end;
    fe_status = SSL_ech_get_status(fe_ssl, &fe_inner, &fe_outer);
    if (verbose)
        TEST_info("fe_server status %d, %s, %s",
                  fe_status, fe_inner, fe_outer);
    if (!TEST_int_eq(fe_status, st->exp_fe_status))
        goto end;
    /* override cert verification */
    SSL_set_verify_result(clientssl, X509_V_OK);
    clientstatus = SSL_ech_get_status(clientssl, &cinner, &couter);
    if (verbose)
        TEST_info("client status %d, %s, %s",
                  clientstatus, cinner, couter);
    if (!TEST_int_eq(clientstatus, st->exp_cli_status))
        goto end;

    /* all good */
    res = 1;
end:
    SSL_SESSION_free(sess);
    OPENSSL_free(rbe->hrrtok);
    OPENSSL_free(rbe);
    BIO_free_all(c_to_s_bio);
    BIO_free_all(s_to_c_bio);
    OPENSSL_free(fe_inner);
    OPENSSL_free(fe_outer);
    OPENSSL_free(sinner);
    OPENSSL_free(souter);
    OPENSSL_free(cinner);
    OPENSSL_free(couter);
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_free(fe_ssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    SSL_CTX_free(fe_ctx);
    SSL_CTX_free(dummy);
    return res;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run ECH Corruption tests\n" },
        { NULL }
    };
    return test_options;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    certsdir = test_get_argument(0);
    if (certsdir == NULL)
        certsdir = DEF_CERTS_DIR;
    be_cert = test_mk_file_path(certsdir, "servercert.pem");
    if (be_cert == NULL)
        goto err;
    be_privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (be_privkey == NULL)
        goto err;
    fe_cert = test_mk_file_path(certsdir, "fe_cert.pem");
    if (fe_cert == NULL)
        goto err;
    fe_privkey = test_mk_file_path(certsdir, "fe_key.pem");
    if (fe_privkey == NULL)
        goto err;
    /* read our pre-cooked ECH PEM file */
    echkeyfile = test_mk_file_path(certsdir, "echconfig.pem");
    if (!TEST_ptr(echkeyfile))
        goto err;
    echconfig = echconfiglist_from_PEM(echkeyfile);
    if (!TEST_ptr(echconfig))
        goto err;
    echconfiglen = strlen(echconfig);
    bin_echconfiglen = ech_helper_base64_decode(echconfig, echconfiglen,
                                                &bin_echconfig);
    ADD_ALL_TESTS(ech_split_mode, OSSL_NELEM(testcases));
    return 1;
err:
    return 0;
#else
    return 1;
#endif
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ECH
    bio_f_tls_split_mode_free();
    OPENSSL_free(be_cert);
    OPENSSL_free(be_privkey);
    OPENSSL_free(fe_cert);
    OPENSSL_free(fe_privkey);
    OPENSSL_free(echkeyfile);
    OPENSSL_free(echconfig);
    OPENSSL_free(bin_echconfig);
#endif
}
