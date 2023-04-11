/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_TSERVER_H
# define OSSL_QUIC_TSERVER_H

# include <openssl/ssl.h>
# include <openssl/bio.h>
# include "internal/quic_stream.h"
# include "internal/quic_channel.h"
# include "internal/statem.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Test Server Module
 * =======================
 *
 * This implements a QUIC test server. Since full QUIC server support is not yet
 * implemented this server is limited in features and scope. It exists to
 * provide a target for our QUIC client to talk to for testing purposes.
 *
 * A given QUIC test server instance supports only one client at a time.
 *
 * Note that this test server is not suitable for production use because it does
 * not implement address verification, anti-amplification or retry logic.
 */
typedef struct quic_tserver_st QUIC_TSERVER;

typedef struct quic_tserver_args_st {
    OSSL_LIB_CTX *libctx;
    const char *propq;
    BIO *net_rbio, *net_wbio;
    OSSL_TIME (*now_cb)(void *arg);
    void *now_cb_arg;
} QUIC_TSERVER_ARGS;

QUIC_TSERVER *ossl_quic_tserver_new(const QUIC_TSERVER_ARGS *args,
                                    const char *certfile, const char *keyfile);

void ossl_quic_tserver_free(QUIC_TSERVER *srv);

/* Set mutator callbacks for test framework support */
int ossl_quic_tserver_set_plain_packet_mutator(QUIC_TSERVER *srv,
                                               ossl_mutate_packet_cb mutatecb,
                                               ossl_finish_mutate_cb finishmutatecb,
                                               void *mutatearg);

int ossl_quic_tserver_set_handshake_mutator(QUIC_TSERVER *srv,
                                            ossl_statem_mutate_handshake_cb mutate_handshake_cb,
                                            ossl_statem_finish_mutate_handshake_cb finish_mutate_handshake_cb,
                                            void *mutatearg);

/* Advances the state machine. */
int ossl_quic_tserver_tick(QUIC_TSERVER *srv);

/* Returns 1 if we have a (non-terminated) client. */
int ossl_quic_tserver_is_connected(QUIC_TSERVER *srv);

/*
 * Returns 1 if we have finished the TLS handshake
 */
int ossl_quic_tserver_is_handshake_confirmed(const QUIC_TSERVER *srv);

/* Returns 1 if the server is in any terminating or terminated state */
int ossl_quic_tserver_is_term_any(const QUIC_TSERVER *srv);

QUIC_TERMINATE_CAUSE ossl_quic_tserver_get_terminate_cause(const QUIC_TSERVER *srv);

/* Returns 1 if the server is in a terminated state */
int ossl_quic_tserver_is_terminated(const QUIC_TSERVER *srv);

/*
 * Attempts to read from stream 0. Writes the number of bytes read to
 * *bytes_read and returns 1 on success. If no bytes are available, 0 is written
 * to *bytes_read and 1 is returned (this is considered a success case).
 *
 * Returns 0 if connection is not currently active. If the receive part of
 * the stream has reached the end of stream condition, returns 0; call
 * ossl_quic_tserver_has_read_ended() to identify this condition.
 */
int ossl_quic_tserver_read(QUIC_TSERVER *srv,
                           unsigned char *buf,
                           size_t buf_len,
                           size_t *bytes_read);

/*
 * Returns 1 if the read part of the stream has ended normally.
 */
int ossl_quic_tserver_has_read_ended(QUIC_TSERVER *srv);

/*
 * Attempts to write to stream 0. Writes the number of bytes consumed to
 * *bytes_written and returns 1 on success. If there is no space currently
 * available to write any bytes, 0 is written to *consumed and 1 is returned
 * (this is considered a success case).
 *
 * Note that unlike libssl public APIs, this API always works in a 'partial
 * write' mode.
 *
 * Returns 0 if connection is not currently active.
 */
int ossl_quic_tserver_write(QUIC_TSERVER *srv,
                            const unsigned char *buf,
                            size_t buf_len,
                            size_t *bytes_written);

/*
 * Signals normal end of the stream.
 */
int ossl_quic_tserver_conclude(QUIC_TSERVER *srv);

BIO *ossl_quic_tserver_get0_rbio(QUIC_TSERVER *srv);

# endif

#endif
