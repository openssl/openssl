/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_CHANNEL_H
# define OSSL_QUIC_CHANNEL_H

# include <openssl/ssl.h>
# include "internal/quic_types.h"
# include "internal/quic_stream_map.h"
# include "internal/quic_reactor.h"
# include "internal/quic_statm.h"
# include "internal/time.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Channel
 * ============
 *
 * A QUIC channel (QUIC_CHANNEL) is an object which binds together all of the
 * various pieces of QUIC into a single top-level object, and handles connection
 * state which is not specific to the client or server roles. In particular, it
 * is strictly separated from the libssl front end I/O API personality layer,
 * and is not an SSL object.
 *
 * The name QUIC_CHANNEL is chosen because QUIC_CONNECTION is already in use,
 * but functionally these relate to the same thing (a QUIC connection). The use
 * of two separate objects ensures clean separation between the API personality
 * layer and common code for handling connections, and between the functionality
 * which is specific to clients and which is specific to servers, and the
 * functionality which is common to both.
 *
 * The API personality layer provides SSL objects (e.g. a QUIC_CONNECTION) which
 * consume a QUIC channel and implement a specific public API. Things which are
 * handled by the API personality layer include emulation of blocking semantics,
 * handling of SSL object mode flags like non-partial write mode, etc.
 *
 * Where the QUIC_CHANNEL is used in a server role, there is one QUIC_CHANNEL
 * per connection. In the future a QUIC Channel Manager will probably be defined
 * to handle ownership of resources which are shared between connections (e.g.
 * demuxers). Since we only use server-side functionality for dummy test servers
 * for now, which only need to handle one connection at a time, this is not
 * currently modelled.
 */

#  define QUIC_CHANNEL_STATE_IDLE                        0
#  define QUIC_CHANNEL_STATE_ACTIVE                      1
#  define QUIC_CHANNEL_STATE_TERMINATING_CLOSING         2
#  define QUIC_CHANNEL_STATE_TERMINATING_DRAINING        3
#  define QUIC_CHANNEL_STATE_TERMINATED                  4

typedef struct quic_channel_args_st {
    OSSL_LIB_CTX *libctx;
    const char *propq;
    int is_server;
} QUIC_CHANNEL_ARGS;

typedef struct quic_channel_st QUIC_CHANNEL;

/*
 * Create a new QUIC channel using the given arguments. The argument structure
 * does not need to remain allocated. Returns NULL on failure.
 */
QUIC_CHANNEL *ossl_quic_channel_new(const QUIC_CHANNEL_ARGS *args);

/* No-op if ch is NULL. */
void ossl_quic_channel_free(QUIC_CHANNEL *ch);

/*
 * Connection Lifecycle Events
 * ===========================
 *
 * Various events that can be raised on the channel by other parts of the QUIC
 * implementation. Some of these are suitable for general use by any part of the
 * code (e.g. ossl_quic_channel_raise_protocol_error), others are for very
 * specific use by particular components only (e.g.
 * ossl_quic_channel_on_handshake_confirmed).
 */

/*
 * To be used by a QUIC connection. Starts the channel. For a client-mode
 * channel, this starts sending the first handshake layer message, etc. Can only
 * be called in the idle state; successive calls are ignored.
 */
int ossl_quic_channel_start(QUIC_CHANNEL *ch);

/* Start a locally initiated connection shutdown. */
void ossl_quic_channel_local_close(QUIC_CHANNEL *ch);

/*
 * Called when the handshake is confirmed.
 */
int ossl_quic_channel_on_handshake_confirmed(QUIC_CHANNEL *ch);

/*
 * Raises a protocol error. This is intended to be the universal call suitable
 * for handling of all peer-triggered protocol violations or errors detected by
 * us. We specify a QUIC transport-scope error code and optional frame type
 * which was responsible. If a frame type is not applicable, specify zero. The
 * reason string is not currently handled, but should be a string of static
 * storage duration. If the connection has already terminated due to a previous
 * protocol error, this is a no-op; first error wins.
 */
void ossl_quic_channel_raise_protocol_error(QUIC_CHANNEL *ch,
                                            uint64_t error_code,
                                            uint64_t frame_type,
                                            const char *reason);

/* For RXDP use. */
void ossl_quic_channel_on_remote_conn_close(QUIC_CHANNEL *ch,
                                            OSSL_QUIC_FRAME_CONN_CLOSE *f);

/*
 * Queries and Accessors
 * =====================
 */

/* Gets the reactor which can be used to tick/poll on the channel. */
QUIC_REACTOR *ossl_quic_channel_get_reactor(QUIC_CHANNEL *ch);

/* Gets the QSM used with the channel. */
QUIC_STREAM_MAP *ossl_quic_channel_get_qsm(QUIC_CHANNEL *ch);

/* Gets the statistics manager used with the channel. */
OSSL_STATM *ossl_quic_channel_get_statm(QUIC_CHANNEL *ch);

/*
 * Gets/sets the current peer address. Generally this should be used before
 * starting a channel in client mode.
 */
int ossl_quic_channel_get_peer_addr(QUIC_CHANNEL *ch, BIO_ADDR *peer_addr);
int ossl_quic_channel_set_peer_addr(QUIC_CHANNEL *ch, const BIO_ADDR *peer_addr);

/* Gets/sets the underlying network read and write BIOs. */
BIO *ossl_quic_channel_get_net_rbio(QUIC_CHANNEL *ch);
BIO *ossl_quic_channel_get_net_wbio(QUIC_CHANNEL *ch);
int ossl_quic_channel_set_net_rbio(QUIC_CHANNEL *ch, BIO *net_rbio);
int ossl_quic_channel_set_net_wbio(QUIC_CHANNEL *ch, BIO *net_wbio);

/*
 * Returns an existing stream by stream ID. Returns NULL if the stream does not
 * exist.
 */
QUIC_STREAM *ossl_quic_channel_get_stream_by_id(QUIC_CHANNEL *ch,
                                                uint64_t stream_id);

/* Returns 1 if channel is terminating or terminated. */
int ossl_quic_channel_is_term_any(const QUIC_CHANNEL *ch);
int ossl_quic_channel_is_terminating(const QUIC_CHANNEL *ch);
int ossl_quic_channel_is_terminated(const QUIC_CHANNEL *ch);
int ossl_quic_channel_is_active(const QUIC_CHANNEL *ch);
int ossl_quic_channel_is_handshake_complete(const QUIC_CHANNEL *ch);

# endif

#endif
