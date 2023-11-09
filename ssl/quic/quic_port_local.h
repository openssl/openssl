#ifndef OSSL_QUIC_PORT_LOCAL_H
# define OSSL_QUIC_PORT_LOCAL_H

# include "internal/quic_port.h"
# include "internal/quic_reactor.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Port Structure
 * ===================
 *
 * QUIC port internals. It is intended that only the QUIC_PORT and QUIC_CHANNEL
 * implementation be allowed to access this structure directly.
 *
 * Other components should not include this header.
 */
struct quic_port_st {
    OSSL_LIB_CTX                    *libctx;
    const char                      *propq;

    /* Mutex for the entire QUIC event domain. */
    CRYPTO_MUTEX                    *mutex;

    /* Callback used to get the current time. */
    OSSL_TIME                       (*now_cb)(void *arg);
    void                            *now_cb_arg;

    /* Asynchronous I/O reactor. */
    QUIC_REACTOR                    rtor;

    /* Network-side read and write BIOs. */
    BIO                             *net_rbio, *net_wbio;

    /* RX demuxer. We register incoming DCIDs with this. */
    QUIC_DEMUX                      *demux;
};

# endif

#endif
