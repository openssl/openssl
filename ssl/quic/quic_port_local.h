#ifndef OSSL_QUIC_PORT_LOCAL_H
# define OSSL_QUIC_PORT_LOCAL_H

# include "internal/quic_port.h"
# include "internal/quic_reactor.h"
# include "internal/list.h"

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
DECLARE_LIST_OF(ch, QUIC_CHANNEL);

struct quic_port_st {
    OSSL_LIB_CTX                    *libctx;
    const char                      *propq;

    /*
     * Master synchronisation mutex for the entire QUIC event domain. Used for
     * thread assisted mode synchronisation. We don't own this; the instantiator
     * of the port passes it to us and is responsible for freeing it after port
     * destruction.
     */
    CRYPTO_MUTEX                    *mutex;

    /* Callback used to get the current time. */
    OSSL_TIME                       (*now_cb)(void *arg);
    void                            *now_cb_arg;

    /* Used to create handshake layer objects inside newly created channels. */
    SSL_CTX                         *channel_ctx;

    /* Asynchronous I/O reactor. */
    QUIC_REACTOR                    rtor;

    /* Network-side read and write BIOs. */
    BIO                             *net_rbio, *net_wbio;

    /* RX demuxer. We register incoming DCIDs with this. */
    QUIC_DEMUX                      *demux;

    /* List of all child channels. */
    OSSL_LIST(ch)                   channel_list;

    /* Special TSERVER channel. To be removed in the future. */
    QUIC_CHANNEL                    *tserver_ch;

    /* LCIDM used for incoming packet routing by DCID. */
    QUIC_LCIDM                      *lcidm;

    /* SRTM used for incoming packet routing by SRT. */
    QUIC_SRTM                       *srtm;

    /* DCID length used for incoming short header packets. */
    unsigned char                   rx_short_dcid_len;
    /* For clients, CID length used for outgoing Initial packets. */
    unsigned char                   tx_init_dcid_len;

    /* Is this port created to support multiple connections? */
    unsigned int                    is_multi_conn                   : 1;

    /* Inhibit tick for testing purposes? */
    unsigned int                    inhibit_tick                    : 1;
};

# endif

#endif
