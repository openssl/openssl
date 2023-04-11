/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_TXP_H
# define OSSL_QUIC_TXP_H

# include <openssl/ssl.h>
# include "internal/quic_types.h"
# include "internal/quic_record_tx.h"
# include "internal/quic_cfq.h"
# include "internal/quic_txpim.h"
# include "internal/quic_stream.h"
# include "internal/quic_stream_map.h"
# include "internal/quic_fc.h"
# include "internal/bio_addr.h"
# include "internal/time.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC TX Packetiser
 * ==================
 */
typedef struct ossl_quic_tx_packetiser_args_st {
    /* Configuration Settings */
    QUIC_CONN_ID    cur_scid;   /* Current Source Connection ID we use. */
    QUIC_CONN_ID    cur_dcid;   /* Current Destination Connection ID we use. */
    BIO_ADDR        peer;       /* Current destination L4 address we use. */
    uint32_t        ack_delay_exponent; /* ACK delay exponent used when encoding. */

    /* Injected Dependencies */
    OSSL_QTX        *qtx;       /* QUIC Record Layer TX we are using */
    QUIC_TXPIM      *txpim;     /* QUIC TX'd Packet Information Manager */
    QUIC_CFQ        *cfq;       /* QUIC Control Frame Queue */
    OSSL_ACKM       *ackm;      /* QUIC Acknowledgement Manager */
    QUIC_STREAM_MAP *qsm;       /* QUIC Streams Map */
    QUIC_TXFC       *conn_txfc; /* QUIC Connection-Level TX Flow Controller */
    QUIC_RXFC       *conn_rxfc; /* QUIC Connection-Level RX Flow Controller */
    const OSSL_CC_METHOD *cc_method; /* QUIC Congestion Controller */
    OSSL_CC_DATA    *cc_data;   /* QUIC Congestion Controller Instance */
    OSSL_TIME       (*now)(void *arg);  /* Callback to get current time. */
    void            *now_arg;

    /*
     * Injected dependencies - crypto streams.
     *
     * Note: There is no crypto stream for the 0-RTT EL.
     *       crypto[QUIC_PN_SPACE_APP] is the 1-RTT crypto stream.
     */
    QUIC_SSTREAM    *crypto[QUIC_PN_SPACE_NUM];
} OSSL_QUIC_TX_PACKETISER_ARGS;

typedef struct ossl_quic_tx_packetiser_st OSSL_QUIC_TX_PACKETISER;

OSSL_QUIC_TX_PACKETISER *ossl_quic_tx_packetiser_new(const OSSL_QUIC_TX_PACKETISER_ARGS *args);

typedef void (ossl_quic_initial_token_free_fn)(const unsigned char *buf,
                                               size_t buf_len, void *arg);

void ossl_quic_tx_packetiser_free(OSSL_QUIC_TX_PACKETISER *txp);

/* Generate normal packets containing most frame types. */
#define TX_PACKETISER_ARCHETYPE_NORMAL      0
/* Generate ACKs only. */
#define TX_PACKETISER_ARCHETYPE_ACK_ONLY    1
#define TX_PACKETISER_ARCHETYPE_NUM         2

/*
 * Generates a datagram by polling the various ELs to determine if they want to
 * generate any frames, and generating a datagram which coalesces packets for
 * any ELs which do.
 *
 * archetype is a TX_PACKETISER_ARCHETYPE_* value.
 *
 * Returns TX_PACKETISER_RES_FAILURE on failure (e.g. allocation error),
 * TX_PACKETISER_RES_NO_PKT if no packets were sent (e.g. because nothing wants
 * to send anything), and TX_PACKETISER_RES_SENT_PKT if packets were sent.
 *
 * If an ACK-eliciting packet was sent, 1 is written to *sent_ack_eliciting,
 * otherwise *sent_ack_eliciting is unchanged.
 */
#define TX_PACKETISER_RES_FAILURE   0
#define TX_PACKETISER_RES_NO_PKT    1
#define TX_PACKETISER_RES_SENT_PKT  2
int ossl_quic_tx_packetiser_generate(OSSL_QUIC_TX_PACKETISER *txp,
                                     uint32_t archetype,
                                     int *sent_ack_eliciting);

/*
 * Returns 1 if one or more packets would be generated if
 * ossl_quic_tx_packetiser_generate were called.
 *
 * If TX_PACKETISER_BYPASS_CC is set in flags, congestion control is
 * ignored for the purposes of making this determination.
 */
#define TX_PACKETISER_BYPASS_CC   (1U << 0)

int ossl_quic_tx_packetiser_has_pending(OSSL_QUIC_TX_PACKETISER *txp,
                                        uint32_t archetype,
                                        uint32_t flags);

/*
 * Set the token used in Initial packets. The callback is called when the buffer
 * is no longer needed; for example, when the TXP is freed or when this function
 * is called again with a new buffer.
 */
void ossl_quic_tx_packetiser_set_initial_token(OSSL_QUIC_TX_PACKETISER *txp,
                                               const unsigned char *token,
                                               size_t token_len,
                                               ossl_quic_initial_token_free_fn *free_cb,
                                               void *free_cb_arg);

/* Change the DCID the TXP uses to send outgoing packets. */
int ossl_quic_tx_packetiser_set_cur_dcid(OSSL_QUIC_TX_PACKETISER *txp,
                                         const QUIC_CONN_ID *dcid);

/* Change the SCID the TXP uses to send outgoing (long) packets. */
int ossl_quic_tx_packetiser_set_cur_scid(OSSL_QUIC_TX_PACKETISER *txp,
                                         const QUIC_CONN_ID *scid);

/* Change the destination L4 address the TXP uses to send datagrams. */
int ossl_quic_tx_packetiser_set_peer(OSSL_QUIC_TX_PACKETISER *txp,
                                     const BIO_ADDR *peer);

/*
 * Inform the TX packetiser that an EL has been discarded. Idempotent.
 *
 * This does not inform the QTX as well; the caller must also inform the QTX.
 *
 * The TXP will no longer reference the crypto[enc_level] QUIC_SSTREAM which was
 * provided in the TXP arguments. However, it is the callers responsibility to
 * free that QUIC_SSTREAM if desired.
 */
int ossl_quic_tx_packetiser_discard_enc_level(OSSL_QUIC_TX_PACKETISER *txp,
                                              uint32_t enc_level);

/*
 * Informs the TX packetiser that the handshake is complete. The TX packetiser
 * will not send 1-RTT application data until the handshake is complete,
 * as the authenticity of the peer is not confirmed until the handshake
 * complete event occurs.
 */
void ossl_quic_tx_packetiser_notify_handshake_complete(OSSL_QUIC_TX_PACKETISER *txp);

/* Asks the TXP to generate a HANDSHAKE_DONE frame in the next 1-RTT packet. */
void ossl_quic_tx_packetiser_schedule_handshake_done(OSSL_QUIC_TX_PACKETISER *txp);

/* Asks the TXP to ensure the next packet in the given PN space is ACK-eliciting. */
void ossl_quic_tx_packetiser_schedule_ack_eliciting(OSSL_QUIC_TX_PACKETISER *txp,
                                                    uint32_t pn_space);

/*
 * Schedules a connection close. *f and f->reason are copied. This operation is
 * irreversible and causes all further packets generated by the TXP to contain a
 * CONNECTION_CLOSE frame. This function fails if it has already been called
 * successfully; the information in *f cannot be changed after the first
 * successful call to this function.
 */
int ossl_quic_tx_packetiser_schedule_conn_close(OSSL_QUIC_TX_PACKETISER *txp,
                                                const OSSL_QUIC_FRAME_CONN_CLOSE *f);

# endif

#endif
