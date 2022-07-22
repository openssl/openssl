/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_RECORD_H
# define OSSL_QUIC_RECORD_H

# include <openssl/ssl.h>
# include "internal/quic_wire_pkt.h"
# include "internal/quic_types.h"
# include "internal/quic_record_util.h"
# include "internal/quic_demux.h"

/*
 * QUIC Record Layer
 * =================
 */
typedef struct ossl_qrl_st OSSL_QRL;

typedef struct ossl_qrl_args_st {
    OSSL_LIB_CTX   *libctx;
    const char     *propq;

    /* Demux to receive datagrams from. */
    QUIC_DEMUX     *rx_demux;

    /* Length of connection IDs used in short-header packets in bytes. */
    size_t          short_conn_id_len;

    /* Initial reference PN used for RX. */
    QUIC_PN         rx_init_largest_pn[QUIC_PN_SPACE_NUM];
} OSSL_QRL_ARGS;

/* Instantiates a new QRL. */
OSSL_QRL *ossl_qrl_new(const OSSL_QRL_ARGS *args);

/*
 * Frees the QRL. All packets obtained using ossl_qrl_read_pkt must already
 * have been released by calling ossl_qrl_release_pkt.
 *
 * You do not need to call ossl_qrl_remove_dst_conn_id first; this function will
 * unregister the QRL from the demuxer for all registered destination connection
 * IDs (DCIDs) automatically.
 */
void ossl_qrl_free(OSSL_QRL *qrl);

/*
 * DCID Management
 * ===============
 */

/*
 * Adds a given DCID to the QRL. The QRL will register the DCID with the demuxer
 * so that incoming packets with that DCID are passed to the given QRL. Multiple
 * DCIDs may be associated with a QRL at any one time. You will need to add at
 * least one DCID after instantiating the QRL. A zero-length DCID is a valid
 * input to this function. This function fails if the DCID is already
 * registered.
 *
 * Returns 1 on success or 0 on error.
 */
int ossl_qrl_add_dst_conn_id(OSSL_QRL *qrl,
                             const QUIC_CONN_ID *dst_conn_id);

/*
 * Remove a DCID previously registered with ossl_qrl_add_dst_conn_id. The DCID
 * is unregistered from the demuxer. Fails if the DCID is not registered with
 * the demuxer.
 *
 * Returns 1 on success or 0 on error.
 */
int ossl_qrl_remove_dst_conn_id(OSSL_QRL *qrl,
                                const QUIC_CONN_ID *dst_conn_id);

/*
 * Secret Management
 * =================
 *
 * A QRL has several encryption levels (Initial, Handshake, 0-RTT, 1-RTT) and
 * two directions (RX, TX). At any given time, key material is managed for each
 * (EL, RX/TX) combination.
 *
 * Broadly, for a given (EL, RX/TX), the following state machine is applicable:
 *
 *   WAITING_FOR_KEYS --[Provide]--> HAVE_KEYS --[Discard]--> | DISCARDED |
 *         \-------------------------------------[Discard]--> |           |
 *
 * To transition the RX side of an EL from WAITING_FOR_KEYS to HAVE_KEYS, call
 * ossl_qrl_provide_rx_secret (or for the INITIAL EL,
 * ossl_qrl_provide_rx_secret_initial).
 *
 * Once keys have been provisioned for an EL, you call
 * ossl_qrl_discard_enc_level to transition the EL to the DISCARDED state. You
 * can also call this function to transition directly to the DISCARDED state
 * even before any keys have been provisioned for that EL.
 *
 * The DISCARDED state is terminal for a given EL; you cannot provide a secret
 * again for that EL after reaching it.
 *
 * Incoming packets cannot be processed and decrypted if they target an EL
 * not in the HAVE_KEYS state. However, there is a distinction between
 * the WAITING_FOR_KEYS and DISCARDED states:
 *
 *   - In the WAITING_FOR_KEYS state, the QRL assumes keys for the given
 *     EL will eventually arrive. Therefore, if it receives any packet
 *     for an EL in this state, it buffers it and tries to process it
 *     again once the EL reaches HAVE_KEYS.
 *
 *   - In the DISCARDED state, the QRL assumes no keys for the given
 *     EL will ever arrive again. If it receives any packet for an EL
 *     in this state, it is simply discarded.
 *
 * If the user wishes to instantiate a new QRL to replace an old one for
 * whatever reason, for example to take over for an already established QUIC
 * connection, it is important that all ELs no longer being used (i.e., INITIAL,
 * 0-RTT, 1-RTT) are transitioned to the DISCARDED state. Otherwise, the QRL
 * will assume that keys for these ELs will arrive in future, and will buffer
 * any received packets for those ELs perpetually. This can be done by calling
 * ossl_qrl_discard_enc_level for all non-1-RTT ELs immediately after
 * instantiating the QRL.
 *
 * The INITIAL EL is not setup automatically when the QRL is instantiated. This
 * allows the caller to instead discard it immediately after instantiation of
 * the QRL if it is not needed, for example if the QRL is being instantiated to
 * take over handling of an existing connection which has already passed the
 * INITIAL phase. This avoids the unnecessary derivation of INITIAL keys where
 * they are not needed. In the ordinary case, ossl_qrl_provide_rx_secret_initial
 * should be called immediately after instantiation.
 */

/*
 * A QUIC client sends its first INITIAL packet with a random DCID, which is
 * used to compute the secret used for INITIAL packet encryption. This function
 * must be called to provide the DCID used for INITIAL packet secret computation
 * before the QRL can process any INITIAL response packets.
 *
 * It is possible to use the QRL without ever calling this, for example if there
 * is no desire to handle INITIAL packets (e.g. if the QRL is instantiated to
 * succeed a previous QRL and handle a connection which is already established.)
 * However, in this case you should make sure you call
 * ossl_qrl_discard_enc_level (see above).
 *
 * Returns 1 on success or 0 on error.
 */
int ossl_qrl_provide_rx_secret_initial(OSSL_QRL *qrl,
                                       const QUIC_CONN_ID *dst_conn_id);

/*
 * Provides a secret to the QRL, which arises due to an encryption level change.
 * enc_level is a QUIC_ENC_LEVEL_* value. This function cannot be used to
 * initialise the INITIAL encryption level; see
 * ossl_qrl_provide_rx_secret_initial instead.
 *
 * You should seek to call this function for a given EL before packets of that
 * EL arrive and are processed by the QRL. However, if packets have already
 * arrived for a given EL, the QRL will defer processing of them and perform
 * processing of them when this function is eventually called for the EL in
 * question.
 *
 * suite_id is a QRL_SUITE_* value which determines the AEAD function used for
 * the QRL.
 *
 * The secret passed is used directly to derive the "quic key", "quic iv" and
 * "quic hp" values.
 *
 * secret_len is the length of the secret buffer in bytes. The buffer must be
 * sized correctly to the chosen suite, else the function fails.
 *
 * This function can only be called once for a given EL. Subsequent calls fail,
 * as do calls made after a corresponding call to ossl_qrl_discard_enc_level for
 * that EL. The secret for a EL cannot be changed after it is set because QUIC
 * has no facility for introducing additional key material after an EL is setup.
 * QUIC key updates are managed automatically by the QRL and do not require user
 * intervention.
 *
 * Returns 1 on success or 0 on failure.
 */
int ossl_qrl_provide_rx_secret(OSSL_QRL              *qrl,
                               uint32_t               enc_level,
                               uint32_t               suite_id,
                               const unsigned char   *secret,
                               size_t                 secret_len);

/*
 * Informs the QRL that it can now discard key material for a given EL. The QRL
 * will no longer be able to process incoming packets received at that
 * encryption level. This function is idempotent and succeeds if the EL has
 * already been discarded.
 *
 * Returns 1 on success and 0 on failure.
 */
int ossl_qrl_discard_enc_level(OSSL_QRL *qrl, uint32_t enc_level);

/*
 * Packet Reception
 * ================
 */

/* Information about a received packet. */
typedef struct ossl_qrl_rx_pkt_st {
    /* Opaque handle to be passed to ossl_qrl_release_pkt. */
    void               *handle;

    /*
     * Points to a logical representation of the decoded QUIC packet header. The
     * data and len fields point to the decrypted QUIC payload (i.e., to a
     * sequence of zero or more (potentially malformed) frames to be decoded).
     */
    QUIC_PKT_HDR       *hdr;

    /*
     * Address the packet was received from. If this is not available for this
     * packet, this field is NULL (but this can only occur for manually injected
     * packets).
     */
    const BIO_ADDR     *peer;

    /*
     * Local address the packet was sent to. If this is not available for this
     * packet, this field is NULL.
     */
    const BIO_ADDR     *local;

    /*
     * This is the length of the datagram which contained this packet. Note that
     * the datagram may have contained other packets than this. The intended use
     * for this is so that the user can enforce minimum datagram sizes (e.g. for
     * datagrams containing INITIAL packets), as required by RFC 9000.
     */
    size_t              datagram_len;
} OSSL_QRL_RX_PKT;

/*
 * Tries to read a new decrypted packet from the QRL.
 *
 * On success, all fields of *pkt are filled and 1 is returned.
 * Else, returns 0.
 *
 * The resources referenced by pkt->hdr, pkt->data and pkt->peer will remain
 * allocated at least until the user frees them by calling ossl_qrl_release_pkt,
 * which must be called once you are done with the packet.
 */
int ossl_qrl_read_pkt(OSSL_QRL *qrl, OSSL_QRL_RX_PKT *pkt);

/*
 * Release the resources pointed to by an OSSL_QRL_RX_PKT returned by
 * ossl_qrl_read_pkt. Pass the opaque value pkt->handle returned in the
 * structure.
 */
void ossl_qrl_release_pkt(OSSL_QRL *qrl, void *handle);

/*
 * Returns 1 if there are any already processed (i.e. decrypted) packets waiting
 * to be read from the QRL.
 */
int ossl_qrl_processed_read_pending(OSSL_QRL *qrl);

/*
 * Returns 1 if there arre any unprocessed (i.e. not yet decrypted) packets
 * waiting to be processed by the QRL. These may or may not result in
 * successfully decrypted packets once processed. This indicates whether
 * unprocessed data is buffered by the QRL, not whether any data is available in
 * a kernel socket buffer.
 */
int ossl_qrl_unprocessed_read_pending(OSSL_QRL *qrl);

/*
 * Returns the number of UDP payload bytes received from the network so far
 * since the last time this counter was cleared. If clear is 1, clears the
 * counter and returns the old value.
 *
 * The intended use of this is to allow callers to determine how much credit to
 * add to their anti-amplification budgets. This is reported separately instead
 * of in the OSSL_QRL_RX_PKT structure so that a caller can apply
 * anti-amplification credit as soon as a datagram is received, before it has
 * necessarily read all processed packets contained within that datagram from
 * the QRL.
 */
uint64_t ossl_qrl_get_bytes_received(OSSL_QRL *qrl, int clear);

/*
 * Sets a callback which is called when a packet is received and being
 * validated before being queued in the read queue. This is called before packet
 * body decryption. pn_space is a QUIC_PN_SPACE_* value denoting which PN space
 * the PN belongs to.
 *
 * If this callback returns 1, processing continues normally.
 * If this callback returns 0, the packet is discarded.
 *
 * Other packets in the same datagram will still be processed where possible.
 *
 * The intended use for this function is to allow early validation of whether
 * a PN is a potential duplicate before spending CPU time decrypting the
 * packet payload.
 *
 * The callback is optional and can be unset by passing NULL for cb.
 * cb_arg is an opaque value passed to cb.
 */
typedef int (ossl_qrl_early_rx_validation_cb)(QUIC_PN pn, int pn_space,
                                              void *arg);

int ossl_qrl_set_early_rx_validation_cb(OSSL_QRL *qrl,
                                        ossl_qrl_early_rx_validation_cb *cb,
                                        void *cb_arg);

#endif
