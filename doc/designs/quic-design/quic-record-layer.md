QUIC Record Layer API
=====================

The QUIC record layer (QRL) performs the following functions:

- The handling of received datagrams and the initial processing of the
  packets within them, including packet header processing and packet
  decryption.

- The serialization, encryption and transmission of sent packets.

The QRL relies on the DEMUX, which is responsible for actual reads of datagrams
from a datagram network BIO. The DEMUX performs a preliminary examination of
received packet headers to determine a destination connection ID and passes
received datagrams to a specific instance of a QUIC record layer based on the
destination connection ID.

The QRL does not process or examine decrypted packet payloads Processing of
frames is performed by other components, which read them from the QRL.

The QRL does not use the same method structures or polymorphic interface as the
TLS record layer, as there is no benefit to doing so and the structure of the
records returned differs substantially.

Broadly, the interface to the QRL looks like this:

Instantiation
-------------

```c
#define OSSL_QUIC_ENC_LEVEL_INITIAL     0
#define OSSL_QUIC_ENC_LEVEL_HANDSHAKE   1
#define OSSL_QUIC_ENC_LEVEL_0RTT        2
#define OSSL_QUIC_ENC_LEVEL_1RTT        3

typedef struct ossl_qrl_st OSSL_QRL;

typedef struct ossl_qrl_args_st {
    OSSL_LIB_CTX *libctx;
    const char   *propq;

    /*
     * This list is not exhaustive and will expand as the QRL
     * is developed and its requirements become more clear.
     */

    /* Datagram network BIO to use. */
    BIO    *rx_bio, *tx_bio;
    /* Length of connection IDs in short packets in bytes. */
    size_t  short_conn_id_len;
    /* key ... */
    /* IV ... */
    /* cipher information ... */

} OSSL_QRL_ARGS;

/*
 * Instantiates a new QRL. A pointer to the QRL is written
 * to *qrl. Returns 1 on success or 0 on failure.
 */
int ossl_qrl_new(const OSSL_QRL_ARGS *args, OSSL_QRL **qrl);

/*
 * Frees the QRL. All packets obtained using ossl_qrl_read_pkt must already have
 * been released by calling ossl_qrl_release_pkt.
 */
int ossl_qrl_free(OSSL_QRL *qrl);
```

RX API
------

```c
/*
 * Information about a received QUIC packet.
 */
typedef struct ossl_qrl_rx_pkt_st {
    /* Opaque handle to be passed to ossl_qrl_release_pkt. */
    void               *handle;

    /* Points to a logical decode of the QUIC packet header. */
    OSSL_QUIC_PKT_HDR  *hdr;

    /*
     * Points to the decrypted QUIC payload. In other words, this is a sequence
     * of zero or more (potentially malformed) frames to be decoded.
     */
    unsigned char      *data;
    size_t              data_len;

    /*
     * OSSL_QUIC_ENC_LEVEL_*. The encryption level the packet was encrypted at.
     */
    uint8_t             enc_level;

    /* Address the packet was received from. */
    const BIO_ADDR     *peer;
} OSSL_QRL_RX_PKT;

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
 * Tries to read a new decrypted packet from the QRL.
 *
 * On success, all fields of *pkt are filled and 1 is returned.
 * Else, returns 0.
 *
 * The resources referenced by pkt->hdr and pkt->data will remain allocated at
 * least until the user frees them by calling ossl_qrl_release_pkt. This
 * function must be called once you are done with this data.
 */
int ossl_qrl_read_pkt(OSSL_QRL *qrl,
                      OSSL_QRL_RX_PKT *pkt);

/*
 * Release the resources pointed to by an OSSL_QRL_RX_PKT
 * returned by ossl_qrl_read_pkt. Pass the opaque value pkt->handle
 * returned in the structure.
 */
void ossl_qrl_release_pkt(OSSL_QRL *qrl,
                          void *handle);

/*
 * Change the BIO being used by the QRL for RX.
 */
int ossl_qrl_set1_read_bio(OSSL_QRL *qrl, BIO *rx_bio);
```

TX API
------

This is much more rough and will change more, as implementation on the TX side
of the QRL hasn't started yet and there are more requirements to be discovered.

```c
typedef struct OSSL_QRL_IOVEC {
    const unsigned char    *buf;
    size_t                  len;
} OSSL_QRL_IOVEC;

#define OSSL_QRL_TX_FLAG_DEFER_SEND     (1UL<<0)

typedef struct ossl_qrl_tx_pkt_st {
    /*
     * Logical packet header to be serialized.
     */
    const OSSL_QUIC_PKT_HDR *hdr;

    /*
     * Gather buffers used to compose the packet payload, which contains
     * frames to be encrypted.
     */
    const OSSL_QRL_IOVEC   *iovec;
    size_t                  num_iovec;

    /* OSSL_QRL_TX_FLAG_* */
    uint64_t                flags;

    /* OSSL_QUIC_ENC_LEVEL_* */
    uint8_t                 enc_level;

    /*
     * Note: Assuming destination BIO_ADDR is being set on the QRL for now,
     * though this could change
     */
} OSSL_QRL_TX_PKT;

/*
 * Writes one packet. The packet data is consumed and encrypted immediately, so
 * the header structure and data referenced need not remain allocated after the
 * call returns. The packet is not necessarily written to the network
 * immediately.
 *
 * If OSSL_QRL_TX_FLAG_DEFER_SEND is set, the packet is not sent immediately but
 * is held until the next call to ossl_qrl_write_pkt. This can be used to
 * concatenate several packets into a single transmitted datagram. Every packet
 * but the final packet to be written into a datagram should have the flag
 * unset. packet to be written into a datagram should have the flag unset.
 */
int ossl_qrl_write_pkt(OSSL_QRL *qrl, const OSSL_QRL_TX_PKT *pkt);

/*
 * Change the BIO being used by the QRL for TX.
 */
int ossl_qrl_set1_write_bio(OSSL_QRL *qrl, BIO *tx_bio);

/* TODO MTU handling, etc. */
```

Packet Headers
--------------

Packet headers are logically represented by the following structure.

This structure may be cleaned up a bit later and is being published here to
provide some early guidance of what to expect.

```c
/*
 * QUIC Packet Header
 * ==================
 *
 * This structure provides a logical representation of a QUIC packet header.
 *
 * QUIC packet formats fall into the following categories:
 *
 *   Long Packets, which is subdivided into five possible packet types:
 *     Version Negotiation (a special case);
 *     Initial;
 *     0-RTT;
 *     Handshake; and
 *     Retry
 *
 *   Short Packets, which comprises only a single packet type (1-RTT).
 *
 * The packet formats vary and common fields are found in some packets but
 * not others. The below table indicates which fields are present in which
 * kinds of packet. * indicates header protection is applied.
 *
 *   SLLLLL         Legend: 1=1-RTT, i=Initial, 0=0-RTT, h=Handshake
 *   1i0hrv                 r=Retry, v=Version Negotiation
 *   ------
 *   1i0hrv         Header Form (0=Short, 1=Long)
 *   1i0hr          Fixed Bit (always 1)
 *   1              Spin Bit
 *   1       *      Reserved Bits
 *   1       *      Key Phase
 *   1i0h    *      Packet Number Length
 *    i0hr?         Long Packet Type
 *    i0h           Type-Specific Bits
 *    i0hr          Version (note: always 0 for Version Negotiation packets)
 *   1i0hrv         Destination Connection ID
 *    i0hrv         Source Connection ID
 *   1i0h    *      Packet Number
 *    i             Token
 *    i0h           Length
 *       r          Retry Token
 *       r          Retry Integrity Tag
 *
 * For each field below, the conditions under which the field is valid are
 * specified. If a field is not currently valid, its contents are undefined
 * unless otherwise specified.
 */
#define QUIC_MAX_CONN_ID_LEN                20

#define QUIC_V1_LONG_PKT_TYPE_INITIAL       0x0
#define QUIC_V1_LONG_PKT_TYPE_0RTT          0x1
#define QUIC_V1_LONG_PKT_TYPE_HANDSHAKE     0x2
#define QUIC_V1_LONG_PKT_TYPE_RETRY         0x3

typedef struct ossl_quic_pkt_hdr_st {
    /* [ALL] 1 if this was a long packet, 0 otherwise. Always valid. */
    unsigned int    is_long     :1;

    /* [L] Long Packet Type. Valid if (is_long). */
    unsigned int    long_type   :2;

    /* [S] Value of the spin bit. Valid if (!is_long). */
    unsigned int    spin_bit    :1;

    /*
     * [S] Value of the Key Phase bit in the short packet.
     * Valid if (!is_long && !partial).
     */
    unsigned int    key_phase   :1;

    /*
     * [1i0h] Length of packet number in bytes. This is the decoded value.
     * Valid if ((!is_long || (version && long_type != RETRY)) && !partial).
     */
    unsigned int    pn_len      :4;

    /*
     * [ALL] Set to 1 if this is a partial decode because the packet header
     * has not yet been deprotected. pn_len, pn and key_phase are not valid if
     * this is set.
     *
     * (NOTE: This is used inside the record layer only. May be removed
     * from the final interface.)
     */
    unsigned int    partial     :1;

    /* [L] Version field. Valid if (is_long). */
    uint32_t        version;

    /* [ALL] Number of bytes in the connection ID. Always valid. */
    uint8_t         dst_conn_id_len;
    uint8_t         dst_conn_id[QUIC_MAX_CONN_ID_LEN];

    /* [L] Number of bytes in the connection ID. Valid if (is_long). */
    uint8_t         src_conn_id_len;
    uint8_t         src_conn_id[QUIC_MAX_CONN_ID_LEN];

    /*
     * [1i0h] Relatively-encoded packet number in undecoded form. The correct
     * decoding of this value is context-dependent. The number of bytes valid in
     * this buffer is determined by pn_len above. If the decode was partial,
     * this field is unset.
     *
     * (NOTE: This is used inside the record layer only. May be removed from the
     * final interface.)
     *
     * Valid if ((!is_long || (version && long_type != RETRY)) && !partial).
     */
    uint8_t         pn_raw[4];

    /*
     * [1i0h] Decoded packet number.
     *
     * Valid if ((!is_long || (version && long_type != RETRY)) && !partial).
     */
    QUIC_PN         pn;

    /*
     * [i] Token field in Initial packet. For RX, valid until record is
     * released. token_len is the length of the token in bytes.
     *
     * Valid if (is_long && long_type == INITIAL).
     */
    const uint8_t  *token;
    size_t          token_len;

    /*
     * [r] Retry Token in a Retry packet. For RX, valid until record is
     * released. retry_token_len is the length of the retry token in bytes.
     *
     * Valid if (is_long && long_type == RETRY).
     */
    const uint8_t  *retry_token;
    size_t          retry_token_len;

    /*
     * [r] Retry Integrity Tag in a Retry packet.
     *
     * Valid if (is_long && long_type == RETRY).
     */
    uint8_t         retry_integrity_tag[16];
} OSSL_QUIC_PKT_HDR;
```

