/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_record.h"
#include "internal/common.h"

/*
 * Mark a packet in a bitfield.
 *
 * pkt_idx: index of packet within datagram.
 */
static ossl_inline void pkt_mark(uint64_t *bitf, size_t pkt_idx)
{
    assert(pkt_idx < QUIC_MAX_PKT_PER_URXE);
    *bitf |= ((uint64_t)1) << pkt_idx;
}

/* Returns 1 if a packet is in the bitfield. */
static ossl_inline int pkt_is_marked(const uint64_t *bitf, size_t pkt_idx)
{
    assert(pkt_idx < QUIC_MAX_PKT_PER_URXE);
    return (*bitf & (((uint64_t)1) << pkt_idx)) != 0;
}

/*
 * RXE
 * ===
 *
 * RX Entries (RXEs) store processed (i.e., decrypted) data received from the
 * network. One RXE is used per received QUIC packet.
 */
typedef struct rxe_st RXE;

struct rxe_st {
    RXE                *prev, *next;
    size_t              data_len, alloc_len;

    /* Extra fields for per-packet information. */
    QUIC_PKT_HDR        hdr; /* data/len are decrypted payload */

    /* Decoded packet number. */
    QUIC_PN             pn;

    /* Addresses copied from URXE. */
    BIO_ADDR            peer, local;

    /* Total length of the datagram which contained this packet. */
    size_t              datagram_len;
};

typedef struct ossl_qrl_rxe_list_st {
    RXE *head, *tail;
} RXE_LIST;

static ossl_inline unsigned char *rxe_data(const RXE *e)
{
    return (unsigned char *)(e + 1);
}

static void rxe_remove(RXE_LIST *l, RXE *e)
{
    if (e->prev != NULL)
        e->prev->next = e->next;
    if (e->next != NULL)
        e->next->prev = e->prev;

    if (e == l->head)
        l->head = e->next;
    if (e == l->tail)
        l->tail = e->prev;

    e->next = e->prev = NULL;
}

static void rxe_insert_tail(RXE_LIST *l, RXE *e)
{
    if (l->tail == NULL) {
        l->head = l->tail = e;
        e->next = e->prev = NULL;
        return;
    }

    l->tail->next = e;
    e->prev = l->tail;
    e->next = NULL;
    l->tail = e;
}

/*
 * QRL
 * ===
 */

/* (Encryption level, direction)-specific state. */
typedef struct ossl_qrl_enc_level_st {
    /* Hash function used for key derivation. */
    EVP_MD                     *md;
    /* Context used for packet body ciphering. */
    EVP_CIPHER_CTX             *cctx;
    /* IV used to construct nonces used for AEAD packet body ciphering. */
    unsigned char               iv[EVP_MAX_IV_LENGTH];
    /* Have we permanently discarded this encryption level? */
    unsigned char               discarded;
    /* QRL_SUITE_* value. */
    uint32_t                    suite_id;
    /* Length of authentication tag. */
    uint32_t                    tag_len;
    /*
     * Cryptographic context used to apply and remove header protection from
     * packet headers.
     */
    QUIC_HDR_PROTECTOR          hpr;
} OSSL_QRL_ENC_LEVEL;

struct ossl_qrl_st {
    OSSL_LIB_CTX               *libctx;
    const char                 *propq;

    /* Demux to receive datagrams from. */
    QUIC_DEMUX                 *rx_demux;

    /* Length of connection IDs used in short-header packets in bytes. */
    size_t                      short_conn_id_len;

    /*
     * List of URXEs which are filled with received encrypted data.
     * These are returned to the DEMUX's free list as they are processed.
     */
    QUIC_URXE_LIST              urx_pending;

    /*
     * List of URXEs which we could not decrypt immediately and which are being
     * kept in case they can be decrypted later.
     */
    QUIC_URXE_LIST              urx_deferred;

    /*
     * List of RXEs which are not currently in use. These are moved
     * to the pending list as they are filled.
     */
    RXE_LIST                    rx_free;

    /*
     * List of RXEs which are filled with decrypted packets ready to be passed
     * to the user. A RXE is removed from all lists inside the QRL when passed
     * to the user, then returned to the free list when the user returns it.
     */
    RXE_LIST                    rx_pending;

    /* Largest PN we have received and processed in a given PN space. */
    QUIC_PN                     rx_largest_pn[QUIC_PN_SPACE_NUM];

    /* Per encryption-level state. */
    OSSL_QRL_ENC_LEVEL          rx_el[QUIC_ENC_LEVEL_NUM];
    OSSL_QRL_ENC_LEVEL          tx_el[QUIC_ENC_LEVEL_NUM];

    /* Bytes we have received since this counter was last cleared. */
    uint64_t                    bytes_received;

    /* Validation callback. */
    ossl_qrl_early_rx_validation_cb    *rx_validation_cb;
    void                               *rx_validation_cb_arg;
};

static void qrl_on_rx(QUIC_URXE *urxe, void *arg);

/* Constants used for key derivation in QUIC v1. */
static const unsigned char quic_client_in_label[] = {
    0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e /* "client in" */
};
static const unsigned char quic_server_in_label[] = {
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e /* "server in" */
};
static const unsigned char quic_v1_iv_label[] = {
    0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76 /* "quic iv" */
};
static const unsigned char quic_v1_key_label[] = {
    0x71, 0x75, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79 /* "quic key" */
};
static const unsigned char quic_v1_hp_label[] = {
    0x71, 0x75, 0x69, 0x63, 0x20, 0x68, 0x70 /* "quic hp" */
};
/* Salt used to derive Initial packet protection keys (RFC 9001 Section 5.2). */
static const unsigned char quic_v1_initial_salt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

static ossl_inline OSSL_QRL_ENC_LEVEL *qrl_get_el(OSSL_QRL *qrl,
                                                  uint32_t enc_level,
                                                  int is_tx)
{
    if (!ossl_assert(enc_level < QUIC_ENC_LEVEL_NUM))
        return NULL;
    return is_tx ? &qrl->tx_el[enc_level] : &qrl->rx_el[enc_level];
}

/*
 * Returns 1 if we have key material for a given encryption level, 0 if we do
 * not yet have material and -1 if the EL is discarded.
 */
static int qrl_have_el(OSSL_QRL *qrl, uint32_t enc_level, int is_tx)
{
    OSSL_QRL_ENC_LEVEL *el = qrl_get_el(qrl, enc_level, is_tx);

    if (el->cctx != NULL)
        return 1;
    if (el->discarded)
        return -1;
    return 0;
}

/* Drops keying material for a given encryption level. */
static void qrl_el_discard(OSSL_QRL *qrl, uint32_t enc_level,
                           int is_tx, int final)
{
    OSSL_QRL_ENC_LEVEL *el = qrl_get_el(qrl, enc_level, is_tx);

    if (el->discarded)
        return;

    if (el->cctx != NULL) {
        ossl_quic_hdr_protector_destroy(&el->hpr);

        EVP_CIPHER_CTX_free(el->cctx);
        el->cctx    = NULL;

        EVP_MD_free(el->md);
        el->md      = NULL;
    }

    /* Zeroise IV. */
    OPENSSL_cleanse(el->iv, sizeof(el->iv));

    if (final)
        el->discarded = 1;
}

/*
 * Sets up cryptographic state for a given encryption level and direction by
 * deriving "quic iv", "quic key" and "quic hp" values from a given secret.
 *
 * md is a hash function used for key derivation. If it is NULL, this function
 * fetches the necessary hash function itself. If it is non-NULL, this function
 * can reuse the caller's reference to a suitable EVP_MD; the EVP_MD provided
 * must match the suite.
 *
 * On success where md is non-NULL, takes ownership of the caller's reference to
 * md.
 */
static int qrl_el_set_secret(OSSL_QRL *qrl, uint32_t enc_level,
                             uint32_t suite_id, EVP_MD *md,
                             int is_tx,
                             const unsigned char *secret,
                             size_t secret_len)
{
    OSSL_QRL_ENC_LEVEL *el = qrl_get_el(qrl, enc_level, is_tx);
    unsigned char key[EVP_MAX_KEY_LENGTH], hpr_key[EVP_MAX_KEY_LENGTH];
    size_t key_len = 0, hpr_key_len = 0, iv_len = 0;
    const char *cipher_name = NULL, *md_name = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    int own_md = 0, have_hpr = 0;

    if (el->discarded)
        /* Should not be trying to reinitialise an EL which was discarded. */
        return 0;

    cipher_name = ossl_qrl_get_suite_cipher_name(suite_id);
    iv_len      = ossl_qrl_get_suite_cipher_iv_len(suite_id);
    key_len     = ossl_qrl_get_suite_cipher_key_len(suite_id);
    hpr_key_len = ossl_qrl_get_suite_hdr_prot_key_len(suite_id);
    if (cipher_name == NULL)
        return 0;

    if (secret_len != ossl_qrl_get_suite_secret_len(suite_id))
        return 0;

    if (md == NULL) {
        md_name = ossl_qrl_get_suite_md_name(suite_id);

        if ((md = EVP_MD_fetch(qrl->libctx,
                                   md_name, qrl->propq)) == NULL)
            return 0;

        own_md = 1;
    }

    /* Derive "quic iv" key. */
    if (!ossl_quic_hkdf_expand_label(qrl->libctx, qrl->propq,
                                     md,
                                     secret, secret_len,
                                     quic_v1_iv_label,
                                     sizeof(quic_v1_iv_label),
                                     NULL, 0,
                                     el->iv, iv_len))
        goto err;

    /* Derive "quic key" key. */
    if (!ossl_quic_hkdf_expand_label(qrl->libctx, qrl->propq,
                                     md,
                                     secret, secret_len,
                                     quic_v1_key_label,
                                     sizeof(quic_v1_key_label),
                                     NULL, 0,
                                     key, key_len))
        goto err;

    /* Derive "quic hp" key. */
    if (!ossl_quic_hkdf_expand_label(qrl->libctx, qrl->propq,
                                     md,
                                     secret, secret_len,
                                     quic_v1_hp_label,
                                     sizeof(quic_v1_hp_label),
                                     NULL, 0,
                                     hpr_key, hpr_key_len))
        goto err;

    /* Free any old context which is using old keying material. */
    if (el->cctx != NULL) {
        ossl_quic_hdr_protector_destroy(&el->hpr);
        EVP_CIPHER_CTX_free(el->cctx);
        el->cctx = NULL;
    }

    /* Setup header protection context. */
    if (!ossl_quic_hdr_protector_init(&el->hpr,
                                      qrl->libctx,
                                      qrl->propq,
                                      ossl_qrl_get_suite_hdr_prot_cipher_id(suite_id),
                                      hpr_key,
                                      hpr_key_len))
        goto err;

    have_hpr = 1;

    /* Create and initialise cipher context. */
    if ((cipher = EVP_CIPHER_fetch(qrl->libctx, cipher_name,
                                   qrl->propq)) == NULL)
        goto err;

    if (!ossl_assert(iv_len  == (size_t)EVP_CIPHER_get_iv_length(cipher))
        || !ossl_assert(key_len == (size_t)EVP_CIPHER_get_key_length(cipher)))
        goto err;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* IV will be changed on RX so we don't need to use a real value here. */
    if (!EVP_CipherInit_ex(cctx, cipher, NULL, key, el->iv, 0))
        goto err;

    el->suite_id    = suite_id;
    el->cctx        = cctx;
    el->md          = md;
    el->tag_len     = ossl_qrl_get_suite_cipher_tag_len(suite_id);

    /* Zeroize intermediate keys. */
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(hpr_key, sizeof(hpr_key));
    EVP_CIPHER_free(cipher);
    return 1;

err:
    if (have_hpr)
        ossl_quic_hdr_protector_destroy(&el->hpr);
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (own_md)
        EVP_MD_free(md);
    return 0;
}

OSSL_QRL *ossl_qrl_new(const OSSL_QRL_ARGS *args)
{
    OSSL_QRL *qrl;
    size_t i;

    if (args->rx_demux == NULL)
        return 0;

    qrl = OPENSSL_zalloc(sizeof(OSSL_QRL));
    if (qrl == NULL)
        return 0;

    for (i = 0; i < OSSL_NELEM(qrl->rx_largest_pn); ++i)
        qrl->rx_largest_pn[i] = args->rx_init_largest_pn[i];

    qrl->libctx             = args->libctx;
    qrl->propq              = args->propq;
    qrl->rx_demux           = args->rx_demux;
    qrl->short_conn_id_len  = args->short_conn_id_len;
    return qrl;
}

static void qrl_cleanup_rxl(RXE_LIST *l)
{
    RXE *e, *enext;
    for (e = l->head; e != NULL; e = enext) {
        enext = e->next;
        OPENSSL_free(e);
    }
    l->head = l->tail = NULL;
}

static void qrl_cleanup_urxl(OSSL_QRL *qrl, QUIC_URXE_LIST *l)
{
    QUIC_URXE *e, *enext;
    for (e = l->head; e != NULL; e = enext) {
        enext = e->next;
        ossl_quic_demux_release_urxe(qrl->rx_demux, e);
    }
    l->head = l->tail = NULL;
}

void ossl_qrl_free(OSSL_QRL *qrl)
{
    uint32_t i;

    /* Unregister from the RX DEMUX. */
    ossl_quic_demux_unregister_by_cb(qrl->rx_demux, qrl_on_rx, qrl);

    /* Free RXE queue data. */
    qrl_cleanup_rxl(&qrl->rx_free);
    qrl_cleanup_rxl(&qrl->rx_pending);
    qrl_cleanup_urxl(qrl, &qrl->urx_pending);
    qrl_cleanup_urxl(qrl, &qrl->urx_deferred);

    /* Drop keying material and crypto resources. */
    for (i = 0; i < QUIC_ENC_LEVEL_NUM; ++i) {
        qrl_el_discard(qrl, i, 0, 1);
        qrl_el_discard(qrl, i, 1, 1);
    }

    OPENSSL_free(qrl);
}

static void qrl_on_rx(QUIC_URXE *urxe, void *arg)
{
    OSSL_QRL *qrl = arg;

    /* Initialize our own fields inside the URXE and add to the pending list. */
    urxe->processed     = 0;
    urxe->hpr_removed   = 0;
    ossl_quic_urxe_insert_tail(&qrl->urx_pending, urxe);
}

int ossl_qrl_add_dst_conn_id(OSSL_QRL *qrl,
                             const QUIC_CONN_ID *dst_conn_id)
{
    return ossl_quic_demux_register(qrl->rx_demux,
                                    dst_conn_id,
                                    qrl_on_rx,
                                    qrl);
}

int ossl_qrl_remove_dst_conn_id(OSSL_QRL *qrl,
                                const QUIC_CONN_ID *dst_conn_id)
{
    return ossl_quic_demux_unregister(qrl->rx_demux, dst_conn_id);
}

static void qrl_requeue_deferred(OSSL_QRL *qrl)
{
    QUIC_URXE *e;

    while ((e = qrl->urx_deferred.head) != NULL) {
        ossl_quic_urxe_remove(&qrl->urx_deferred, e);
        ossl_quic_urxe_insert_head(&qrl->urx_pending, e);
    }
}

int ossl_qrl_provide_rx_secret(OSSL_QRL *qrl, uint32_t enc_level,
                               uint32_t suite_id,
                               const unsigned char *secret, size_t secret_len)
{
    if (enc_level == QUIC_ENC_LEVEL_INITIAL || enc_level >= QUIC_ENC_LEVEL_NUM)
        return 0;

    if (!qrl_el_set_secret(qrl, enc_level, suite_id, NULL,
                           /*is_tx=*/0, secret, secret_len))
        return 0;

    /*
     * Any packets we previously could not decrypt, we may now be able to
     * decrypt, so move any datagrams containing deferred packets from the
     * deferred to the pending queue.
     */
    qrl_requeue_deferred(qrl);
    return 1;
}

/* Initialise key material for the INITIAL encryption level. */
int ossl_qrl_provide_rx_secret_initial(OSSL_QRL *qrl,
                                       const QUIC_CONN_ID *dst_conn_id)
{
    unsigned char initial_secret[32];
    unsigned char client_initial_secret[32], server_initial_secret[32];
    EVP_MD *sha256;
    int have_rx = 0;

    /* Initial encryption always uses SHA-256. */
    if ((sha256 = EVP_MD_fetch(qrl->libctx,
                               "SHA256", qrl->propq)) == NULL)
        return 0;

    /* Derive initial secret from destination connection ID. */
    if (!ossl_quic_hkdf_extract(qrl->libctx, qrl->propq,
                                sha256,
                                quic_v1_initial_salt,
                                sizeof(quic_v1_initial_salt),
                                dst_conn_id->id,
                                dst_conn_id->id_len,
                                initial_secret,
                                sizeof(initial_secret)))
        goto err;

    /* Derive "client in" secret. */
    if (!ossl_quic_hkdf_expand_label(qrl->libctx, qrl->propq,
                                     sha256,
                                     initial_secret,
                                     sizeof(initial_secret),
                                     quic_client_in_label,
                                     sizeof(quic_client_in_label),
                                     NULL, 0,
                                     client_initial_secret,
                                     sizeof(client_initial_secret)))
        goto err;

    /* Derive "server in" secret. */
    if (!ossl_quic_hkdf_expand_label(qrl->libctx, qrl->propq,
                                     sha256,
                                     initial_secret,
                                     sizeof(initial_secret),
                                     quic_server_in_label,
                                     sizeof(quic_server_in_label),
                                     NULL, 0,
                                     server_initial_secret,
                                     sizeof(server_initial_secret)))
        goto err;

    /* Setup RX cipher. Initial encryption always uses AES-128-GCM. */
    if (!qrl_el_set_secret(qrl, QUIC_ENC_LEVEL_INITIAL,
                           QRL_SUITE_AES128GCM,
                           sha256,
                           /*is_tx=*/0,
                           server_initial_secret,
                           sizeof(server_initial_secret)))
        goto err;

    have_rx = 1;

    /*
     * qrl_el_set_secret takes ownership of our ref to SHA256, so get a new ref
     * for the following call for the TX side.
     */
    if (!EVP_MD_up_ref(sha256)) {
        sha256 = NULL;
        goto err;
    }

    /* Setup TX cipher. */
    if (!qrl_el_set_secret(qrl, QUIC_ENC_LEVEL_INITIAL,
                            QRL_SUITE_AES128GCM,
                            sha256,
                            /*is_tx=*/1,
                            client_initial_secret,
                            sizeof(client_initial_secret)))
        goto err;

    /*
     * Any packets we previously could not decrypt, we may now be able to
     * decrypt, so move any datagrams containing deferred packets from the
     * deferred to the pending queue.
     */
    qrl_requeue_deferred(qrl);
    return 1;

err:
    if (have_rx)
        qrl_el_discard(qrl, QUIC_ENC_LEVEL_INITIAL, /*is_tx=*/0, 0);

    EVP_MD_free(sha256);
    return 0;
}

int ossl_qrl_discard_enc_level(OSSL_QRL *qrl, uint32_t enc_level)
{
    if (enc_level >= QUIC_ENC_LEVEL_NUM)
        return 0;

    qrl_el_discard(qrl, enc_level, 0, 1);
    return 1;
}

/* Returns 1 if there are one or more pending RXEs. */
int ossl_qrl_processed_read_pending(OSSL_QRL *qrl)
{
    return qrl->rx_pending.head != NULL;
}

/* Returns 1 if there are yet-unprocessed packets. */
int ossl_qrl_unprocessed_read_pending(OSSL_QRL *qrl)
{
    return qrl->urx_pending.head != NULL || qrl->urx_deferred.head != NULL;
}

/* Pop the next pending RXE. Returns NULL if no RXE is pending. */
static RXE *qrl_pop_pending_rxe(OSSL_QRL *qrl)
{
    RXE *rxe = qrl->rx_pending.head;

    if (rxe == NULL)
        return NULL;

    rxe_remove(&qrl->rx_pending, rxe);
    return rxe;
}

/* Allocate a new RXE. */
static RXE *qrl_alloc_rxe(size_t alloc_len)
{
    RXE *rxe;

    if (alloc_len >= SIZE_MAX - sizeof(RXE))
        return NULL;

    rxe = OPENSSL_malloc(sizeof(RXE) + alloc_len);
    if (rxe == NULL)
        return NULL;

    rxe->prev = rxe->next = NULL;
    rxe->alloc_len = alloc_len;
    rxe->data_len  = 0;
    return rxe;
}

/*
 * Ensures there is at least one RXE in the RX free list, allocating a new entry
 * if necessary. The returned RXE is in the RX free list; it is not popped.
 *
 * alloc_len is a hint which may be used to determine the RXE size if allocation
 * is necessary. Returns NULL on allocation failure.
 */
static RXE *qrl_ensure_free_rxe(OSSL_QRL *qrl, size_t alloc_len)
{
    RXE *rxe;

    if (qrl->rx_free.head != NULL)
        return qrl->rx_free.head;

    rxe = qrl_alloc_rxe(alloc_len);
    if (rxe == NULL)
        return NULL;

    rxe_insert_tail(&qrl->rx_free, rxe);
    return rxe;
}

/*
 * Resize the data buffer attached to an RXE to be n bytes in size. The address
 * of the RXE might change; the new address is returned, or NULL on failure, in
 * which case the original RXE remains valid.
 */
static RXE *qrl_resize_rxe(RXE_LIST *rxl, RXE *rxe, size_t n)
{
    RXE *rxe2;

    /* Should never happen. */
    if (rxe == NULL)
        return NULL;

    if (n >= SIZE_MAX - sizeof(RXE))
        return NULL;

    /*
     * NOTE: We do not clear old memory, although it does contain decrypted
     * data.
     */
    rxe2 = OPENSSL_realloc(rxe, sizeof(RXE) + n);
    if (rxe2 == NULL)
        /* original RXE is still in tact unchanged */
        return NULL;

    if (rxe != rxe2) {
        if (rxl->head == rxe)
            rxl->head = rxe2;
        if (rxl->tail == rxe)
            rxl->tail = rxe2;
        if (rxe->prev != NULL)
            rxe->prev->next = rxe2;
        if (rxe->next != NULL)
            rxe->next->prev = rxe2;
    }

    rxe2->alloc_len = n;
    return rxe2;
}

/*
 * Ensure the data buffer attached to an RXE is at least n bytes in size.
 * Returns NULL on failure.
 */
static RXE *qrl_reserve_rxe(RXE_LIST *rxl,
                            RXE *rxe, size_t n)
{
    if (rxe->alloc_len >= n)
        return rxe;

    return qrl_resize_rxe(rxl, rxe, n);
}

/* Return a RXE handed out to the user back to our freelist. */
static void qrl_recycle_rxe(OSSL_QRL *qrl, RXE *rxe)
{
    /* RXE should not be in any list */
    assert(rxe->prev == NULL && rxe->next == NULL);
    rxe_insert_tail(&qrl->rx_free, rxe);
}

/*
 * Given a pointer to a pointer pointing to a buffer and the size of that
 * buffer, copy the buffer into *prxe, expanding the RXE if necessary (its
 * pointer may change due to realloc). *pi is the offset in bytes to copy the
 * buffer to, and on success is updated to be the offset pointing after the
 * copied buffer. *pptr is updated to point to the new location of the buffer.
 */
static int qrl_relocate_buffer(OSSL_QRL *qrl, RXE **prxe, size_t *pi,
                               const unsigned char **pptr, size_t buf_len)
{
    RXE *rxe;
    unsigned char *dst;

    if (!buf_len)
        return 1;

    if ((rxe = qrl_reserve_rxe(&qrl->rx_free, *prxe, *pi + buf_len)) == NULL)
        return 0;

    *prxe = rxe;
    dst = (unsigned char *)rxe_data(rxe) + *pi;

    memcpy(dst, *pptr, buf_len);
    *pi += buf_len;
    *pptr = dst;
    return 1;
}

static uint32_t qrl_determine_enc_level(const QUIC_PKT_HDR *hdr)
{
    switch (hdr->type) {
        case QUIC_PKT_TYPE_INITIAL:
            return QUIC_ENC_LEVEL_INITIAL;
        case QUIC_PKT_TYPE_HANDSHAKE:
            return QUIC_ENC_LEVEL_HANDSHAKE;
        case QUIC_PKT_TYPE_0RTT:
            return QUIC_ENC_LEVEL_0RTT;
        case QUIC_PKT_TYPE_1RTT:
            return QUIC_ENC_LEVEL_1RTT;

        default:
            assert(0);
        case QUIC_PKT_TYPE_RETRY:
        case QUIC_PKT_TYPE_VERSION_NEG:
            return QUIC_ENC_LEVEL_INITIAL; /* not used */
    }
}

static uint32_t rxe_determine_pn_space(RXE *rxe)
{
    uint32_t enc_level;

    enc_level = qrl_determine_enc_level(&rxe->hdr);
    return ossl_quic_enc_level_to_pn_space(enc_level);
}

static int qrl_validate_hdr_early(OSSL_QRL *qrl, RXE *rxe,
                                  RXE *first_rxe)
{
    /* Ensure version is what we want. */
    if (rxe->hdr.version != QUIC_VERSION_1
        && rxe->hdr.version != QUIC_VERSION_NONE)
        return 0;

    /* Clients should never receive 0-RTT packets. */
    if (rxe->hdr.type == QUIC_PKT_TYPE_0RTT)
        return 0;

    /* Version negotiation and retry packets must be the first packet. */
    if (first_rxe != NULL && (rxe->hdr.type == QUIC_PKT_TYPE_VERSION_NEG
                              || rxe->hdr.type == QUIC_PKT_TYPE_RETRY))
        return 0;

    /*
     * If this is not the first packet in a datagram, the destination connection
     * ID must match the one in that packet.
     */
    if (first_rxe != NULL &&
        !ossl_quic_conn_id_eq(&first_rxe->hdr.dst_conn_id,
                              &rxe->hdr.dst_conn_id))
        return 0;

    return 1;
}

/* Validate header and decode PN. */
static int qrl_validate_hdr(OSSL_QRL *qrl, RXE *rxe)
{
    int pn_space = rxe_determine_pn_space(rxe);

    if (!ossl_quic_wire_decode_pkt_hdr_pn(rxe->hdr.pn, rxe->hdr.pn_len,
                                          qrl->rx_largest_pn[pn_space],
                                          &rxe->pn))
        return 0;

    /*
     * Allow our user to decide whether to discard the packet before we try and
     * decrypt it.
     */
    if (qrl->rx_validation_cb != NULL
        && !qrl->rx_validation_cb(rxe->pn, pn_space, qrl->rx_validation_cb_arg))
        return 0;

    return 1;
}

/*
 * Tries to decrypt a packet payload.
 *
 * Returns 1 on success or 0 on failure (which is permanent). The payload is
 * decrypted from src and written to dst. The buffer dst must be of at least
 * src_len bytes in length. The actual length of the output in bytes is written
 * to *dec_len on success, which will always be equal to or less than (usually
 * less than) src_len.
 */
static int qrl_decrypt_pkt_body(OSSL_QRL *qrl, unsigned char *dst,
                                const unsigned char *src,
                                size_t src_len, size_t *dec_len,
                                const unsigned char *aad, size_t aad_len,
                                QUIC_PN pn, uint32_t enc_level)
{
    int l = 0, l2 = 0;
    unsigned char nonce[EVP_MAX_IV_LENGTH];
    size_t nonce_len, i;
    OSSL_QRL_ENC_LEVEL *el = &qrl->rx_el[enc_level];

    if (src_len > INT_MAX || aad_len > INT_MAX || el->tag_len >= src_len)
        return 0;

    /* We should not have been called if we do not have key material. */
    if (!ossl_assert(qrl_have_el(qrl, enc_level, /*is_tx=*/0) == 1))
        return 0;

    /* Construct nonce (nonce=IV ^ PN). */
    nonce_len = EVP_CIPHER_CTX_get_iv_length(el->cctx);
    if (!ossl_assert(nonce_len >= sizeof(QUIC_PN)))
        return 0;

    memcpy(nonce, el->iv, nonce_len);
    for (i = 0; i < sizeof(QUIC_PN); ++i)
        nonce[nonce_len - i - 1] ^= (unsigned char)(pn >> (i * 8));

    /* type and key will already have been setup; feed the IV. */
    if (EVP_CipherInit_ex(el->cctx, NULL,
                          NULL, NULL, nonce, /*enc=*/0) != 1)
        return 0;

    /* Feed the AEAD tag we got so the cipher can validate it. */
    if (EVP_CIPHER_CTX_ctrl(el->cctx, EVP_CTRL_AEAD_SET_TAG,
                            el->tag_len,
                            (unsigned char *)src + src_len - el->tag_len) != 1)
        return 0;

    /* Feed AAD data. */
    if (EVP_CipherUpdate(el->cctx, NULL, &l, aad, aad_len) != 1)
        return 0;

    /* Feed encrypted packet body. */
    if (EVP_CipherUpdate(el->cctx, dst, &l, src, src_len - el->tag_len) != 1)
        return 0;

    /* Ensure authentication succeeded. */
    if (EVP_CipherFinal_ex(el->cctx, NULL, &l2) != 1)
        return 0;

    *dec_len = l;
    return 1;
}

static ossl_inline void ignore_res(int x)
{
    /* No-op. */
}

/* Process a single packet in a datagram. */
static int qrl_process_pkt(OSSL_QRL *qrl, QUIC_URXE *urxe,
                           PACKET *pkt, size_t pkt_idx,
                           RXE **first_rxe,
                           size_t datagram_len)
{
    RXE *rxe;
    const unsigned char *eop = NULL;
    size_t i, aad_len = 0, dec_len = 0;
    PACKET orig_pkt = *pkt;
    const unsigned char *sop = PACKET_data(pkt);
    unsigned char *dst;
    char need_second_decode = 0, already_processed = 0;
    QUIC_PKT_HDR_PTRS ptrs;
    uint32_t pn_space, enc_level;

    /*
     * Get a free RXE. If we need to allocate a new one, use the packet length
     * as a good ballpark figure.
     */
    rxe = qrl_ensure_free_rxe(qrl, PACKET_remaining(pkt));
    if (rxe == NULL)
        return 0;

    /* Have we already processed this packet? */
    if (pkt_is_marked(&urxe->processed, pkt_idx))
        already_processed = 1;

    /*
     * Decode the header into the RXE structure. We first decrypt and read the
     * unprotected part of the packet header (unless we already removed header
     * protection, in which case we decode all of it).
     */
    need_second_decode = !pkt_is_marked(&urxe->hpr_removed, pkt_idx);
    if (!ossl_quic_wire_decode_pkt_hdr(pkt,
                                      qrl->short_conn_id_len,
                                      need_second_decode, &rxe->hdr, &ptrs))
        goto malformed;

    /*
     * Our successful decode above included an intelligible length and the
     * PACKET is now pointing to the end of the QUIC packet.
     */
    eop = PACKET_data(pkt);

    /*
     * Make a note of the first RXE so we can later ensure the destination
     * connection IDs of all packets in a datagram mater.
     */
    if (pkt_idx == 0)
        *first_rxe = rxe;

    /*
     * Early header validation. Since we now know the packet length, we can also
     * now skip over it if we already processed it.
     */
    if (already_processed
        || !qrl_validate_hdr_early(qrl, rxe, pkt_idx == 0 ? NULL : *first_rxe))
        goto malformed;

    if (rxe->hdr.type == QUIC_PKT_TYPE_VERSION_NEG
        || rxe->hdr.type == QUIC_PKT_TYPE_RETRY) {
        /*
         * Version negotiation and retry packets are a special case. They do not
         * contain a payload which needs decrypting and have no header
         * protection.
         */

        /* Just copy the payload from the URXE to the RXE. */
        if ((rxe = qrl_reserve_rxe(&qrl->rx_free, rxe, rxe->hdr.len)) == NULL)
            /*
             * Allocation failure. EOP will be pointing to the end of the
             * datagram so processing of this datagram will end here.
             */
            goto malformed;

        /* We are now committed to returning the packet. */
        memcpy(rxe_data(rxe), rxe->hdr.data, rxe->hdr.len);
        pkt_mark(&urxe->processed, pkt_idx);

        rxe->hdr.data = rxe_data(rxe);

        /* Move RXE to pending. */
        rxe_remove(&qrl->rx_free, rxe);
        rxe_insert_tail(&qrl->rx_pending, rxe);
        return 0; /* success, did not defer */
    }

    /* Determine encryption level of packet. */
    enc_level = qrl_determine_enc_level(&rxe->hdr);

    /* If we do not have keying material for this encryption level yet, defer. */
    switch (qrl_have_el(qrl, enc_level, /*is_tx=*/0)) {
        case 1:
            /* We have keys. */
            break;
        case 0:
            /* No keys yet. */
            goto cannot_decrypt;
        default:
            /* We already discarded keys for this EL, we will never process this.*/
            goto malformed;
    }

    /*
     * We will copy any token included in the packet to the start of our RXE
     * data buffer (so that we don't reference the URXE buffer any more and can
     * recycle it). Track our position in the RXE buffer by index instead of
     * pointer as the pointer may change as reallocs occur.
     */
    i = 0;

    /*
     * rxe->hdr.data is now pointing at the (encrypted) packet payload. rxe->hdr
     * also has fields pointing into the PACKET buffer which will be going away
     * soon (the URXE will be reused for another incoming packet).
     *
     * Firstly, relocate some of these fields into the RXE as needed.
     *
     * Relocate token buffer and fix pointer.
     */
    if (rxe->hdr.type == QUIC_PKT_TYPE_INITIAL
        && !qrl_relocate_buffer(qrl, &rxe, &i, &rxe->hdr.token,
                                rxe->hdr.token_len))
        goto malformed;

    /* Now remove header protection. */
    *pkt = orig_pkt;

    if (need_second_decode) {
        if (!ossl_quic_hdr_protector_decrypt(&qrl->rx_el[enc_level].hpr, &ptrs))
            goto malformed;

        /*
         * We have removed header protection, so don't attempt to do it again if
         * the packet gets deferred and processed again.
         */
        pkt_mark(&urxe->hpr_removed, pkt_idx);

        /* Decode the now unprotected header. */
        if (ossl_quic_wire_decode_pkt_hdr(pkt, qrl->short_conn_id_len,
                                          0, &rxe->hdr, NULL) != 1)
            goto malformed;
    }

    /* Validate header and decode PN. */
    if (!qrl_validate_hdr(qrl, rxe))
        goto malformed;

    /*
     * We automatically discard INITIAL keys when successfully decrypting a
     * HANDSHAKE packet.
     */
    if (enc_level == QUIC_ENC_LEVEL_HANDSHAKE)
        qrl_el_discard(qrl, QUIC_ENC_LEVEL_INITIAL, 0, 1);

    /*
     * The AAD data is the entire (unprotected) packet header including the PN.
     * The packet header has been unprotected in place, so we can just reuse the
     * PACKET buffer. The header ends where the payload begins.
     */
    aad_len = rxe->hdr.data - sop;

    /* Ensure the RXE buffer size is adequate for our payload. */
    if ((rxe = qrl_reserve_rxe(&qrl->rx_free, rxe, rxe->hdr.len + i)) == NULL) {
        /*
         * Allocation failure, treat as malformed and do not bother processing
         * any further packets in the datagram as they are likely to also
         * encounter allocation failures.
         */
        eop = NULL;
        goto malformed;
    }

    /*
     * We decrypt the packet body to immediately after the token at the start of
     * the RXE buffer (where present).
     *
     * Do the decryption from the PACKET (which points into URXE memory) to our
     * RXE payload (single-copy decryption), then fixup the pointers in the
     * header to point to our new buffer.
     *
     * If decryption fails this is considered a permanent error; we defer
     * packets we don't yet have decryption keys for above, so if this fails,
     * something has gone wrong with the handshake process or a packet has been
     * corrupted.
     */
    dst = (unsigned char *)rxe_data(rxe) + i;
    if (!qrl_decrypt_pkt_body(qrl, dst, rxe->hdr.data, rxe->hdr.len,
                              &dec_len, sop, aad_len, rxe->pn, enc_level))
        goto malformed;

    /*
     * We have now successfully decrypted the packet payload. If there are
     * additional packets in the datagram, it is possible we will fail to
     * decrypt them and need to defer them until we have some key material we
     * don't currently possess. If this happens, the URXE will be moved to the
     * deferred queue. Since a URXE corresponds to one datagram, which may
     * contain multiple packets, we must ensure any packets we have already
     * processed in the URXE are not processed again (this is an RFC
     * requirement). We do this by marking the nth packet in the datagram as
     * processed.
     *
     * We are now committed to returning this decrypted packet to the user,
     * meaning we now consider the packet processed and must mark it
     * accordingly.
     */
    pkt_mark(&urxe->processed, pkt_idx);

    /*
     * Update header to point to the decrypted buffer, which may be shorter
     * due to AEAD tags, block padding, etc.
     */
    rxe->hdr.data       = dst;
    rxe->hdr.len        = dec_len;
    rxe->data_len       = dec_len;
    rxe->datagram_len   = datagram_len;

    /* We processed the PN successfully, so update largest processed PN. */
    pn_space = rxe_determine_pn_space(rxe);
    if (rxe->pn > qrl->rx_largest_pn[pn_space])
        qrl->rx_largest_pn[pn_space] = rxe->pn;

    /* Copy across network addresses from URXE to RXE. */
    rxe->peer   = urxe->peer;
    rxe->local  = urxe->local;

    /* Move RXE to pending. */
    rxe_remove(&qrl->rx_free, rxe);
    rxe_insert_tail(&qrl->rx_pending, rxe);
    return 0; /* success, did not defer; not distinguished from failure */

cannot_decrypt:
    /*
     * We cannot process this packet right now (but might be able to later). We
     * MUST attempt to process any other packets in the datagram, so defer it
     * and skip over it.
     */
    assert(eop != NULL && eop >= PACKET_data(pkt));
    /*
     * We don't care if this fails as it will just result in the packet being at
     * the end of the datagram buffer.
     */
    ignore_res(PACKET_forward(pkt, eop - PACKET_data(pkt)));
    return 1; /* deferred */

malformed:
    if (eop != NULL) {
        /*
         * This packet cannot be processed and will never be processable. We
         * were at least able to decode its header and determine its length, so
         * we can skip over it and try to process any subsequent packets in the
         * datagram.
         *
         * Mark as processed as an optimization.
         */
        assert(eop >= PACKET_data(pkt));
        pkt_mark(&urxe->processed, pkt_idx);
        /* We don't care if this fails (see above) */
        ignore_res(PACKET_forward(pkt, eop - PACKET_data(pkt)));
    } else {
        /*
         * This packet cannot be processed and will never be processable.
         * Because even its header is not intelligible, we cannot examine any
         * further packets in the datagram because its length cannot be
         * discerned.
         *
         * Advance over the entire remainder of the datagram, and mark it as
         * processed gap as an optimization.
         */
        pkt_mark(&urxe->processed, pkt_idx);
        /* We don't care if this fails (see above) */
        ignore_res(PACKET_forward(pkt, PACKET_remaining(pkt)));
    }
    return 0; /* failure, did not defer; not distinguished from success */
}

/* Process a datagram which was received. */
static int qrl_process_datagram(OSSL_QRL *qrl, QUIC_URXE *e,
                                const unsigned char *data,
                                size_t data_len)
{
    int have_deferred = 0;
    PACKET pkt;
    size_t pkt_idx = 0;
    RXE *first_rxe = NULL;

    qrl->bytes_received += data_len;

    if (!PACKET_buf_init(&pkt, data, data_len))
        return 0;

    for (; PACKET_remaining(&pkt) > 0; ++pkt_idx) {
        /*
         * A packet smallest than the minimum possible QUIC packet size is not
         * considered valid. We also ignore more than a certain number of
         * packets within the same datagram.
         */
        if (PACKET_remaining(&pkt) < QUIC_MIN_VALID_PKT_LEN
            || pkt_idx >= QUIC_MAX_PKT_PER_URXE)
            break;

        /*
         * We note whether packet processing resulted in a deferral since
         * this means we need to move the URXE to the deferred list rather
         * than the free list after we're finished dealing with it for now.
         *
         * However, we don't otherwise care here whether processing succeeded or
         * failed, as the RFC says even if a packet in a datagram is malformed,
         * we should still try to process any packets following it.
         *
         * In the case where the packet is so malformed we can't determine its
         * lenngth, qrl_process_pkt will take care of advancing to the end of
         * the packet, so we will exit the loop automatically in this case.
         */
        if (qrl_process_pkt(qrl, e, &pkt, pkt_idx, &first_rxe, data_len))
            have_deferred = 1;
    }

    /* Only report whether there were any deferrals. */
    return have_deferred;
}

/* Process a single pending URXE. */
static int qrl_process_one_urxl(OSSL_QRL *qrl, QUIC_URXE *e)
{
    int was_deferred;

    /* The next URXE we process should be at the head of the pending list. */
    if (!ossl_assert(e == qrl->urx_pending.head))
        return 0;

    /*
     * Attempt to process the datagram. The return value indicates only if
     * processing of the datagram was deferred. If we failed to process the
     * datagram, we do not attempt to process it again and silently eat the
     * error.
     */
    was_deferred = qrl_process_datagram(qrl, e, ossl_quic_urxe_data(e),
                                        e->data_len);

    /*
     * Remove the URXE from the pending list and return it to
     * either the free or deferred list.
     */
    ossl_quic_urxe_remove(&qrl->urx_pending, e);
    if (was_deferred > 0)
        ossl_quic_urxe_insert_tail(&qrl->urx_deferred, e);
    else
        ossl_quic_demux_release_urxe(qrl->rx_demux, e);

    return 1;
}

/* Process any pending URXEs to generate pending RXEs. */
static int qrl_process_urxl(OSSL_QRL *qrl)
{
    QUIC_URXE *e;

    while ((e = qrl->urx_pending.head) != NULL)
        if (!qrl_process_one_urxl(qrl, e))
            return 0;

    return 1;
}

int ossl_qrl_read_pkt(OSSL_QRL *qrl, OSSL_QRL_RX_PKT *pkt)
{
    RXE *rxe;

    if (!ossl_qrl_processed_read_pending(qrl)) {
        if (!qrl_process_urxl(qrl))
            return 0;

        if (!ossl_qrl_processed_read_pending(qrl))
            return 0;
    }

    rxe = qrl_pop_pending_rxe(qrl);
    if (!ossl_assert(rxe != NULL))
        return 0;

    pkt->handle     = rxe;
    pkt->hdr        = &rxe->hdr;
    pkt->peer
        = BIO_ADDR_family(&rxe->peer) != AF_UNSPEC ? &rxe->peer : NULL;
    pkt->local
        = BIO_ADDR_family(&rxe->local) != AF_UNSPEC ? &rxe->local : NULL;
    return 1;
}

void ossl_qrl_release_pkt(OSSL_QRL *qrl, void *handle)
{
    RXE *rxe = handle;

    qrl_recycle_rxe(qrl, rxe);
}

uint64_t ossl_qrl_get_bytes_received(OSSL_QRL *qrl, int clear)
{
    uint64_t v = qrl->bytes_received;

    if (clear)
        qrl->bytes_received = 0;

    return v;
}

int ossl_qrl_set_early_rx_validation_cb(OSSL_QRL *qrl,
                                        ossl_qrl_early_rx_validation_cb *cb,
                                        void *cb_arg)
{
    qrl->rx_validation_cb       = cb;
    qrl->rx_validation_cb_arg   = cb_arg;
    return 1;
}
