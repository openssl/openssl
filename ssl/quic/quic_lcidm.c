/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_lcidm.h"
#include "internal/quic_types.h"
#include "internal/quic_vlint.h"
#include "internal/common.h"
#include "crypto/siphash.h"
#include "internal/htable.h"
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * QUIC Local Connection ID Manager
 * ================================
 */

typedef struct quic_lcidm_conn_st QUIC_LCIDM_CONN;

enum {
    LCID_TYPE_ODCID, /* This LCID is the ODCID from the peer */
    LCID_TYPE_INITIAL, /* This is our Initial SCID */
    LCID_TYPE_NCID /* This LCID was issued via a NCID frame */
};

typedef struct quic_lcid_st {
    QUIC_CONN_ID cid;
    uint64_t seq_num;

    /* Back-pointer to the owning QUIC_LCIDM_CONN structure. */
    QUIC_LCIDM_CONN *conn;

    /* LCID_TYPE_* */
    unsigned int type : 2;

    OSSL_QUEUE_MEMBER(lcid); /* in QUIC_LCIDM.lcids, keyed by cid */
    OSSL_QUEUE_MEMBER(conn_lcid); /* in the owning QUIC_LCIDM_CONN.lcids */
} QUIC_LCID;

/*
 * The port-wide tables have a fixed number of buckets (32 KB and 8 KB on
 * LP64): a connection holds a few LCIDs, so chains stay short up to a few
 * thousand connections per port and only lengthen beyond that.
 */
#define LCIDM_LCID_BITS 12
#define LCIDM_CONN_BITS 10

DEFINE_QUEUE_OF(lcid, QUIC_LCID);
DEFINE_HTABLE_OF(lcid, QUIC_LCID, LCIDM_LCID_BITS);
DEFINE_QUEUE_OF(conn_lcid, QUIC_LCID);

struct quic_lcidm_conn_st {
    size_t num_active_lcid;
    OSSL_QUEUE lcids; /* this connection's QUIC_LCIDs */
    void *opaque;
    QUIC_LCID *odcid_lcid_obj;
    uint64_t next_seq_num;

    /* Have we enrolled an ODCID? */
    unsigned int done_odcid : 1;

    OSSL_QUEUE_MEMBER(lcidm_conn); /* in QUIC_LCIDM.conns, keyed by opaque */
};

DEFINE_QUEUE_OF(lcidm_conn, QUIC_LCIDM_CONN);
DEFINE_HTABLE_OF(lcidm_conn, QUIC_LCIDM_CONN, LCIDM_CONN_BITS);

struct quic_lcidm_st {
    OSSL_LIB_CTX *libctx;
    uint64_t hash_key[2]; /* random key for siphash */
    OSSL_HTABLE(lcid)
    lcids; /* (QUIC_CONN_ID) -> (QUIC_LCID *)  */
    OSSL_HTABLE(lcidm_conn)
    conns; /* (void *opaque) -> (QUIC_LCIDM_CONN *) */
    size_t lcid_len; /* Length in bytes for all LCIDs */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    QUIC_CONN_ID next_lcid;
#endif
};

static uint64_t lcid_hash(const QUIC_LCIDM *lcidm, const QUIC_CONN_ID *cid)
{
    SIPHASH siphash = {
        0,
    };
    uint64_t hashval = 0;
    unsigned char digest[SIPHASH_MIN_DIGEST_SIZE];

    /* Use a supported SipHash digest size (8 or 16); 8 is sufficient here. */
    if (!SipHash_set_hash_size(&siphash, SIPHASH_MIN_DIGEST_SIZE))
        goto out;
    if (!SipHash_Init(&siphash, (const uint8_t *)lcidm->hash_key, 0, 0))
        goto out;
    SipHash_Update(&siphash, cid->id, cid->id_len);
    if (!SipHash_Final(&siphash, digest, SIPHASH_MIN_DIGEST_SIZE))
        goto out;

    memcpy(&hashval, digest, sizeof(hashval));
out:
    return hashval;
}

QUIC_LCIDM *ossl_quic_lcidm_new(OSSL_LIB_CTX *libctx, size_t lcid_len)
{
    QUIC_LCIDM *lcidm = NULL;

    if (lcid_len > QUIC_MAX_CONN_ID_LEN)
        goto err;

    if ((lcidm = OPENSSL_zalloc(sizeof(*lcidm))) == NULL)
        goto err;

    /* generate a random key for the hash tables hash function */
    if (!RAND_bytes_ex(libctx, (unsigned char *)&lcidm->hash_key,
            sizeof(uint64_t) * 2, 0))
        goto err;

    ossl_htable_lcid_init(&lcidm->lcids);
    ossl_htable_lcidm_conn_init(&lcidm->conns);
    lcidm->libctx = libctx;
    lcidm->lcid_len = lcid_len;
    return lcidm;

err:
    OPENSSL_free(lcidm);
    return NULL;
}

static void lcidm_delete_conn(QUIC_LCIDM *lcidm, QUIC_LCIDM_CONN *conn);

static void lcidm_delete_conn_(QUIC_LCIDM_CONN *conn, void *arg)
{
    lcidm_delete_conn((QUIC_LCIDM *)arg, conn);
}

void ossl_quic_lcidm_free(QUIC_LCIDM *lcidm)
{
    if (lcidm == NULL)
        return;

    /* Deleting the visited connection is allowed during doall. */
    ossl_htable_lcidm_conn_doall_arg(&lcidm->conns, lcidm_delete_conn_, lcidm);
    OPENSSL_free(lcidm);
}

static QUIC_LCID *lcidm_get0_lcid(const QUIC_LCIDM *lcidm, const QUIC_CONN_ID *lcid)
{
    QUIC_LCID *lcid_obj;

    if (lcid->id_len > QUIC_MAX_CONN_ID_LEN)
        return NULL;

    OSSL_HTABLE_FIND(lcid_obj, lcid, &lcidm->lcids, lcid_hash(lcidm, lcid),
        ossl_quic_conn_id_eq(&lcid_obj->cid, lcid));
    return lcid_obj;
}

static QUIC_LCIDM_CONN *lcidm_get0_conn(const QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN *conn;

    OSSL_HTABLE_FIND(conn, lcidm_conn, &lcidm->conns, ossl_hash_ptr(opaque),
        conn->opaque == opaque);
    return conn;
}

static QUIC_LCIDM_CONN *lcidm_upsert_conn(QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN *conn = lcidm_get0_conn(lcidm, opaque);

    if (conn != NULL)
        return conn;

    if ((conn = OPENSSL_zalloc(sizeof(*conn))) == NULL)
        return NULL;

    ossl_queue_init(&conn->lcids);
    conn->opaque = opaque;
    ossl_htable_lcidm_conn_add(&lcidm->conns, conn, ossl_hash_ptr(opaque));
    return conn;
}

static void lcidm_delete_conn_lcid(QUIC_LCIDM *lcidm, QUIC_LCID *lcid_obj)
{
    ossl_htable_lcid_del(&lcidm->lcids, lcid_obj);
    ossl_queue_conn_lcid_del(lcid_obj);
    assert(lcid_obj->conn->num_active_lcid > 0);
    --lcid_obj->conn->num_active_lcid;
    OPENSSL_free(lcid_obj);
}

static void lcidm_delete_conn(QUIC_LCIDM *lcidm, QUIC_LCIDM_CONN *conn)
{
    QUIC_LCID *lcid_obj, *lcid_next;

    OSSL_QUEUE_FOREACH_DELSAFE (lcid_obj, lcid_next, conn_lcid, &conn->lcids)
        lcidm_delete_conn_lcid(lcidm, lcid_obj);

    ossl_htable_lcidm_conn_del(&lcidm->conns, conn);
    OPENSSL_free(conn);
}

static QUIC_LCID *lcidm_conn_new_lcid(QUIC_LCIDM *lcidm, QUIC_LCIDM_CONN *conn,
    const QUIC_CONN_ID *lcid)
{
    QUIC_LCID *lcid_obj;

    if (lcid->id_len > QUIC_MAX_CONN_ID_LEN)
        return NULL;

    if ((lcid_obj = OPENSSL_zalloc(sizeof(*lcid_obj))) == NULL)
        return NULL;

    lcid_obj->cid = *lcid;
    lcid_obj->conn = conn;

    ossl_queue_conn_lcid_add(&conn->lcids, lcid_obj);
    ossl_htable_lcid_add(&lcidm->lcids, lcid_obj, lcid_hash(lcidm, lcid));
    ++conn->num_active_lcid;
    return lcid_obj;
}

size_t ossl_quic_lcidm_get_lcid_len(const QUIC_LCIDM *lcidm)
{
    return lcidm->lcid_len;
}

size_t ossl_quic_lcidm_get_num_active_lcid(const QUIC_LCIDM *lcidm,
    void *opaque)
{
    QUIC_LCIDM_CONN *conn;

    conn = lcidm_get0_conn(lcidm, opaque);
    if (conn == NULL)
        return 0;

    return conn->num_active_lcid;
}

static int lcidm_generate_cid(QUIC_LCIDM *lcidm,
    QUIC_CONN_ID *cid)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    int i;

    lcidm->next_lcid.id_len = (unsigned char)lcidm->lcid_len;
    *cid = lcidm->next_lcid;

    for (i = lcidm->lcid_len - 1; i >= 0; --i)
        if (++lcidm->next_lcid.id[i] != 0)
            break;

    return 1;
#else
    return ossl_quic_gen_rand_conn_id(lcidm->libctx, lcidm->lcid_len, cid);
#endif
}

static int lcidm_generate(QUIC_LCIDM *lcidm,
    void *opaque,
    unsigned int type,
    QUIC_CONN_ID *lcid_out,
    uint64_t *seq_num)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID *lcid_obj;
    size_t i;
#define MAX_RETRIES 8

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if ((type == LCID_TYPE_INITIAL && conn->next_seq_num > 0)
        || conn->next_seq_num > OSSL_QUIC_VLINT_MAX)
        return 0;

    i = 0;
    do {
        if (i++ >= MAX_RETRIES)
            /*
             * Too many retries; should not happen but if it does, don't loop
             * endlessly.
             */
            return 0;

        if (!lcidm_generate_cid(lcidm, lcid_out))
            return 0;

        /* If a collision occurs, retry. */
    } while (lcidm_get0_lcid(lcidm, lcid_out) != NULL);

    if ((lcid_obj = lcidm_conn_new_lcid(lcidm, conn, lcid_out)) == NULL)
        return 0;

    lcid_obj->seq_num = conn->next_seq_num;
    lcid_obj->type = type;

    if (seq_num != NULL)
        *seq_num = lcid_obj->seq_num;

    ++conn->next_seq_num;
    return 1;
}

int ossl_quic_lcidm_enrol_odcid(QUIC_LCIDM *lcidm,
    void *opaque,
    const QUIC_CONN_ID *initial_odcid)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID *lcid_obj;

    if (initial_odcid == NULL || initial_odcid->id_len < QUIC_MIN_ODCID_LEN
        || initial_odcid->id_len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if (conn->done_odcid)
        return 0;

    if (lcidm_get0_lcid(lcidm, initial_odcid) != NULL)
        return 0;

    if ((lcid_obj = lcidm_conn_new_lcid(lcidm, conn, initial_odcid)) == NULL)
        return 0;

    lcid_obj->seq_num = LCIDM_ODCID_SEQ_NUM;
    lcid_obj->type = LCID_TYPE_ODCID;

    conn->odcid_lcid_obj = lcid_obj;
    conn->done_odcid = 1;
    return 1;
}

int ossl_quic_lcidm_generate_initial(QUIC_LCIDM *lcidm,
    void *opaque,
    QUIC_CONN_ID *initial_lcid)
{
    return lcidm_generate(lcidm, opaque, LCID_TYPE_INITIAL,
        initial_lcid, NULL);
}

int ossl_quic_lcidm_bind_channel(QUIC_LCIDM *lcidm, void *opaque,
    const QUIC_CONN_ID *lcid)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID *lcid_obj;

    /*
     * the plan is simple:
     *   make sure the lcid is still unused.
     *   do the same business as ossl_quic_lcidm_gnerate_initial() does,
     *   except we will use lcid instead of generating a new one.
     */
    if (ossl_quic_lcidm_lookup(lcidm, lcid, NULL, NULL) != 0)
        return 0;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if ((lcid_obj = lcidm_conn_new_lcid(lcidm, conn, lcid)) == NULL) {
        lcidm_delete_conn(lcidm, conn);
        return 0;
    }

    lcid_obj->seq_num = conn->next_seq_num;
    lcid_obj->type = LCID_TYPE_INITIAL;
    conn->next_seq_num++;

    return 1;
}

int ossl_quic_lcidm_generate(QUIC_LCIDM *lcidm,
    void *opaque,
    OSSL_QUIC_FRAME_NEW_CONN_ID *ncid_frame)
{
    ncid_frame->seq_num = 0;
    ncid_frame->retire_prior_to = 0;

    return lcidm_generate(lcidm, opaque, LCID_TYPE_NCID,
        &ncid_frame->conn_id,
        &ncid_frame->seq_num);
}

int ossl_quic_lcidm_retire_odcid(QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN *conn;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if (conn->odcid_lcid_obj == NULL)
        return 0;

    lcidm_delete_conn_lcid(lcidm, conn->odcid_lcid_obj);
    conn->odcid_lcid_obj = NULL;
    return 1;
}

int ossl_quic_lcidm_retire(QUIC_LCIDM *lcidm,
    void *opaque,
    uint64_t retire_prior_to,
    const QUIC_CONN_ID *containing_pkt_dcid,
    QUIC_CONN_ID *retired_lcid,
    uint64_t *retired_seq_num,
    int *did_retire)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID *lcid_obj, *earliest = NULL;

    if (did_retire == NULL)
        return 0;

    *did_retire = 0;
    if ((conn = lcidm_get0_conn(lcidm, opaque)) == NULL)
        return 1;

    /* Retire the oldest eligible LCID; the ODCID cannot be retired here. */
    OSSL_QUEUE_FOREACH (lcid_obj, conn_lcid, &conn->lcids) {
        if (lcid_obj->type == LCID_TYPE_ODCID
            || lcid_obj->seq_num >= retire_prior_to)
            continue;
        if (earliest == NULL || lcid_obj->seq_num < earliest->seq_num)
            earliest = lcid_obj;
    }
    if (earliest == NULL)
        return 1;

    if (containing_pkt_dcid != NULL
        && ossl_quic_conn_id_eq(&earliest->cid, containing_pkt_dcid))
        return 0;

    *did_retire = 1;
    if (retired_lcid != NULL)
        *retired_lcid = earliest->cid;
    if (retired_seq_num != NULL)
        *retired_seq_num = earliest->seq_num;

    lcidm_delete_conn_lcid(lcidm, earliest);
    return 1;
}

int ossl_quic_lcidm_cull(QUIC_LCIDM *lcidm, void *opaque)
{
    QUIC_LCIDM_CONN *conn;

    if ((conn = lcidm_get0_conn(lcidm, opaque)) == NULL)
        return 0;

    lcidm_delete_conn(lcidm, conn);
    return 1;
}

int ossl_quic_lcidm_lookup(QUIC_LCIDM *lcidm,
    const QUIC_CONN_ID *lcid,
    uint64_t *seq_num,
    void **opaque)
{
    QUIC_LCID *lcid_obj;

    if (lcid == NULL)
        return 0;

    if ((lcid_obj = lcidm_get0_lcid(lcidm, lcid)) == NULL)
        return 0;

    if (seq_num != NULL)
        *seq_num = lcid_obj->seq_num;

    if (opaque != NULL)
        *opaque = lcid_obj->conn->opaque;

    return 1;
}

int ossl_quic_lcidm_debug_remove(QUIC_LCIDM *lcidm,
    const QUIC_CONN_ID *lcid)
{
    QUIC_LCID *lcid_obj;

    if ((lcid_obj = lcidm_get0_lcid(lcidm, lcid)) == NULL)
        return 0;

    lcidm_delete_conn_lcid(lcidm, lcid_obj);
    return 1;
}

int ossl_quic_lcidm_debug_add(QUIC_LCIDM *lcidm, void *opaque,
    const QUIC_CONN_ID *lcid,
    uint64_t seq_num)
{
    QUIC_LCIDM_CONN *conn;
    QUIC_LCID *lcid_obj;

    if (lcid == NULL || lcid->id_len > QUIC_MAX_CONN_ID_LEN)
        return 0;

    if ((conn = lcidm_upsert_conn(lcidm, opaque)) == NULL)
        return 0;

    if (lcidm_get0_lcid(lcidm, lcid) != NULL)
        return 0;

    if ((lcid_obj = lcidm_conn_new_lcid(lcidm, conn, lcid)) == NULL)
        return 0;

    lcid_obj->seq_num = seq_num;
    lcid_obj->type = LCID_TYPE_NCID;
    return 1;
}

int ossl_quic_lcidm_get_unused_cid(QUIC_LCIDM *lcidm, QUIC_CONN_ID *cid)
{
    int i;

    for (i = 0; i < 10; i++) {
        if (lcidm_generate_cid(lcidm, cid)
            && lcidm_get0_lcid(lcidm, cid) == NULL)
            return 1; /* not found <=> radomly generated cid is unused */
    }

    return 0;
}
