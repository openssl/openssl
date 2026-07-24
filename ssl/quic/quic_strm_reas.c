/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/uint_set.h"
#include "internal/common.h"
#include "internal/quic_strm_reas.h"
#include "internal/list.h"

#if !defined(NDEBUG) && defined(WITH_SF_LIST_DEBUG)
#include <stdio.h>
#define DEBUG_PRINT(...) fprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) (void)(0)
#endif
/*
 * This is a reference counted buffer. More stream chunks can
 * share the data buffer. Each chunk keeps it's own metadata
 * to access bytes in buffer.
 */
typedef struct refbuf_t {
    uint64_t refbuf_magic;
    uint64_t refbuf_count;
    unsigned char *refbuf_buf;
} REFBUF;
#define REFBUF_MAGIC 0xf00dfeedf00dfeed

#define DIRECT_STORAGE_SZ	(2 * sizeof(void *))

/*
 * storage type indicates where stream data bytes
 * are stored.
 */
enum {
    ST_TYPE_DIRECT,	/* in chunk structure itself (sc_dstorage) */
    ST_TYPE_PKT,	/* bytes are stored in attached pkt (sc_pkt) */
    ST_TYPE_REFBUF,	/* in reference counted buffer (sc_refbuf) */
    ST_TYPE_TEST,
       /* for testing, quic_stream_test passes stream data without packet */
};

/*
 * Stream chunk keeps stream bytes as received from QUIC STREAM_FRAME.
 * Each chunk of stream data by [start, end).
 */
struct stream_chunk_t {
    OSSL_LIST_MEMBER(sc, struct stream_chunk_t);
    UINT_RANGE sc_range;
    int sc_st; /* storage type */
    union {
        const unsigned char *u_data;
        unsigned char *u_data_w;
    } sc_data_u;
    union {
        OSSL_QRX_PKT *u_sc_pkt;
        REFBUF *u_sc_refbuf;
        unsigned char u_sc_dstorage[DIRECT_STORAGE_SZ];
    } sc_storage_u;
};

#define sc_data sc_data_u.u_data
#define sc_data_w sc_data_u.u_data_w

#define sc_pkt sc_storage_u.u_sc_pkt
#define sc_refbuf sc_storage_u.u_sc_refbuf
#define sc_dstorage sc_storage_u.u_sc_dstorage

DEFINE_LIST_OF(sc, struct stream_chunk_t);

#define SCHUNK_SIZE(_sc)	((_sc)->sc_range.end - (_sc)->sc_range.start)
#define SRANGE_SIZE(_sr)	((_sr)->sr_range.end - (_sr)->sr_range.start)

/*
 * Range is keeps list of continuous stream chunks. The range
 * is also defined by [start, end) interval. For every chunk
 * in range this assertion must hold:
 *    sc->sc_range.end == sc->sc_next->sc_range.start
 *
 * If newly arriving stream chunk can not be inserted to existing
 * stream range, then new range must be created.
 */
struct stream_range_t {
    OSSL_LIST(sc) sr_chunks;
    OSSL_RBT_ENTRY(stream_range_t) sr_rbe;
    UINT_RANGE sr_range;
    struct stream_chunk_t *sr_it_sc; /* iterator */
};

static int srange_cmp(const struct stream_range_t *, const struct stream_range_t *);

OSSL_RBT_PROTOTYPE(srange, stream_range_t, sr_rbe, srange_cmp)

OSSL_RBT_GENERATE(srange, stream_range_t, sr_rbe, srange_cmp);

#define UINT64_TO_SIZE_T(_x) ((size_t)(((_x) > SIZE_MAX) ? SIZE_MAX : (_x)))

static REFBUF *refbuf_alloc(uint64_t sz)
{
    REFBUF *refbuf;

    refbuf = OPENSSL_malloc(sizeof(*refbuf) + UINT64_TO_SIZE_T(sz));
    if (refbuf == NULL)
        return NULL;

    refbuf->refbuf_magic = REFBUF_MAGIC;
    refbuf->refbuf_count = 1;
    refbuf->refbuf_buf = (unsigned char *)(&refbuf[1]);

    return refbuf;
}

static REFBUF *refbuf_dup(REFBUF *refbuf)
{
    if (refbuf == NULL)
        return NULL;

    assert(refbuf->refbuf_magic == REFBUF_MAGIC);
    refbuf->refbuf_count++;

    return refbuf;
}

static void refbuf_free(REFBUF *refbuf)
{
    if (refbuf == NULL)
        return;

    assert(refbuf->refbuf_magic == REFBUF_MAGIC);
    refbuf->refbuf_count--;
    if (refbuf->refbuf_count == 0)
        OPENSSL_free(refbuf);

    return;
}

static unsigned char *refbuf_to_buf(REFBUF *refbuf)
{
    if (refbuf == NULL)
        return NULL;

    assert(refbuf->refbuf_magic == REFBUF_MAGIC);
    return refbuf->refbuf_buf;
}

static int srange_cmp(const struct stream_range_t *a_sr,
    const struct stream_range_t *b_sr)
{
    assert(a_sr->sr_range.start < a_sr->sr_range.end);
    assert(b_sr->sr_range.start < b_sr->sr_range.end);
    /*
     * no overlap, A precedes B
     */
    if (a_sr->sr_range.end < b_sr->sr_range.start)
        return -1;

    /*
     * no overlap A follows B
     */
    if (a_sr->sr_range.start > b_sr->sr_range.end)
        return 1;

    /*
     * partial or full overlap or ranges are adjacent.
     * the program needs to do close examination on
     * how to add new chunk to existing stream range.
     */
    return 0;
}

static int keep_schunk_data_on_packet(SFRAME_SET *fs, OSSL_QRX_PKT *pkt,
    UINT_RANGE *r)
{
    /*
     * the function decides whether stream data should be moved
     * from packet buffer to stream buffer or if data can stay
     * at packet buffer.
     *
     * Keeping the data at packet saves yet another buffer
     * allocation at heap (+ data transfer). On the other hand
     * it opens door to malicious peer to force stack to use more
     * memory than necessary.
     *
     * The function here should asses a current stream quality:
     *   how many stream chunks are there
     *   the time elapsed since the arrival of earlier chunk
     *   the time elapsed since the application consumed the data
     *   the size of the chunk compared with the whole packet size
     *   the size of chunk with respect to DIRECT_STORAGE_SZ
     *   ...
     * the code to collect those parmeters is still missing, once
     * this gap will be filled this function will be able to
     * make the decision.
     */

    return 1;
}

static struct stream_chunk_t *new_schunk(SFRAME_SET *fs, OSSL_QRX_PKT *pkt,
    UINT_RANGE *r, const unsigned char *data)
{
    struct stream_chunk_t *sc;
    uint64_t rsize;

    sc = OPENSSL_zalloc(sizeof(*sc));
    if (sc == NULL)
        return NULL;

    /*
     * production code never ever passes NULL for pkt.
     * so if pkt is NULL, then we run under test.
     */
    if (pkt == NULL) {
        sc->sc_st = ST_TYPE_TEST;
        sc->sc_data = data;
        sc->sc_range = *r;
        /*
         * this is for debugging, copies data to chunk buffer
         */
        if (fs->move_buffers) {
            rsize = r->end - r->start;
            if (rsize <= DIRECT_STORAGE_SZ) {
                sc->sc_st = ST_TYPE_DIRECT;
                sc->sc_data_w = sc->sc_dstorage;
            } else {
                sc->sc_st = ST_TYPE_REFBUF;
                sc->sc_refbuf = refbuf_alloc(rsize);
                if (sc->sc_refbuf == NULL) {
                    OPENSSL_free(sc);
                    return NULL;
                }
                sc->sc_data_w = refbuf_to_buf(sc->sc_refbuf);
            }
            sc->sc_range = *r;
            memcpy(sc->sc_data_w, data, UINT64_TO_SIZE_T(rsize));
        }
        return sc;
    }

    if (keep_schunk_data_on_packet(fs, pkt, r) == 1) {
        sc->sc_st = ST_TYPE_PKT;
        sc->sc_pkt = pkt;
        ossl_qrx_pkt_up_ref(pkt);
        sc->sc_data = data;
        sc->sc_range = *r;
    } else {
        rsize = r->end - r->start;
        if (rsize <= DIRECT_STORAGE_SZ) {
            sc->sc_st = ST_TYPE_DIRECT;
            sc->sc_data_w = sc->sc_dstorage;
        } else {
            sc->sc_st = ST_TYPE_REFBUF;
            sc->sc_refbuf = refbuf_alloc(rsize);
            if (sc->sc_refbuf == NULL) {
                OPENSSL_free(sc);
                return NULL;
            }
            sc->sc_data_w = refbuf_to_buf(sc->sc_refbuf);
        }
        sc->sc_range = *r;
        memcpy(sc->sc_data_w, data, UINT64_TO_SIZE_T(rsize));
    }

    return sc;
}

static void destroy_schunk(SFRAME_SET *fs, struct stream_chunk_t *sc)
{
    if (sc == NULL)
        return;

    /*
     * ST_TYPE_TEST is used for testing only. The data are allocated
     * by caller. The caller must make sure the _TEST data for cleanse
     * operation are allocated either at stack or at heap. If they are
     * 'static const char *', then the _cleanse() may crash.
     */
    if (fs->cleanse)
        OPENSSL_cleanse(sc->sc_data_w, UINT64_TO_SIZE_T(SCHUNK_SIZE(sc)));

    switch (sc->sc_st) {
    case ST_TYPE_PKT:
        ossl_qrx_pkt_release(sc->sc_pkt);
        break;
    case ST_TYPE_REFBUF:
        refbuf_free(sc->sc_refbuf);
        break;
    case ST_TYPE_TEST:
        break;
    default:
        assert(sc->sc_st == ST_TYPE_DIRECT);
    }

    OPENSSL_free(sc);
}

static struct stream_chunk_t *copy_schunk(struct stream_chunk_t *sc)
{
    struct stream_chunk_t *copy_sc;

    copy_sc = OPENSSL_zalloc(sizeof(*copy_sc));
    if (copy_sc != NULL) {
        copy_sc->sc_range = sc->sc_range;
        copy_sc->sc_st = sc->sc_st;
        switch (sc->sc_st) {
        case ST_TYPE_PKT:
            copy_sc->sc_pkt = sc->sc_pkt;
            ossl_qrx_pkt_up_ref(copy_sc->sc_pkt);
            copy_sc->sc_data = sc->sc_data;
            break;
        case ST_TYPE_REFBUF:
            copy_sc->sc_refbuf = refbuf_dup(sc->sc_refbuf);
            copy_sc->sc_data = sc->sc_data;
            break;
        case ST_TYPE_TEST:
            copy_sc->sc_data = sc->sc_data;
            break;
        default:
            assert(sc->sc_st == ST_TYPE_DIRECT);
            memcpy(copy_sc->sc_dstorage, sc->sc_dstorage, DIRECT_STORAGE_SZ);
            copy_sc->sc_data_w = copy_sc->sc_dstorage;
        }
    }

    return copy_sc;
}

static struct stream_range_t *new_srange(void)
{
    struct stream_range_t *sr;

    sr = OPENSSL_zalloc(sizeof(*sr));
    if (sr != NULL) {
        ossl_list_sc_init(&sr->sr_chunks);
    }

    return sr;
}

static void destroy_srange(SFRAME_SET *fs, struct stream_range_t *sr)
{
    struct stream_chunk_t *sc;

    if (sr == NULL)
        return;

    assert(sr->sr_rbe.rb_parent == NULL);
    assert(sr->sr_rbe.rb_left == NULL);
    assert(sr->sr_rbe.rb_right == NULL);

    while ((sc = ossl_list_sc_head(&sr->sr_chunks)) != NULL) {
        ossl_list_sc_remove(&sr->sr_chunks, sc);
        fs->stream_chunks--;
        destroy_schunk(fs, sc);
    }

    OPENSSL_free(sr);
}

static struct stream_range_t *create_range(SFRAME_SET *fs,
    struct stream_chunk_t *sc)
{
    struct stream_range_t *sr;

    assert(sc != NULL);

    sr = new_srange();
    if (sr != NULL) {
        ossl_list_sc_insert_head(&sr->sr_chunks, sc);
        sr->sr_range = sc->sc_range;
        fs->stream_chunks++;
    }

    return sr;
}

void ossl_sframe_set_init(SFRAME_SET *fs)
{
    memset(fs, 0, sizeof(*fs));
    OSSL_RBT_INIT(srange, &fs->ranges);
}

static uint64_t get_sc_dstorage_sz(struct stream_chunk_t *sc)
{
    uint64_t sz = 0;

    if (sc->sc_st == ST_TYPE_DIRECT && SCHUNK_SIZE(sc) < DIRECT_STORAGE_SZ)
        sz = DIRECT_STORAGE_SZ - SCHUNK_SIZE(sc);

    return sz;
}

/*
 * adds new stream data bytes to direct storage in existing stream chunk.
 * the new data are added to the end.  each stream chunk has DIRECT_STORAGE_SZ
 * buffer to keep short data chunks.  The direct storage is used when data
 * should be moved from packet buffer to stream buffer as soon as they are
 * received.
 */
static int append_to_dstorage(struct stream_range_t *sr, UINT_RANGE *r,
    const unsigned char *data)
{
    int ok = 0;
    uint64_t dsize;
    uint64_t rsize;
    struct stream_chunk_t *sc;
    UINT_RANGE r_local;

    sc = ossl_list_sc_tail(&sr->sr_chunks);
    /*
     * each range has at least one chunk.
     */
    assert(sc != NULL);

    if (sc->sc_st != ST_TYPE_DIRECT)
        return 0;

    /*
     * can not append, because existing chunk sc, follows the newly
     * added chunk.
     */
    if (sc->sc_range.end >= r->end)
        return 0;

    /*
     * there must be no gap to add short chunk existing chunk
     */
    if (sc->sc_range.end < r->start)
        return 0;
    r_local = *r;

    /*
     * partial overlap: move start of newly received chunk forward
     * (chop new head)
     */
    if (r_local.start < sc->sc_range.end) {
        r_local.start = sc->sc_range.end;
    }

    rsize = (r_local.end - r_local.start);
    /*
     * rsize can not be 0, case where the new whole chunk is part of existing
     * range is handled in our caller (ossl_sframe_list_insert())
     */
    assert(rsize > 0);
    dsize = get_sc_dstorage_sz(sc);
    if (rsize <= dsize) {
        memcpy(&sc->sc_data_w[sc->sc_range.end], data, UINT64_TO_SIZE_T(rsize));
        assert((sc->sc_range.end + rsize) == r->end);
        sc->sc_range.end += rsize;
        assert(SCHUNK_SIZE(sc) <= DIRECT_STORAGE_SZ);
        sr->sr_range.end = sc->sc_range.end;
        ok = 1;
        /*
         * we could copy just bytes which fit to chunk and tell caller
         * to allocate additional chunk for data which don't fit.
         * however this is extreme case already to bother, at least for now.
         */
    }

    return ok;
}

/*
 * adds new stream data bytes to direct storage in existing stream chunk.
 * the new data are added to the start. The existing data must be moved
 * towards the end of direct storage buffer to make space for new data.
 * This makes the prepend operation more expensive than append.
 * The direct storage is used when data should be moved from packet buffer to
 * stream buffer as soon as they are received.
 */
static int prepend_to_dstorage(struct stream_range_t *sr, UINT_RANGE *r,
    const unsigned char *data)
{
    int ok = 0;
    uint64_t dsize;
    uint64_t rsize;
    struct stream_chunk_t *sc;
    UINT_RANGE r_local;

    sc = ossl_list_sc_head(&sr->sr_chunks);
    /*
     * each range has at least one chunk.
     */
    assert(sc != NULL);

    if (sc->sc_st != ST_TYPE_DIRECT)
        return 0;

    /*
     * can not be prepended, new data we try to prepend actually follow the
     * existing chunk sc. 
     */
    if (sc->sc_range.start <= r->start)
        return 0;

    /*
     * there must be no gap to prepend the chunk to direct storage.
     */
    if (r->end < sc->sc_range.start)
        return 0;

    r_local = *r;

    /*
     * partial overlap: move end of newly received chunk backward
     * (chop new tail)
     */
    if (r_local.end > sc->sc_range.start) {
        r_local.end = sc->sc_range.start;
    }
    rsize = (r_local.end - r_local.start);
    /*
     * rsize can not be 0, case where the new whole chunk is part of existing
     * range is handled in our caller (ossl_sframe_list_insert())
     */
    assert(rsize > 0);
    dsize = get_sc_dstorage_sz(sc);
    if (rsize <= dsize) {
        memmove(&sc->sc_data_w[rsize], sc->sc_data_w,
            UINT64_TO_SIZE_T(SCHUNK_SIZE(sc)));
        memcpy(sc->sc_data_w, data, UINT64_TO_SIZE_T(rsize));
        sc->sc_range.start = r->start;
        assert(SCHUNK_SIZE(sc) <= DIRECT_STORAGE_SZ);
        sr->sr_range.start = sc->sc_range.start;
        ok = 1;
    }

    return ok;
}

/*
 * inserts newly received chunk to the head of chunk list.
 * the newly received chunk is trimmed, so its end aligns with
 * the start of the first chunk in the range.
 */
static void prepend_chunk(SFRAME_SET *fs, struct stream_range_t *sr,
    struct stream_chunk_t *sc)
{
    assert(sc->sc_range.start < sc->sc_range.end);
    assert(sr->sr_range.start > sc->sc_range.start);
    DEBUG_PRINT(stderr, "%s %p [ %llu, %llu ] \\ ", __func__,
        sc, sc->sc_range.start, sc->sc_range.end);
    assert(sc->sc_range.end >= sr->sr_range.start);
    if (fs->cleanse)
        OPENSSL_cleanse(sc->sc_data_w,
            UINT64_TO_SIZE_T(sc->sc_range.end - sr->sr_range.start));
    sc->sc_range.end = sr->sr_range.start;
    DEBUG_PRINT(stderr, "[ %llu, %llu ] -> ",
        sc->sc_range.start, sc->sc_range.end);
    ossl_list_sc_insert_head(&sr->sr_chunks, sc);
    /* update start of the range */
    sr->sr_range.start = sc->sc_range.start;
    DEBUG_PRINT(stderr, "%p [ %llu, %llu ]\n",
        sr, sr->sr_range.start, sr->sr_range.end);
    fs->stream_chunks++;
}

/*
 * inserts newly received chunk to the tail of chunk list.
 * The start of newly received chunk is trimmed so it is
 * aligned with end of the last chunk.
 */
static void append_chunk(SFRAME_SET *fs, struct stream_range_t *sr,
    struct stream_chunk_t *sc)
{
    assert(sc->sc_range.start < sc->sc_range.end);
    assert(sr->sr_range.end < sc->sc_range.end);
    if (fs->cleanse)
        OPENSSL_cleanse(sc->sc_data_w,
            UINT64_TO_SIZE_T(sr->sr_range.end - sc->sc_range.start));
    sc->sc_data += (sr->sr_range.end - sc->sc_range.start);
    DEBUG_PRINT(stderr, "%s %p [ %llu, %llu ] \\ ", __func__,
        sc, sc->sc_range.start, sc->sc_range.end);
    sc->sc_range.start = sr->sr_range.end;
    DEBUG_PRINT(stderr, "[ %llu, %llu ] -> ",
        sc->sc_range.start, sc->sc_range.end);
    ossl_list_sc_insert_tail(&sr->sr_chunks, sc);
    /* update end of the range */
    sr->sr_range.end = sc->sc_range.end;
    DEBUG_PRINT(stderr, "%p [ %llu, %llu ]\n",
        sr, sr->sr_range.start, sr->sr_range.end);
    fs->stream_chunks++;
}

/*
 * The newly received chunk includes the whole existing range (list of chunks
 * received earlier).
 *    (sr->sr_range.start > sc->sc_range.start &&
 *        sr->range.end < sc->sc_range.end)
 * This function copies received chunk sc. The sc is inserted to
 * the head of chunks, copy is added to the tail of the chunks.
 */
static int sandwich_chunk(SFRAME_SET *fs, struct stream_range_t *sr,
    struct stream_chunk_t *sc)
{
    int rv = 0;
    struct stream_chunk_t *copy_sc;

    /*
     * the new chunk (sc) includes entire range. Create extra copy which is
     * appended and sc is prepended.
     */
    copy_sc = copy_schunk(sc);
    if (copy_sc != NULL) {
        DEBUG_PRINT(stderr, "%s %p [ %llu, %llu ] -> ",
            __func__, sc, sc->sc_range.start, sc->sc_range.end);
        sc->sc_range.end = sr->sr_range.start;
        /*
         * note: the chunk can degenerate to empty chunk, hence '<='
         * is used. the empty chunk should be discarded later after
         * insertion attempt (call to prepend_chunk()/append_chunk().
         */
        assert(sc->sc_range.start <= sc->sc_range.end);

        assert(copy_sc->sc_range.start <= sr->sr_range.end);
        if (fs->cleanse)
            OPENSSL_cleanse(copy_sc->sc_data_w,
                UINT64_TO_SIZE_T(sr->sr_range.end - copy_sc->sc_range.start));
        copy_sc->sc_data += (sr->sr_range.end - copy_sc->sc_range.start);
        copy_sc->sc_range.start = sr->sr_range.end;

        /*
         * note: the chunk might become empty
         */
        assert(copy_sc->sc_range.start <= copy_sc->sc_range.end);

        DEBUG_PRINT(stderr,
            "%s head: %p [ %llu, %llu ] tail: %p [ %llu, %llu ]\n",
            __func__, sc, sc->sc_range.start, sc->sc_range.end,
            copy_sc, copy_sc->sc_range.start, copy_sc->sc_range.end);

        if (sc->sc_range.start < sr->sr_range.start) {
            prepend_chunk(fs, sr, sc);
            sc = NULL;
        } else {
            DEBUG_PRINT(stderr,
                "%s head chunk overlaps %p [ %llu, %llu ] "
                "with range %p [ %llu, %llu ]\n", __func__,
                sc, sc->sc_range.start, sc->sc_range.end,
                sr, sr->sr_range.start, sr->sr_range.end);
            destroy_schunk(fs, sc);
        }

        if (copy_sc->sc_range.end > sr->sr_range.end) {
            append_chunk(fs, sr, copy_sc);
            copy_sc = NULL;
        } else {
            DEBUG_PRINT(stderr,
                "%s tail chunk overlaps %p [ %llu, %llu ] "
                "with range %p [ %llu, %llu ]\n", __func__,
                copy_sc, copy_sc->sc_range.start, copy_sc->sc_range.end,
                sr, sr->sr_range.start, sr->sr_range.end);
            destroy_schunk(fs, copy_sc);
        }

        /*
         * it is an error if head, nor tail got linked to range.
         */
        if (sc != NULL && copy_sc != NULL)
            rv = 0;
        else
            rv = 1;
        assert(rv == 1);
    }

    return rv;
}

static struct stream_range_t *find_range(SFRAME_SET *fs,
    struct stream_range_t *key)
{
    struct stream_range_t *sr = NULL;

    if (!OSSL_RBT_EMPTY(srange, &fs->ranges))
        sr = OSSL_RBT_FIND(srange, &fs->ranges, key);

    return sr;
}

/*
 * This function help us to merge two ranges (list of chunks)
 * into single range. Function moves the start of the range
 * towards end. It effectively chops n first chunks until
 * new_start found.
 */
static int chop_range(SFRAME_SET *fs, struct stream_range_t *sr,
    uint64_t new_start)
{
    struct stream_chunk_t *sc;

    assert(sr->sr_range.start <= new_start);

    while ((sc = ossl_list_sc_head(&sr->sr_chunks)) != NULL) {
        if (sc->sc_range.end <= new_start) {
            ossl_list_sc_remove(&sr->sr_chunks, sc);
            fs->stream_chunks--;
            destroy_schunk(fs, sc);
        } else {
            break;
        }
    }

    if (sc == NULL)
        return 0;

    assert(new_start >= sc->sc_range.start);

    if (fs->cleanse)
        OPENSSL_cleanse(sc->sc_data_w,
            UINT64_TO_SIZE_T(new_start - sc->sc_range.start));
    sc->sc_data += (new_start - sc->sc_range.start);
    sc->sc_range.start = new_start;
    sr->sr_range.start = new_start;

    return 1;
}

/*
 * function merges two with full overlap. The super_sr range
 * contains the whole sub_sr range. The function destroys
 * sub_sr and returns super_sr.
 */
static struct stream_range_t *merge_ranges(SFRAME_SET *fs,
    struct stream_range_t *super_sr, struct stream_range_t *sub_sr)
{
    /*
     * both ranges must not be empty
     */
    assert(super_sr->sr_range.start < super_sr->sr_range.end);
    assert(sub_sr->sr_range.start < sub_sr->sr_range.end);
    /*
     * sub_sr and super_sr are equal ranges (sets)  super_sr
     * sub_sr is subset of super_sr (super_sr includes sub_sr).
     */
    assert(super_sr->sr_range.start <= sub_sr->sr_range.start &&
        super_sr->sr_range.end >= sub_sr->sr_range.end);

    DEBUG_PRINT(stderr, "%s super: %p [ %llu, %llu ], sub: %p [ %llu, %llu]\n",
        __func__, super_sr, super_sr->sr_range.start, super_sr->sr_range.end,
        sub_sr, sub_sr->sr_range.start, sub_sr->sr_range.end);
    destroy_srange(fs, sub_sr);

    return super_sr;
}

/*
 * The ranges are either adjacent
 * (left_sr->sr_range.end == right_sr->sr_range.end) or there
 * is partial overlap between left_sr and right_sr(
 * (left_sr->sr_range.end >= right_sr->sr_range.start).
 * If there is partial overlap, then the right range is chopped
 * so its start is aligned with left_sr.
 */
static struct stream_range_t *append_range(SFRAME_SET *fs,
    struct stream_range_t *left_sr, struct stream_range_t *right_sr)
{
    /*
     * both ranges must not be empty
     */
    assert(left_sr->sr_range.start < left_sr->sr_range.end);
    assert(right_sr->sr_range.start < right_sr->sr_range.end);
    /*
     * right range follows left range (left < right)
     */
    assert(left_sr->sr_range.end >= right_sr->sr_range.start);

    DEBUG_PRINT(stderr, "%s %p [ %llu, %llu ] + %p [ %llu, %llu ] = %p ",
        __func__, left_sr, left_sr->sr_range.start, left_sr->sr_range.end,
        right_sr, right_sr->sr_range.start, right_sr->sr_range.end, left_sr);

    /*
     * make sure there is no overlap between ranges
     *    (right_sr->sr_range.start == left_sr->sr_range.end)
     */
    if (chop_range(fs, right_sr, left_sr->sr_range.end) == 0)
        return NULL;

    ossl_list_sc_append(&left_sr->sr_chunks, &right_sr->sr_chunks);
    left_sr->sr_range.end = right_sr->sr_range.end;
    DEBUG_PRINT(stderr, "[ %llu, %llu ]\n",
        left_sr->sr_range.start, left_sr->sr_range.end);

    destroy_srange(fs, right_sr);

    return left_sr;
}

/*
 * receives a chunk of data from stream frame.
 */
int ossl_sframe_set_insert(SFRAME_SET *fs, UINT_RANGE *r, OSSL_QRX_PKT *pkt,
    const unsigned char *data, int fin)
{
    struct stream_range_t *sr = NULL;
    struct stream_range_t *adjacent_sr = NULL;
    struct stream_range_t *joined_sr = NULL;
    struct stream_chunk_t *sc = NULL;
    struct stream_range_t key_sr;

    /*
     * receive the FIN frame if FIN frame. If FIN was not seen yet,
     * then record FIN's offset (r->end). If FIN was received then
     * verify FIN's offset match, error out on mismatch.
     */
    if (fin != 0) {
        if (fs->fin == 0) {
            fs->fin = 1;
            fs->fin_off = r->end;
        } else if (fs->fin_off != r->end) {
            return 0;
        }
    }

    /*
     * discard any data past FIN offset (of FIN offset is set).
     */
    if (fs->fin != 0) {
        if (fs->fin_off < r->end)
            r->end = fs->fin_off; /* truncate bytes beyond FIN */
        if (fs->fin_off < r->start)
            return 0;
    }

    if (r->end <= fs->offset) {
        /*
         * retransmitted range got consumed already.
         */
        DEBUG_PRINT(stderr, "%s [ %llu, %llu ] <= %llu\n", __func__,
            r->start, r->end, fs->offset);
        return 1;
    }

    if (r->start < fs->offset) {
        /*
         * make sure retransmitted chunk does not reintroduce
         * bytes which were consumed already.
         */
        DEBUG_PRINT(stderr, "%s [ %llu, %llu ] -> [ %llu, %llu ]\n", __func__,
            r->start, r->end, fs->offset, r->end);
        data += (fs->offset - r->start);
        r->start = fs->offset;
    }

    key_sr.sr_range = *r;

    /*
     *empty, 0 size chunk can carry FIN bit only,
     * FIN has been just handled
     */
    if (r->start == r->end)
        return 1;

    assert(r->start < r->end);

    if ((sr = find_range(fs, &key_sr)) == NULL) {
        sc = new_schunk(fs, pkt, r, data);
        if (sc == NULL)
            goto err;

        sr = create_range(fs, sc);
        if (sr == NULL)
            goto err;
        DEBUG_PRINT(stderr, "%s chunk: %p [ %llu, %llu ] new range: %p\n",
            __func__, sc, sc->sc_range.start, sc->sc_range.end, sr);
        sc = NULL;
        OSSL_RBT_INSERT(srange, &fs->ranges, sr);
        fs->stream_ranges++;
    } else {
        /*
         * retransmission, the whole chunk is found in existing range already
         */
        if (r->start >= sr->sr_range.start && r->end <= sr->sr_range.end) {
            DEBUG_PRINT(stderr,
                "%s [ %llu, %llu ] found in %p [ %llu, %llu ]\n", __func__,
                r->start, r->end, sr, sr->sr_range.start, sr->sr_range.end);
            goto done; /* range is present already, ?does it match? */
        }

        /*
         * try to place chunk to direct storage first. If it fails, then
         * allocate a new chunk.
         */
        if (append_to_dstorage(sr, r, data) == 1)
            goto done;
        /*
         * rare case: there is a single chunk in range and bytes (chunks)
         * arrive in reversed order, is it worth to handle? -- shrug
         */
        if (prepend_to_dstorage(sr, r, data) == 1)
            goto done;

        sc = new_schunk(fs, pkt, r, data);
        if (sc == NULL) {
            sr = NULL;
            goto err;
        }
        DEBUG_PRINT(stderr, "%s %p [ %llu, %llu ] -> %p [ %llu, %llu ]\n",
            __func__, sc, sc->sc_range.start, sc->sc_range.end,
            sr, sr->sr_range.start, sr->sr_range.end);

        /*
         * snadwich, append, prepend can still be improved to handle
         * chunks with direct storage better, but I don't think it's
         * worth the effort. out of order short data chunks (less
         * than DIRECT_STORAGE_SZ) should be considered exceptional.
         */
        if (sc->sc_range.start < sr->sr_range.start &&
            sc->sc_range.end > sr->sr_range.end)
            sandwich_chunk(fs, sr, sc); /* new chunk includes the whole range */
        else if (sc->sc_range.end > sr->sr_range.end &&
            sc->sc_range.start <= sr->sr_range.end)
            append_chunk(fs, sr, sc);
        else if (sc->sc_range.start < sr->sr_range.start &&
            sc->sc_range.end >= sr->sr_range.start)
            prepend_chunk(fs, sr, sc);
        else
            assert(NULL);	/* unreachable */

        /*
         * range got updated we may need to join updated range with
         * another ranges which exist in tree. The current range
         * is removed here and used as a search key. If nothing is found
         * range is inserted back to tree.
         *
         * if another range is found the ranges are merged to single
         * range. The process repeats (merging ranges may be cascade effect,
	 * where more ranges collapse to single range).  The merge result is
	 * removed from tree and used as a search key to find another range.
         * if nothing is found then update is done. otherwise the ranges
         * are merged again.
         */
        OSSL_RBT_REMOVE(srange, &fs->ranges, sr);
        fs->stream_ranges--;
        /*
         * _INSERT() returns range where sr needs to be joined
         */
        adjacent_sr = OSSL_RBT_INSERT(srange, &fs->ranges, sr);

        while (adjacent_sr != NULL) {
            OSSL_RBT_REMOVE(srange, &fs->ranges, adjacent_sr);
            DEBUG_PRINT(stderr, "%s %p [ %llu, %llu ] >< %p [ %llu, %llu ]\n",
                __func__, sr, sr->sr_range.start, sr->sr_range.end, adjacent_sr,
                adjacent_sr->sr_range.start, adjacent_sr->sr_range.end);
            fs->stream_ranges--;

            if (sr->sr_range.start <= adjacent_sr->sr_range.start &&
                sr->sr_range.end >= adjacent_sr->sr_range.end) {
                /*
                 *  adjacent_sr subset of sr
                 */
                joined_sr = merge_ranges(fs, sr, adjacent_sr);
            } else if (sr->sr_range.start >= adjacent_sr->sr_range.start &&
                sr->sr_range.end <= adjacent_sr->sr_range.end) {
                /*
                 *  sr subset of adjacent_sr
                 */
                joined_sr = merge_ranges(fs, adjacent_sr, sr);
            } else if (sr->sr_range.start < adjacent_sr->sr_range.start &&
                sr->sr_range.end >= adjacent_sr->sr_range.start) {
                /*
                 * adjacent_sr follows sr
                 */
                assert(sr->sr_range.end < adjacent_sr->sr_range.end);
                joined_sr = append_range(fs, sr, adjacent_sr);
            } else if (sr->sr_range.start <= adjacent_sr->sr_range.end &&
                sr->sr_range.end > adjacent_sr->sr_range.end) {
                /*
                 *  sr follows adjacent_sr
                 */
                assert(sr->sr_range.end > adjacent_sr->sr_range.end);
                joined_sr = append_range(fs, adjacent_sr, sr);
            } else {
                assert(NULL); /* never happens */
                joined_sr = NULL;
            }
            if (joined_sr == NULL)
                goto err;

            sr = joined_sr;
            adjacent_sr = OSSL_RBT_INSERT(srange, &fs->ranges, sr);
        }
        fs->stream_ranges++;
    }

done:
    return 1;

err:
    destroy_schunk(fs, sc);
    destroy_srange(fs, sr);
    destroy_srange(fs, adjacent_sr);
    /*
     * not enough memory (or another serious error) has occurred,
     * any error here is fatal as some stream chunks could be ACKed
     * already (RFC 9000, 31.1 Packet processing). At least stream
     * needs to be reset. Preferred action is to close connection.
     */

    return 0;
}

/*
 * peeks over the continuous range which is ready to
 * read. ready to read means the fs->offset must be
 * found in range. Also fs->offset can not reach past
 * the first gap in stream data received so far, thus
 * the only range we can use for peek operation is
 * OSSL_RBT_MIN(&fs->ranges).
 *
 * NOTE: it is unsafe to carry more _peek() operations
 * over single SFRMAE_SET.
 */
int ossl_sframe_set_peek(SFRAME_SET *fs, void **iterator,
    UINT_RANGE *range, const unsigned char **data,
    int *fin)
{
    uint64_t start;
    struct stream_range_t *sr = (struct stream_range_t *) *iterator;
    struct stream_chunk_t *sc = NULL;

    if (sr == NULL) {
        sr = OSSL_RBT_MIN(srange, &fs->ranges);
        start = fs->offset;
        if (sr != NULL) {
            sc = ossl_list_sc_head(&sr->sr_chunks);
            sr->sr_it_sc = NULL;
            assert(sc->sc_range.start == sr->sr_range.start);
        }
        /*
         * no chunks are ready to be consumed, if there is a gap.
         */
        if (sc == NULL || sc->sc_range.start > start)
            sc = NULL;
    } else if (sr == OSSL_RBT_MIN(srange, &fs->ranges) && sr->sr_it_sc != NULL) {
        /*
         * sr == _RB_MIN(), revalidates iterator in case the range we
         * work with disapears because it's got joined with other range
         * after new chunk arrival. perhaps not issue now as those operations
         * are mutually exclusive now.
         *
         * sr->sr_it_sc becomes NULL on _move() or _flatten() operation.
         *
         * We may need to revisit iterator implementation as current
         * iterator supports one caller only.
         */
        start = sr->sr_it_sc->sc_range.end;
        sc = ossl_list_sc_next(sr->sr_it_sc);
        assert(sc == NULL || sc->sc_range.start == start);
        assert(sc == NULL || sc->sc_range.start < sc->sc_range.end);
    } else {
        /* iterator got invalidated by move/flatten operation on range */
        DEBUG_PRINT(stderr, "%s iterator got invalidated\n", __func__);
        return 0;
    }

    range->start = start;

    if (sc == NULL) {
        range->end = start;
        *data = NULL;
        *iterator = NULL;

        /* set fin only if we are at the end */
        if (sc == NULL && (sr == NULL || OSSL_RBT_NEXT(srange, sr) == NULL))
            *fin = fs->fin;
        else
            *fin = 0;

        DEBUG_PRINT(stderr, "%s no more chunks\n", __func__);

        return 0;
    }

    range->end = sc->sc_range.end;
    /* chunk keeps data always attached, data dies with chunk */
    assert(sc->sc_data != NULL);
    assert(sc->sc_range.start <= start);
    *data = sc->sc_data + (start - sc->sc_range.start);
    if (sc == ossl_list_sc_tail(&sr->sr_chunks) &&
        OSSL_RBT_NEXT(srange, sr) == NULL)
        *fin = fs->fin;
    else
        *fin = 0;
    if (sr->sr_it_sc != NULL)
        DEBUG_PRINT(stderr, "%s %p [ %llu, %llu ] %p [ %llu, %llu ]\n",
            __func__, sr->sr_it_sc,
            sr->sr_it_sc->sc_range.start, sr->sr_it_sc->sc_range.end,
            sc, sc->sc_range.start, sc->sc_range.end);

    sr->sr_it_sc = sc;
    *iterator = sr;

    /*
     * peek operation indicates error if there are no data to read
     * in range.
     */
    DEBUG_PRINT(stderr,
        "%s peek range: [ %llu, %llu ] range: %p [ %llu, %llu ]\n", __func__,
        range->start, range->end, sr, sr->sr_range.start, sr->sr_range.end);

    return (range->start == range->end) ? 0 : 1;
}

/*
 * move chunks from packet buffer to stream buffer,
 */
int ossl_fset_move_chunks(SFRAME_SET *fs)
{
    struct stream_range_t *sr;
    struct stream_chunk_t *sc;
    REFBUF *refbuf;

    OSSL_RBT_FOREACH(sr, srange, &fs->ranges) {
        assert(ossl_list_sc_num(&sr->sr_chunks) != 0);
        OSSL_LIST_FOREACH_FROM(sc, sc, ossl_list_sc_head(&sr->sr_chunks)) {
            if (sc->sc_st == ST_TYPE_PKT) {
                if (SCHUNK_SIZE(sc) <= DIRECT_STORAGE_SZ) {
                    memcpy(sc->sc_dstorage, sc->sc_data,
                        UINT64_TO_SIZE_T(SCHUNK_SIZE(sc)));
                    sc->sc_st = ST_TYPE_DIRECT;
                    ossl_qrx_pkt_release(sc->sc_pkt);
                    sc->sc_data_w = sc->sc_dstorage;
                } else {
                    refbuf = refbuf_alloc(SCHUNK_SIZE(sc));
                    if (refbuf == NULL)
                        return 0;
                    memcpy(refbuf->refbuf_buf, sc->sc_data,
                        UINT64_TO_SIZE_T(SCHUNK_SIZE(sc)));
                    sc->sc_st = ST_TYPE_REFBUF;
                    ossl_qrx_pkt_release(sc->sc_pkt);
                    sc->sc_refbuf = refbuf;
                    sc->sc_data_w = refbuf_to_buf(refbuf);
                }
            }
        }
    }

    return 1;
}

/*
 * collapse chunks into one continuous buffer.Once function
 * returns there is exactly on stream chunk in list of chunks.
 * sc->sc_range.start == sr->sr_range.start &&
 * sc->sc_range.end == sr->sr_range.end
 */
static int flatten_range(SFRAME_SET *fs, struct stream_range_t *sr)
{
    struct stream_chunk_t *sc, *save_sc;
    uint64_t sz;
    unsigned char *w;
    REFBUF *refbuf;

    assert(ossl_list_sc_num(&sr->sr_chunks) != 0);
    if (ossl_list_sc_num(&sr->sr_chunks) == 1)
        return 1; /* range is flat (number of chunks == 1) already */

    sr->sr_it_sc = NULL;
    assert(sr->sr_range.end > sr->sr_range.start);
    sz = SRANGE_SIZE(sr);
    refbuf = refbuf_alloc(sz);
    if (refbuf == NULL)
        return 0;
    w = refbuf_to_buf(refbuf);
    sc = ossl_list_sc_head(&sr->sr_chunks);
    memcpy(w, sc->sc_data, UINT64_TO_SIZE_T(SCHUNK_SIZE(sc)));
    if (fs->cleanse)
        OPENSSL_cleanse(sc->sc_data_w, UINT64_TO_SIZE_T(SCHUNK_SIZE(sc)));
    w += SCHUNK_SIZE(sc);
    assert(sz >= SCHUNK_SIZE(sc));
    sz -= SCHUNK_SIZE(sc);
    sc->sc_range = sr->sr_range;
    /*
     * use the head chunk for the refbuf,
     * remaining chunks will be freed.
     */
    switch (sc->sc_st) {
    case ST_TYPE_PKT:
        ossl_qrx_pkt_release(sc->sc_pkt);
        sc->sc_st = ST_TYPE_REFBUF;
        sc->sc_refbuf = refbuf;
        sc->sc_data_w = refbuf_to_buf(refbuf);
        break;
    case ST_TYPE_REFBUF:
        refbuf_free(sc->sc_refbuf);
        sc->sc_refbuf = refbuf;
        sc->sc_data_w = refbuf_to_buf(refbuf);
        break;
    case ST_TYPE_DIRECT:
    case ST_TYPE_TEST:
        sc->sc_st = ST_TYPE_REFBUF;
        sc->sc_refbuf = refbuf;
        sc->sc_data_w = refbuf_to_buf(refbuf);
        break;
    default:
        assert(NULL);
    }
    OSSL_LIST_FOREACH_DELSAFE_FROM(sc, save_sc, sc,
        ossl_list_sc_next(sc)) {
        memcpy(w, sc->sc_data, UINT64_TO_SIZE_T(SCHUNK_SIZE(sc)));
        w += SCHUNK_SIZE(sc);
        assert(sz >= SCHUNK_SIZE(sc));
        sz -= SCHUNK_SIZE(sc);
        ossl_list_sc_remove(&sr->sr_chunks, sc);
        fs->stream_chunks--;
        destroy_schunk(fs, sc);
    }

    return 1;
}

/*
 * collapse chunks in all ranges
 */
int ossl_fset_flatten_ranges(SFRAME_SET *fs)
{
    struct stream_range_t *sr;
    int rv = 1;

    OSSL_RBT_FOREACH(sr, srange, &fs->ranges) {
        rv = flatten_range(fs, sr);
        if (rv == 0)
            break;
    }

    return rv;
}

void ossl_sframe_set_destroy_ranges(SFRAME_SET *fs)
{
    struct stream_range_t *sr, *save_sr;

    OSSL_RBT_FOREACH_SAFE(sr, srange, &fs->ranges, save_sr) {
       OSSL_RBT_REMOVE(srange, &fs->ranges, sr);
       fs->stream_ranges--;
       destroy_srange(fs, sr);
    }
}

/*
 * moves the read offset, freeing all chunks which end offset
 * is less than new_offset
 *   sc->sc_range.end < new_offset
 */
int ossl_sframe_set_move_offset(SFRAME_SET *fs, uint64_t new_offset)
{
    struct stream_range_t *sr = OSSL_RBT_MIN(srange, &fs->ranges);
    struct stream_chunk_t *sc, *save_sc;

    if (sr == NULL)
        return 0;

    /*
     * offset can move within continuous range only. it can not
     * move backward, it can not move past the first gap (the first range)
     */
    if (new_offset <= fs->offset ||
        (sr == NULL || new_offset > sr->sr_range.end))
        return 0;

    DEBUG_PRINT(stderr, "%s offset: %llu -> %llu range: %p [ %llu, %llu ] -> ",
        __func__, fs->offset, new_offset, sr, sr->sr_range.start,
        sr->sr_range.end);

    fs->offset = new_offset;

    OSSL_LIST_FOREACH_DELSAFE(sc, save_sc, sc, &sr->sr_chunks) {
        if (new_offset >= sc->sc_range.end) {
            ossl_list_sc_remove(&sr->sr_chunks, sc);
            fs->stream_chunks--;
            if (sr->sr_it_sc == sc)
                sr->sr_it_sc = NULL; /* invalidate iterator chunk */
            destroy_schunk(fs, sc);
        } else {
            break;
        }
    }

    if (sc == NULL) {
        /*
         * the whole range was consumed.
         * this step invalidates iterator we use in ossl_sframe_peek()
         */
        OSSL_RBT_REMOVE(srange, &fs->ranges, sr);
        destroy_srange(fs, sr);
        fs->stream_ranges--;
        DEBUG_PRINT(stderr, "[ NULL ]\n");
    } else {
        if (fs->cleanse)
            OPENSSL_cleanse(sc->sc_data_w,
                UINT64_TO_SIZE_T(new_offset - sc->sc_range.start));
        sc->sc_data += (new_offset - sc->sc_range.start);
        sc->sc_range.start = new_offset;
        sr->sr_range.start = new_offset;
        DEBUG_PRINT(stderr, "[ %lli, %llu ]\n",
            sr->sr_range.start, sr->sr_range.end);
    }

    return 1;
}

int ossl_sframe_set_flatten_first_range(SFRAME_SET *fs)
{
    struct stream_range_t *sr;
    int rv;

    sr = OSSL_RBT_MIN(srange, &fs->ranges);
    /*
     * there must be no gap between offset and start of the range
     */
    if (sr != NULL && sr->sr_range.start <= fs->offset)
        rv = flatten_range(fs, sr);
    else
        rv = 1;

    return rv;
}
