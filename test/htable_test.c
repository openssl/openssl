/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto/objects/obj_dat.h"
#include "crypto/siphash.h"
#include "crypto/x509.h"
#include "internal/htable.h"
#include "crypto/asn1/asn1_local.h"
#include "internal/nelem.h"
#include "testutil.h"

typedef struct entry_st {
    uint64_t key;
    int visits;
    OSSL_QUEUE_MEMBER(ent);
    OSSL_QUEUE_MEMBER(one);
    OSSL_HTABLE_MEMBER(dyn);
    OSSL_HTABLE_MEMBER(cap);
} ENTRY;

#define ENT_BITS 4
#define ENT_BUCKETS ((size_t)1 << ENT_BITS)
DEFINE_QUEUE_OF(ent, ENTRY);
DEFINE_HTABLE_OF(ent, ENTRY, ENT_BITS);

/* A single-bucket table over the same elements, so every insertion collides */
DEFINE_QUEUE_OF(one, ENTRY);
DEFINE_HTABLE_OF(one, ENTRY, 0);

static OSSL_HTABLE(ent) static_table = OSSL_HTABLE_INIT;

/* A growable table: 4 buckets inline, up to 1024. */
#define DYN_MIN_BITS 2
#define DYN_MAX_BITS 10
DEFINE_QUEUE_OF(dyn, ENTRY);
DEFINE_HTABLE_DYN_OF(dyn, ENTRY, DYN_MIN_BITS, DYN_MAX_BITS);

/* A growable table that stops at 8 buckets. */
DEFINE_QUEUE_OF(cap, ENTRY);
DEFINE_HTABLE_DYN_OF(cap, ENTRY, 1, 3);

static uint64_t key_hash(uint64_t key)
{
    return ossl_hash_u64(key);
}

/* The number of non-empty buckets and the length of the longest chain. */
static void chain_shape(const OSSL_QUEUE *buckets, size_t nbuckets,
    size_t *used, size_t *max_chain)
{
    const OSSL_QNODE *n;
    size_t i, len;

    *used = 0;
    *max_chain = 0;
    for (i = 0; i < nbuckets; i++) {
        len = 0;
        OSSL_QUEUE_WALK (n, &buckets[i])
            len++;
        *used += len != 0;
        if (len > *max_chain)
            *max_chain = len;
    }
}

static void init_entries(ENTRY *e, size_t n, uint64_t stride)
{
    size_t i;

    for (i = 0; i < n; i++) {
        e[i].key = (uint64_t)i * stride;
        e[i].visits = 0;
        ossl_queue_ent_init_elem(&e[i]);
        ossl_queue_one_init_elem(&e[i]);
        ossl_queue_dyn_init_elem(&e[i]);
        ossl_queue_cap_init_elem(&e[i]);
    }
}

static int check_empty(OSSL_HTABLE(ent) *ht)
{
    ENTRY *p;
    size_t i;

    if (!TEST_size_t_eq(ossl_htable_num(ht), 0)
        || !TEST_true(ossl_htable_is_empty(ht))
        || !TEST_size_t_eq(ossl_htable_num_buckets(ht), ENT_BUCKETS)
        || !TEST_uint64_t_eq(ossl_htable_mask(ht), ENT_BUCKETS - 1)
        || !TEST_ptr_eq(ossl_htable_bucket(ht, 0x123), &ht->buckets[3])
        || !TEST_ptr_eq(ossl_htable_bucket(ht, UINT64_MAX),
            &ht->buckets[ENT_BUCKETS - 1]))
        return 0;
    for (i = 0; i < ossl_htable_num_buckets(ht); i++)
        if (!TEST_true(ossl_queue_empty(&ht->buckets[i])))
            return 0;

    /* A search of an empty table is a miss */
    OSSL_HTABLE_FIND(p, ent, ht, 7, p->key == 7);
    return TEST_ptr_null(p) && TEST_ptr_null(ossl_htable_ent_head(ht, 7));
}

/* A statically initialised table and a run-time initialised one agree. */
static int test_init(void)
{
    OSSL_HTABLE(ent) table;

    memset(&table, 0xff, sizeof(table));
    ossl_htable_ent_init(&table);
    return check_empty(&static_table) && check_empty(&table);
}

static void count_visit(ENTRY *e, void *arg)
{
    e->visits++;
    (*(size_t *)arg)++;
}

static void del_visit(ENTRY *e, void *arg)
{
    ossl_htable_ent_del(arg, e);
    e->visits++;
}

#define NENTRIES 64

static int test_add_find_del(void)
{
    OSSL_HTABLE(ent) table;
    ENTRY e[NENTRIES], *p;
    size_t i, count = 0, used, max_chain;
    uint64_t b;

    ossl_htable_ent_init(&table);
    init_entries(e, NENTRIES, 7919);

    for (i = 0; i < NENTRIES; i++) {
        ossl_htable_ent_add(&table, &e[i], key_hash(e[i].key));
        if (!TEST_size_t_eq(ossl_htable_num(&table), i + 1)
            || !TEST_true(ossl_queue_ent_hashed(&e[i])))
            return 0;
    }

    chain_shape(table.buckets, ENT_BUCKETS, &used, &max_chain);
    if (!TEST_false(ossl_htable_is_empty(&table))
        || !TEST_size_t_le(used, ENT_BUCKETS)
        || !TEST_size_t_ge(max_chain, NENTRIES / ENT_BUCKETS))
        return 0;

    /* Every element is found under its own key, and an unknown key is not */
    for (i = 0; i < NENTRIES; i++) {
        OSSL_HTABLE_FIND(p, ent, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            return 0;
    }
    OSSL_HTABLE_FIND(p, ent, &table, key_hash(1), p->key == 1);
    if (!TEST_ptr_null(p))
        return 0;

    /* Each element sits in the bucket its hash selects, and nowhere else */
    for (b = 0; b < ENT_BUCKETS; b++)
        OSSL_HTABLE_FOREACH (p, ent, &table, b) {
            if (!TEST_uint64_t_eq(key_hash(p->key) & ossl_htable_mask(&table), b))
                return 0;
            count++;
        }
    if (!TEST_size_t_eq(count, NENTRIES))
        return 0;

    /* doall visits every element exactly once */
    count = 0;
    ossl_htable_ent_doall_arg(&table, count_visit, &count);
    if (!TEST_size_t_eq(count, NENTRIES))
        return 0;
    for (i = 0; i < NENTRIES; i++)
        if (!TEST_int_eq(e[i].visits, 1))
            return 0;

    /* Deleting half leaves the other half findable, and they can come back */
    for (i = 0; i < NENTRIES; i += 2)
        ossl_htable_ent_del(&table, &e[i]);
    if (!TEST_size_t_eq(ossl_htable_num(&table), NENTRIES / 2))
        return 0;
    for (i = 0; i < NENTRIES; i++) {
        OSSL_HTABLE_FIND(p, ent, &table, key_hash(e[i].key), p->key == e[i].key);
        if (i % 2 == 0) {
            if (!TEST_false(ossl_queue_ent_hashed(&e[i])) || !TEST_ptr_null(p))
                return 0;
        } else if (!TEST_ptr_eq(p, &e[i])) {
            return 0;
        }
    }
    for (i = 0; i < NENTRIES; i += 2)
        ossl_htable_ent_add(&table, &e[i], key_hash(e[i].key));
    if (!TEST_size_t_eq(ossl_htable_num(&table), NENTRIES))
        return 0;
    for (i = 0; i < NENTRIES; i++) {
        OSSL_HTABLE_FIND(p, ent, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            return 0;
    }

    /* doall may remove the element it is handed */
    ossl_htable_ent_doall_arg(&table, del_visit, &table);
    if (!TEST_size_t_eq(ossl_htable_num(&table), 0)
        || !TEST_true(ossl_htable_is_empty(&table)))
        return 0;
    for (i = 0; i < NENTRIES; i++)
        if (!TEST_false(ossl_queue_ent_hashed(&e[i]))
            || !TEST_int_eq(e[i].visits, 2))
            return 0;
    chain_shape(table.buckets, ENT_BUCKETS, &used, &max_chain);
    return TEST_size_t_eq(used, 0) && TEST_size_t_eq(max_chain, 0);
}

/* With a single bucket every element shares one chain, most recent first. */
static int test_single_bucket(void)
{
    OSSL_HTABLE(one) table;
    ENTRY e[10], *p, *pn;
    size_t i, count = 0, used, max_chain;

    ossl_htable_one_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    if (!TEST_size_t_eq(ossl_htable_num_buckets(&table), 1)
        || !TEST_uint64_t_eq(ossl_htable_mask(&table), 0)
        || !TEST_ptr_eq(ossl_htable_bucket(&table, UINT64_MAX),
            &table.buckets[0]))
        return 0;

    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_one_add(&table, &e[i], key_hash(e[i].key));
    OSSL_HTABLE_FOREACH (p, one, &table, 12345) {
        if (!TEST_size_t_lt(count, OSSL_NELEM(e))
            || !TEST_ptr_eq(p, &e[OSSL_NELEM(e) - 1 - count]))
            return 0;
        count++;
    }
    chain_shape(table.buckets, 1, &used, &max_chain);
    if (!TEST_size_t_eq(count, OSSL_NELEM(e))
        || !TEST_size_t_eq(used, 1)
        || !TEST_size_t_eq(max_chain, OSSL_NELEM(e)))
        return 0;

    /*
     * Whatever hash a search is given, it lands in the one bucket and walks
     * the chain to its key.
     */
    for (i = 0; i < OSSL_NELEM(e); i++) {
        OSSL_HTABLE_FIND(p, one, &table, (uint64_t)i * 977, p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            return 0;
    }

    /* A deletion-safe bucket walk may remove every element */
    OSSL_HTABLE_FOREACH_DELSAFE (p, pn, one, &table, 0)
        ossl_htable_one_del(&table, p);
    return TEST_size_t_eq(ossl_htable_num(&table), 0)
        && TEST_true(ossl_htable_is_empty(&table))
        && TEST_ptr_null(ossl_htable_one_head(&table, 0));
}

/* Recently-used-cache promotion moves an element to the head of a bucket. */
static int test_ruc(void)
{
    OSSL_HTABLE(ent) table;
    ENTRY e[3], *p;
    size_t i;

    ossl_htable_ent_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_ent_add(&table, &e[i], 5);
    if (!TEST_ptr_eq(ossl_htable_ent_head(&table, 5), &e[2]))
        return 0;

    /* Promoting the tail makes it the head and keeps the count */
    ossl_htable_ent_ruc(&table, &e[0], 5);
    if (!TEST_ptr_eq(ossl_htable_ent_head(&table, 5), &e[0])
        || !TEST_ptr_eq(ossl_queue_ent_next(&e[0]), &e[2])
        || !TEST_ptr_eq(ossl_queue_ent_next(&e[2]), &e[1])
        || !TEST_ptr_null(ossl_queue_ent_next(&e[1]))
        || !TEST_size_t_eq(ossl_htable_num(&table), 3))
        return 0;

    /* Promoting under another hash moves the element to that bucket */
    ossl_htable_ent_ruc(&table, &e[1], 9);
    OSSL_HTABLE_FIND(p, ent, &table, 9, p->key == e[1].key);
    if (!TEST_ptr_eq(p, &e[1])
        || !TEST_ptr_eq(ossl_htable_ent_head(&table, 9), &e[1])
        || !TEST_ptr_null(ossl_queue_ent_next(&e[1]))
        || !TEST_ptr_eq(ossl_htable_ent_head(&table, 5), &e[0])
        || !TEST_ptr_eq(ossl_queue_ent_next(&e[0]), &e[2])
        || !TEST_ptr_null(ossl_queue_ent_next(&e[2]))
        || !TEST_size_t_eq(ossl_htable_num(&table), 3))
        return 0;
    OSSL_HTABLE_FIND(p, ent, &table, 5, p->key == e[1].key);
    return TEST_ptr_null(p);
}

/* The hash helpers spread keys over the low bits that select a bucket. */
static int test_hash_mixing(void)
{
    unsigned char used[1024];
    size_t i, n = 0, m = 0;
    int local = 0;

    /* Zero is the finaliser's fixed point; everything else moves */
    if (!TEST_uint64_t_eq(ossl_hash_u64(0), 0)
        || !TEST_uint64_t_ne(ossl_hash_u64(1), 1)
        || !TEST_uint64_t_ne(ossl_hash_u64(1), ossl_hash_u64(2))
        || !TEST_uint64_t_eq(ossl_hash_ptr(&local),
            ossl_hash_u64((uint64_t)(uintptr_t)&local)))
        return 0;

    /* Mixed sequential keys spread like random ones: about 63% of buckets */
    memset(used, 0, sizeof(used));
    for (i = 0; i < OSSL_NELEM(used); i++)
        used[ossl_hash_u64(i) & (OSSL_NELEM(used) - 1)] = 1;
    for (i = 0; i < OSSL_NELEM(used); i++)
        n += used[i];

    /* Keys with a stride of four passed through raw use a quarter of them */
    memset(used, 0, sizeof(used));
    for (i = 0; i < OSSL_NELEM(used); i++)
        used[(i << 2) & (OSSL_NELEM(used) - 1)] = 1;
    for (i = 0; i < OSSL_NELEM(used); i++)
        m += used[i];

    return TEST_size_t_ge(n, OSSL_NELEM(used) / 2)
        && TEST_size_t_eq(m, OSSL_NELEM(used) / 4);
}

/*
 * scan_ext_flags() on a keyed intrusive table.
 *
 * ossl_x509v3_cache_extensions() scans the extensions of a certificate once,
 * in scan_ext_flags() (crypto/x509/v3_purp.c), for a repeated extension,
 * the freshest CRL extension and unsupported critical ones. Extensions with
 * a built-in NID are deduplicated through a bitset; every other OID, which
 * the author of an untrusted certificate chooses freely, goes through a
 * SipHash-keyed hash table that exists only for the scan. The library
 * allocates an OPENSSL_LHASH and an array of entry wrappers for it.
 *
 * The function below is that scan with the same signature, the same flags
 * and the same loop; only the else branch differs, where the LHASH, the
 * wrapper array and the streaming SipHash give way to a keyed OSSL_HTABLE in
 * the frame, a pool of intrusive entries beside it (a heap pool only for a
 * certificate with more extensions than the pool holds) and the table's
 * own hash. The tests drive it through real X509 objects and check every
 * certificate against the library's scan via X509_get_extension_flags().
 */
typedef struct oid_entry_st {
    const ASN1_OBJECT *obj;
    OSSL_QUEUE_MEMBER(oid);
} OID_ENTRY;

#define OID_BITS 3 /* 8 buckets: fewer than the extensions, so chains form */
#define OID_BUCKETS ((size_t)1 << OID_BITS)
#define SCAN_EXT_POOL 32 /* entries kept in the frame */
DEFINE_QUEUE_OF(oid, OID_ENTRY);
DEFINE_HTABLE_KEYED_OF(oid, OID_ENTRY, OID_BITS);

static void scan_ext_flags(const X509 *x509, uint32_t *flags)
{
    OSSL_HTABLE(oid) table;
    OID_ENTRY pool[SCAN_EXT_POOL], *ents = NULL;
    size_t num_entries = 0;
    uint8_t ex_bitset[(NUM_NID + 7) / 8];
    int count = X509_get_ext_count(x509);

    memset(ex_bitset, 0, sizeof(ex_bitset));
    /* A certificate MUST NOT include more than one instance of an extension. */
    for (int i = 0; i < count; i++) {
        const X509_EXTENSION *ex = X509_get_ext(x509, i);
        const ASN1_OBJECT *a = X509_EXTENSION_get_object(ex);
        int nid = OBJ_obj2nid(a);

        /*
         * Known NIDs within the build-time bitset limit are checked for
         * duplicates in constant time. Unknown OIDs and dynamically registered
         * NIDs that exceed the limit fall back to duplicate detection via a
         * hash table.
         */
        if (nid > NID_undef && nid < NUM_NID) {
            unsigned int ex_bit = nid;

            if ((ex_bitset[ex_bit >> 3] & (1u << (ex_bit & 7))) != 0) {
                *flags |= EXFLAG_DUPLICATE;
                break;
            }
            ex_bitset[ex_bit >> 3] |= (1u << (ex_bit & 7));
        } else {
            OID_ENTRY *p;
            uint64_t h;

            if (a->length < 1) {
                *flags |= EXFLAG_INVALID;
                break;
            }
            /*
             * Salt the table and pick the entry pool the first time an
             * attacker-controlled OID is seen. The table never outlives
             * this function. Fail closed with EXFLAG_INVALID when the key
             * cannot be drawn or a heap pool cannot be allocated, as the
             * library does when its table cannot be set up.
             */
            if (ents == NULL) {
                OSSL_LIB_CTX *libctx = NULL;

                ossl_x509_get0_libctx(x509, &libctx, NULL);
                if (!ossl_htable_oid_init(&table, libctx)) {
                    *flags |= EXFLAG_INVALID;
                    break;
                }
                if (count <= SCAN_EXT_POOL) {
                    ents = pool;
                } else if ((ents = OPENSSL_malloc_array(count, sizeof(*ents)))
                    == NULL) {
                    *flags |= EXFLAG_INVALID;
                    break;
                }
            }
            h = ossl_htable_oid_hash(&table, a->data, a->length);
            OSSL_HTABLE_FIND(p, oid, &table, h, OBJ_cmp(p->obj, a) == 0);
            if (p != NULL) {
                *flags |= EXFLAG_DUPLICATE;
                break;
            }
            ents[num_entries].obj = a;
            ossl_queue_oid_init_elem(&ents[num_entries]);
            ossl_htable_oid_add(&table, &ents[num_entries], h);
            num_entries++;
        }
        if (nid == NID_freshest_crl)
            *flags |= EXFLAG_FRESHEST;
        if (!X509_EXTENSION_get_critical(ex))
            continue;
        if (!X509_supported_extension(ex)) {
            *flags |= EXFLAG_CRITICAL;
            break;
        }
    }
    if (ents != pool)
        OPENSSL_free(ents);
}

/* The flags the scan sets, as opposed to the rest of the cache function */
#define SCAN_FLAGS \
    (EXFLAG_DUPLICATE | EXFLAG_INVALID | EXFLAG_CRITICAL | EXFLAG_FRESHEST)

/*
 * The table's hash is SipHash-2-4: it reproduces the reference vector and
 * agrees with libcrypto's streaming SipHash under the drawn key, and two
 * tables draw two keys.
 */
static int test_keyed_hash(void)
{
    /* SipHash-2-4 reference vector: key 00..0f, message 00..0e */
    static const uint64_t ref = 0xa129ca6149be45e5ULL;
    OSSL_HTABLE(oid) t, u;
    SIPHASH sip = { 0 };
    unsigned char msg[64], digest[SIPHASH_MIN_DIGEST_SIZE], le[8];
    uint64_t v, x = 0x0123456789abcdefULL;
    size_t i;

    if (!TEST_true(ossl_htable_oid_init(&t, NULL))
        || !TEST_true(ossl_htable_oid_init(&u, NULL))
        || !TEST_true(ossl_htable_is_empty(&t))
        || !TEST_size_t_eq(sizeof(t.key), OSSL_HTABLE_KEY_SIZE)
        || !TEST_mem_ne(t.key, sizeof(t.key), u.key, sizeof(u.key)))
        return 0;

    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)i;
    memcpy(t.key, msg, sizeof(t.key));
    if (!TEST_uint64_t_eq(ossl_htable_oid_hash(&t, msg, 15), ref))
        return 0;

    /* Every length against SipHash_*() with an 8-byte hash size, u's key */
    for (i = 0; i <= sizeof(msg); i++) {
        if (!TEST_true(SipHash_set_hash_size(&sip, sizeof(digest)))
            || !TEST_true(SipHash_Init(&sip, u.key, 0, 0)))
            return 0;
        SipHash_Update(&sip, msg, i);
        if (!TEST_true(SipHash_Final(&sip, digest, sizeof(digest))))
            return 0;
        memcpy(&v, digest, sizeof(v));
        if (!TEST_uint64_t_eq(ossl_htable_oid_hash(&u, msg, i), v))
            return 0;
    }

    /* The integer form hashes the little-endian bytes */
    for (i = 0; i < sizeof(le); i++)
        le[i] = (unsigned char)(x >> (8 * i));
    return TEST_uint64_t_eq(ossl_htable_oid_hash_u64(&u, x),
               ossl_htable_oid_hash(&u, le, sizeof(le)))
        && TEST_uint64_t_ne(ossl_htable_oid_hash_u64(&u, x),
            ossl_htable_oid_hash_u64(&t, x));
}

/* A table cannot be salted without a DRBG, and says so. */
static int test_keyed_init_failure(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *nullprov = NULL;
    OSSL_HTABLE(oid) t;
    int ret = 0;

    /* Loading the null provider stops the default one from auto-loading */
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(nullprov = OSSL_PROVIDER_load(libctx, "null")))
        goto end;
    memset(&t, 0xff, sizeof(t));
    if (!TEST_false(ossl_htable_oid_init(&t, libctx))
        || !TEST_true(ossl_htable_is_empty(&t)))
        goto end;
    ERR_clear_error();
    ret = 1;
end:
    OSSL_PROVIDER_unload(nullprov);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

/* ---- certificates for the scan ------------------------------------------ */

static X509 *new_cert(void)
{
    X509 *x = X509_new();

    if (!TEST_ptr(x))
        return NULL;
    if (!TEST_true(X509_set_version(x, X509_VERSION_3))) {
        X509_free(x);
        return NULL;
    }
    return x;
}

/* A built-in extension with a well-formed value the cache can parse */
static int add_known(X509 *x, int nid, const char *value)
{
    X509_EXTENSION *ex = X509V3_EXT_nconf_nid(NULL, NULL, nid, value);
    int ok;

    if (!TEST_ptr(ex))
        return 0;
    ok = TEST_true(X509_add_ext(x, ex, -1));
    X509_EXTENSION_free(ex);
    return ok;
}

/* An extension of any OID with an opaque value (DER NULL) */
static int add_raw(X509 *x, const ASN1_OBJECT *obj, int critical)
{
    static const unsigned char der_null[] = { 0x05, 0x00 };
    ASN1_OCTET_STRING *data = ASN1_OCTET_STRING_new();
    X509_EXTENSION *ex = NULL;
    int ok = 0;

    if (!TEST_ptr(data)
        || !TEST_true(ASN1_OCTET_STRING_set(data, der_null, sizeof(der_null)))
        || !TEST_ptr(ex = X509_EXTENSION_create_by_OBJ(NULL, obj, critical, data)))
        goto end;
    ok = TEST_true(X509_add_ext(x, ex, -1));
end:
    X509_EXTENSION_free(ex);
    ASN1_OCTET_STRING_free(data);
    return ok;
}

/* An unknown (NID_undef) extension under a private enterprise arc */
static int add_unknown(X509 *x, unsigned int n, int critical)
{
    char txt[64];
    ASN1_OBJECT *obj;
    int ok = 0;

    snprintf(txt, sizeof(txt), "1.3.6.1.4.1.99999.%u", n);
    if (!TEST_ptr(obj = OBJ_txt2obj(txt, 1)))
        return 0;
    if (TEST_int_eq(OBJ_obj2nid(obj), NID_undef))
        ok = add_raw(x, obj, critical);
    ASN1_OBJECT_free(obj);
    return ok;
}

/* Four standard extensions, two of them critical, as most certificates have */
static int add_typical(X509 *x)
{
    return add_known(x, NID_basic_constraints, "critical,CA:TRUE")
        && add_known(x, NID_key_usage, "critical,keyCertSign,cRLSign")
        && add_known(x, NID_ext_key_usage, "serverAuth")
        && add_known(x, NID_subject_alt_name, "DNS:example.com");
}

/*
 * Run the scan on |x| and check it sets exactly |expect|; then run the
 * library's cache on the same certificate and check its scan-owned flags
 * agree, EXFLAG_INVALID excepted where the cache sets it for a reason the
 * scan does not see (a repeated built-in extension fails X509_get_ext_d2i()).
 * The cache is computed once per certificate and never invalidated, so a
 * certificate goes through here once.
 */
static int check_scan(X509 *x, uint32_t expect)
{
    uint32_t flags = 0, lib, mask = SCAN_FLAGS;

    scan_ext_flags(x, &flags);
    if (!TEST_uint_eq(flags, expect))
        return 0;
    lib = X509_get_extension_flags(x);
    ERR_clear_error();
    if ((expect & EXFLAG_DUPLICATE) != 0)
        mask &= ~EXFLAG_INVALID;
    return TEST_uint_eq(lib & mask, expect & mask);
}

/* Build a fresh certificate with |build|(x, variant) and check its scan. */
static int check_built(int (*build)(X509 *x, int variant), int variant,
    uint32_t expect)
{
    X509 *x = new_cert();
    int ret = 0;

    if (x != NULL && build(x, variant) && check_scan(x, expect))
        ret = 1;
    X509_free(x);
    return ret;
}

/* ---- the scan as an API ---------------------------------------------- */

/* A common certificate sets nothing; the freshest CRL extension is flagged. */
static int build_common(X509 *x, int freshest)
{
    return add_typical(x)
        && add_raw(x, OBJ_nid2obj(NID_certificate_policies), 0)
        && add_raw(x, OBJ_nid2obj(NID_info_access), 0)
        && (!freshest || add_raw(x, OBJ_nid2obj(NID_freshest_crl), 0));
}

static int test_scan_typical(void)
{
    return check_built(build_common, 0, 0)
        && check_built(build_common, 1, EXFLAG_FRESHEST);
}

/* A repeated built-in extension is caught by the bitset. */
static int build_duplicate_known(X509 *x, int variant)
{
    return add_typical(x)
        && add_unknown(x, 1, 0)
        && add_known(x, NID_basic_constraints, "CA:FALSE");
}

static int test_scan_duplicate_known(void)
{
    return check_built(build_duplicate_known, 0, EXFLAG_DUPLICATE);
}

/*
 * Private extensions go through the table: fewer than the table has
 * buckets, exactly the frame pool, and twice that, so the chains and the
 * heap pool are both exercised. Distinct OIDs set nothing; a repeat of the
 * first as the last extension is a duplicate.
 */
static const size_t unknown_counts[] = {
    OID_BUCKETS - 1, SCAN_EXT_POOL, 2 * SCAN_EXT_POOL
};

static int build_unknowns(X509 *x, int variant)
{
    size_t i, n = unknown_counts[variant >> 1];

    for (i = 0; i < n; i++)
        if (!add_unknown(x, (unsigned int)i, 0))
            return 0;
    return (variant & 1) == 0 || add_unknown(x, 0, 0);
}

static int test_scan_unknown(int idx)
{
    TEST_info("%zu private extensions", unknown_counts[idx]);
    return check_built(build_unknowns, idx << 1, 0)
        && check_built(build_unknowns, (idx << 1) | 1, EXFLAG_DUPLICATE);
}

/* A repeated private extension among built-in ones. */
static int build_mixed(X509 *x, int repeat)
{
    return add_known(x, NID_basic_constraints, "critical,CA:TRUE")
        && add_unknown(x, 7, 0)
        && add_known(x, NID_key_usage, "critical,keyCertSign")
        && add_unknown(x, 8, 0)
        && add_known(x, NID_subject_alt_name, "DNS:example.com")
        && (!repeat || add_unknown(x, 7, 0));
}

static int test_scan_duplicate_unknown(void)
{
    return check_built(build_mixed, 0, 0)
        && check_built(build_mixed, 1, EXFLAG_DUPLICATE);
}

/*
 * OIDs whose encodings are prefixes of one another are distinct extensions,
 * and OBJ_cmp() alone tells them apart when they share a chain.
 */
static int build_prefixes(X509 *x, int variant)
{
    static const char *const txt[] = {
        "1.3.6.1.4.1.99999",
        "1.3.6.1.4.1.99999.1",
        "1.3.6.1.4.1.99999.1.1",
        "1.3.6.1.4.1.99999.1.2",
        "1.3.6.1.4.1.99999.1.1.1",
    };
    ASN1_OBJECT *obj;
    size_t i;
    int ok;

    for (i = 0; i < OSSL_NELEM(txt); i++) {
        if (!TEST_ptr(obj = OBJ_txt2obj(txt[i], 1)))
            return 0;
        ok = TEST_int_eq(OBJ_obj2nid(obj), NID_undef) && add_raw(x, obj, 0);
        ASN1_OBJECT_free(obj);
        if (!ok)
            return 0;
    }
    return 1;
}

static int test_scan_prefix_oids(void)
{
    return check_built(build_prefixes, 0, 0);
}

/*
 * An unsupported critical extension stops the scan: a duplicate behind it
 * is not reported, while a supported critical one (the two in
 * add_typical()) is passed over. The other way round the duplicate wins.
 */
static int build_critical(X509 *x, int dup_first)
{
    if (dup_first)
        return add_unknown(x, 3, 0)
            && add_unknown(x, 3, 0)
            && add_unknown(x, 4, 1);
    return add_typical(x)
        && add_unknown(x, 3, 1)
        && add_unknown(x, 3, 0);
}

static int test_scan_critical(void)
{
    return check_built(build_critical, 0, EXFLAG_CRITICAL)
        && check_built(build_critical, 1, EXFLAG_DUPLICATE);
}

/*
 * A NID registered at run time lies beyond the bitset and is deduplicated
 * through the table by encoding, like an unknown OID.
 */
static const char dynamic_oid[] = "1.3.6.1.4.1.99998.1";

static int build_dynamic(X509 *x, int repeat)
{
    ASN1_OBJECT *dyn = OBJ_txt2obj(dynamic_oid, 1); /* the registered object */

    return TEST_ptr(dyn)
        && TEST_int_ge(OBJ_obj2nid(dyn), NUM_NID)
        && add_typical(x)
        && add_raw(x, dyn, 0)
        && add_unknown(x, 5, 0)
        && (!repeat || add_raw(x, dyn, 0));
}

static int test_scan_dynamic_nid(void)
{
    int nid;

    if (!TEST_int_ne(nid = OBJ_create(dynamic_oid, "htableTestExt",
                         "htable test extension"),
            NID_undef)
        || !TEST_int_ge(nid, NUM_NID))
        return 0;
    return check_built(build_dynamic, 0, 0)
        && check_built(build_dynamic, 1, EXFLAG_DUPLICATE);
}

/*
 * A zero-length OID is invalid and stops the scan where it stands. Such an
 * extension cannot be added through the API (X509_add_ext() copies the
 * extension by encoding it, and an empty OBJECT IDENTIFIER does not encode),
 * so it is pushed onto the certificate's extension stack directly.
 */
static int build_zero_length(X509 *x, int variant)
{
    static const unsigned char der_null[] = { 0x05, 0x00 };
    ASN1_OBJECT *empty = NULL;
    ASN1_OCTET_STRING *data = NULL;
    X509_EXTENSION *ex = NULL;
    int ok = 0;

    if (!TEST_ptr(empty = ossl_asn1_object_new())
        || !TEST_size_t_eq(OBJ_length(empty), 0)
        || !TEST_ptr(data = ASN1_OCTET_STRING_new())
        || !TEST_true(ASN1_OCTET_STRING_set(data, der_null, sizeof(der_null)))
        || !add_unknown(x, 1, 0)
        || !TEST_ptr(ex = X509_EXTENSION_create_by_OBJ(NULL, empty, 0, data))
        || !TEST_true(sk_X509_EXTENSION_push(x->cert_info.extensions, ex)))
        goto end;
    ex = NULL; /* owned by the certificate now */
    ok = add_unknown(x, 1, 0) /* a duplicate the scan never reaches */
        && TEST_size_t_eq(
            OBJ_length(X509_EXTENSION_get_object(X509_get_ext(x, 1))), 0);
end:
    X509_EXTENSION_free(ex);
    ASN1_OCTET_STRING_free(data);
    ASN1_OBJECT_free(empty);
    return ok;
}

static int test_scan_zero_length_oid(void)
{
    return check_built(build_zero_length, 0, EXFLAG_INVALID);
}

/*
 * Hash flooding. An attacker who knows the key can pick OIDs that all share
 * a bucket; here the "known" key is all zeroes and the OIDs were chosen to
 * collide under it. On a table left with that key every one of them lands in
 * one chain. On a table salted by _init() they spread like any other input,
 * and a certificate carrying them scans the same either way.
 */
#define FLOOD_OIDS 48

static ASN1_OBJECT *flood_oids[FLOOD_OIDS];

static int build_flood(X509 *x, int repeat)
{
    size_t i;

    for (i = 0; i < FLOOD_OIDS; i++)
        if (!add_raw(x, flood_oids[i], 0))
            return 0;
    return !repeat || add_raw(x, flood_oids[0], 0);
}

static size_t table_max_chain(const OSSL_HTABLE(oid) *t, size_t *used)
{
    size_t max_chain;

    chain_shape(t->buckets, OID_BUCKETS, used, &max_chain);
    return max_chain;
}

static int test_scan_flood(void)
{
    OSSL_HTABLE(oid) zero, salted;
    OID_ENTRY ents[FLOOD_OIDS];
    size_t i, n = 0, used;
    unsigned int cand;
    int ret = 0;

    memset(flood_oids, 0, sizeof(flood_oids));
    if (!TEST_true(ossl_htable_oid_init(&zero, NULL))
        || !TEST_true(ossl_htable_oid_init(&salted, NULL)))
        goto end;
    memset(zero.key, 0, sizeof(zero.key));

    /* Keep the candidates that hash to bucket 0 under the all-zero key */
    for (cand = 0; n < FLOOD_OIDS && cand < 100000; cand++) {
        char txt[64];
        ASN1_OBJECT *o;

        snprintf(txt, sizeof(txt), "1.3.6.1.4.1.99999.%u", cand);
        if (!TEST_ptr(o = OBJ_txt2obj(txt, 1)))
            goto end;
        if ((ossl_htable_oid_hash(&zero, OBJ_get0_data(o), OBJ_length(o))
                & ossl_htable_mask(&zero))
            == 0)
            flood_oids[n++] = o;
        else
            ASN1_OBJECT_free(o);
    }
    if (!TEST_size_t_eq(n, FLOOD_OIDS))
        goto end;

    /* Unsalted: one chain holding every OID */
    for (i = 0; i < n; i++) {
        ents[i].obj = flood_oids[i];
        ossl_queue_oid_init_elem(&ents[i]);
        ossl_htable_oid_add(&zero, &ents[i],
            ossl_htable_oid_hash(&zero, OBJ_get0_data(flood_oids[i]),
                OBJ_length(flood_oids[i])));
    }
    if (!TEST_size_t_eq(table_max_chain(&zero, &used), FLOOD_OIDS)
        || !TEST_size_t_eq(used, 1))
        goto end;

    /*
     * Salted: the chosen collisions do not carry over. 48 OIDs in 8
     * buckets: the longest chain is 6 on average and reaching even half of
     * them has odds below 1 in 10^12.
     */
    for (i = 0; i < n; i++) {
        ossl_htable_oid_del(&zero, &ents[i]);
        ossl_htable_oid_add(&salted, &ents[i],
            ossl_htable_oid_hash(&salted, OBJ_get0_data(flood_oids[i]),
                OBJ_length(flood_oids[i])));
    }
    if (!TEST_size_t_lt(table_max_chain(&salted, &used), FLOOD_OIDS / 2)
        || !TEST_size_t_gt(used, 1)
        || !TEST_true(ossl_htable_is_empty(&zero)))
        goto end;

    /* The scan of a certificate carrying the flood is unaffected by it */
    if (!check_built(build_flood, 0, 0)
        || !check_built(build_flood, 1, EXFLAG_DUPLICATE))
        goto end;

    ret = 1;
end:
    for (i = 0; i < OSSL_NELEM(flood_oids); i++)
        ASN1_OBJECT_free(flood_oids[i]);
    return ret;
}

/* Growable tables */

/* The bucket count a growable table has after holding at most |n| entries. */
static size_t dyn_expected_buckets(size_t n, unsigned int min_bits,
    unsigned int max_bits)
{
    size_t nb = (size_t)1 << min_bits;

    while (nb < n && nb < ((size_t)1 << max_bits))
        nb <<= 1;
    return nb;
}

#define DYN_N 1000

static int test_dyn_grow(void)
{
    OSSL_HTABLE(dyn) table;
    ENTRY *e = NULL, *p;
    size_t i, used, max_chain;
    int ret = 0;

    ossl_htable_dyn_init(&table);
    if (!TEST_ptr_eq(table.buckets, table.inline_buckets)
        || !TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table),
            (size_t)1 << DYN_MIN_BITS)
        || !TEST_true(ossl_htable_is_empty(&table))
        || !TEST_ptr(e = OPENSSL_malloc(DYN_N * sizeof(*e))))
        goto end;
    init_entries(e, DYN_N, 7);

    /* The buckets double as soon as the entries outnumber them */
    for (i = 0; i < DYN_N; i++) {
        ossl_htable_dyn_add(&table, &e[i], key_hash(e[i].key));
        if (!TEST_size_t_eq(ossl_htable_num(&table), i + 1)
            || !TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table),
                dyn_expected_buckets(i + 1, DYN_MIN_BITS, DYN_MAX_BITS))
            || !TEST_uint64_t_eq(ossl_htable_dyn_hash_of(&e[i]),
                key_hash(e[i].key)))
            goto end;
    }
    if (!TEST_ptr_ne(table.buckets, table.inline_buckets))
        goto end;

    /* Growing re-linked every entry under the hash it was added with */
    for (i = 0; i < DYN_N; i++) {
        OSSL_HTABLE_FIND(p, dyn, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            goto end;
    }
    chain_shape(table.buckets, ossl_htable_dyn_num_buckets(&table), &used,
        &max_chain);
    if (!TEST_size_t_le(max_chain, 8))
        goto end;

    /* Deleting never shrinks the buckets */
    for (i = 0; i < DYN_N; i += 2)
        ossl_htable_dyn_del(&table, &e[i]);
    if (!TEST_size_t_eq(ossl_htable_num(&table), DYN_N / 2)
        || !TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table),
            dyn_expected_buckets(DYN_N, DYN_MIN_BITS, DYN_MAX_BITS)))
        goto end;
    for (i = 0; i < DYN_N; i++) {
        OSSL_HTABLE_FIND(p, dyn, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, i % 2 == 0 ? NULL : &e[i]))
            goto end;
    }

    /* Cleanup gives back the grown buckets and leaves a usable empty table */
    ossl_htable_dyn_cleanup(&table);
    if (!TEST_ptr_eq(table.buckets, table.inline_buckets)
        || !TEST_true(ossl_htable_is_empty(&table))
        || !TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table),
            (size_t)1 << DYN_MIN_BITS))
        goto end;
    ossl_queue_dyn_init_elem(&e[0]);
    ossl_htable_dyn_add(&table, &e[0], key_hash(e[0].key));
    OSSL_HTABLE_FIND(p, dyn, &table, key_hash(e[0].key), p->key == e[0].key);
    ret = TEST_ptr_eq(p, &e[0]);
end:
    ossl_htable_dyn_cleanup(&table);
    OPENSSL_free(e);
    return ret;
}

/* Past max_bits the table stops growing and its chains lengthen instead. */
static int test_dyn_max_bits(void)
{
    OSSL_HTABLE(cap) table;
    ENTRY e[64], *p;
    size_t i;
    int ret = 0;

    ossl_htable_cap_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_cap_add(&table, &e[i], key_hash(e[i].key));
    if (!TEST_size_t_eq(ossl_htable_cap_num_buckets(&table), 8)
        || !TEST_size_t_eq(ossl_htable_num(&table), OSSL_NELEM(e))
        || !TEST_true(ossl_htable_cap_reserve(&table, 1000))
        || !TEST_size_t_eq(ossl_htable_cap_num_buckets(&table), 8))
        goto end;
    for (i = 0; i < OSSL_NELEM(e); i++) {
        OSSL_HTABLE_FIND(p, cap, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            goto end;
    }
    ret = 1;
end:
    ossl_htable_cap_cleanup(&table);
    return ret;
}

/*
 * In a growable table FIND compares the stored hash before evaluating the
 * caller's condition; in a static table every element of the bucket reaches
 * the condition.
 */
static int cond_calls;

static int counted_eq(const ENTRY *p, uint64_t key)
{
    cond_calls++;
    return p->key == key;
}

static int test_dyn_hash_compare(void)
{
    OSSL_HTABLE(dyn) dyn;
    OSSL_HTABLE(ent) ent;
    ENTRY e[4], *p;
    size_t i;
    int ret = 0;

    ossl_htable_dyn_init(&dyn);
    ossl_htable_ent_init(&ent);
    init_entries(e, OSSL_NELEM(e), 1);
    /* Four hashes that share bucket 1 in either table, all distinct */
    for (i = 0; i < OSSL_NELEM(e); i++) {
        ossl_htable_dyn_add(&dyn, &e[i], 1 + (uint64_t)i * 1024);
        ossl_htable_ent_add(&ent, &e[i], 1 + (uint64_t)i * 1024);
    }
    if (!TEST_size_t_eq(ossl_htable_dyn_num_buckets(&dyn), 4)
        || !TEST_ptr_eq(ossl_htable_dyn_head(&dyn, 1), &e[3]))
        goto end;

    /* e[0] is the tail of its chain: three hash mismatches, one compare */
    cond_calls = 0;
    OSSL_HTABLE_FIND(p, dyn, &dyn, 1, counted_eq(p, e[0].key));
    if (!TEST_ptr_eq(p, &e[0]) || !TEST_int_eq(cond_calls, 1))
        goto end;
    cond_calls = 0;
    OSSL_HTABLE_FIND(p, dyn, &dyn, 1 + 4096, counted_eq(p, e[0].key));
    if (!TEST_ptr_null(p) || !TEST_int_eq(cond_calls, 0))
        goto end;

    /* A matching hash with a different key still misses */
    cond_calls = 0;
    OSSL_HTABLE_FIND(p, dyn, &dyn, 1 + 1024, counted_eq(p, e[0].key));
    if (!TEST_ptr_null(p) || !TEST_int_eq(cond_calls, 1))
        goto end;

    cond_calls = 0;
    OSSL_HTABLE_FIND(p, ent, &ent, 1, counted_eq(p, e[0].key));
    if (!TEST_ptr_eq(p, &e[0]) || !TEST_int_eq(cond_calls, 4))
        goto end;
    ret = 1;
end:
    ossl_htable_dyn_cleanup(&dyn);
    return ret;
}

static int test_dyn_reserve(void)
{
    OSSL_HTABLE(dyn) table;
    ENTRY e[3], *p;
    size_t i;
    int ret = 0;

    ossl_htable_dyn_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_dyn_add(&table, &e[i], key_hash(e[i].key));

    /* Fewer than there are buckets: nothing to do */
    if (!TEST_true(ossl_htable_dyn_reserve(&table, 2))
        || !TEST_ptr_eq(table.buckets, table.inline_buckets)
        /* Up to the next power of two, entries carried over */
        || !TEST_true(ossl_htable_dyn_reserve(&table, 100))
        || !TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table), 128)
        /* Bounded by max_bits */
        || !TEST_true(ossl_htable_dyn_reserve(&table, 100000))
        || !TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table),
            (size_t)1 << DYN_MAX_BITS))
        goto end;
    for (i = 0; i < OSSL_NELEM(e); i++) {
        OSSL_HTABLE_FIND(p, dyn, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            goto end;
    }
    ret = 1;
end:
    ossl_htable_dyn_cleanup(&table);
    return ret;
}

/* Allocation failure while growing: the table carries on with its buckets. */
static CRYPTO_malloc_fn saved_malloc;
static CRYPTO_realloc_fn saved_realloc;
static CRYPTO_free_fn saved_free;
static int fail_mallocs;

static void *failing_malloc(size_t num, const char *file, int line)
{
    if (fail_mallocs)
        return NULL;
    return saved_malloc(num, file, line);
}

static int test_dyn_grow_failure(void)
{
    OSSL_HTABLE(dyn) table;
    ENTRY e[16], *p;
    size_t i;
    int wrapped = 0, ret = 0;

    ossl_htable_dyn_init(&table);
    init_entries(e, OSSL_NELEM(e), 1);
    CRYPTO_get_mem_functions(&saved_malloc, &saved_realloc, &saved_free);
    if (!TEST_true(CRYPTO_set_mem_functions(failing_malloc, saved_realloc,
            saved_free)))
        goto end;
    wrapped = 1;

    fail_mallocs = 1;
    for (i = 0; i < 8; i++)
        ossl_htable_dyn_add(&table, &e[i], key_hash(e[i].key));
    if (!TEST_false(ossl_htable_dyn_reserve(&table, 64)))
        goto end;
    fail_mallocs = 0;
    if (!TEST_ptr_eq(table.buckets, table.inline_buckets)
        || !TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table),
            (size_t)1 << DYN_MIN_BITS)
        || !TEST_size_t_eq(ossl_htable_num(&table), 8))
        goto end;
    for (i = 0; i < 8; i++) {
        OSSL_HTABLE_FIND(p, dyn, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            goto end;
    }

    /* The next add grows by one doubling, not to fit every entry */
    ossl_htable_dyn_add(&table, &e[8], key_hash(e[8].key));
    if (!TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table),
            (size_t)2 << DYN_MIN_BITS))
        goto end;
    for (i = 9; i < OSSL_NELEM(e); i++)
        ossl_htable_dyn_add(&table, &e[i], key_hash(e[i].key));
    if (!TEST_size_t_eq(ossl_htable_dyn_num_buckets(&table), 16))
        goto end;
    for (i = 0; i < OSSL_NELEM(e); i++) {
        OSSL_HTABLE_FIND(p, dyn, &table, key_hash(e[i].key), p->key == e[i].key);
        if (!TEST_ptr_eq(p, &e[i]))
            goto end;
    }
    ret = 1;
end:
    fail_mallocs = 0;
    if (wrapped
        && !TEST_true(CRYPTO_set_mem_functions(saved_malloc, saved_realloc,
            saved_free)))
        ret = 0;
    ossl_htable_dyn_cleanup(&table);
    return ret;
}

static void dyn_del_visited(ENTRY *el, void *arg)
{
    el->visits++;
    ossl_htable_dyn_del(arg, el);
}

/* doall visits every entry once, across grown buckets, and may delete it. */
static int test_dyn_doall_del(void)
{
    OSSL_HTABLE(dyn) table;
    ENTRY e[100];
    size_t i;
    int ret = 0;

    ossl_htable_dyn_init(&table);
    init_entries(e, OSSL_NELEM(e), 3);
    for (i = 0; i < OSSL_NELEM(e); i++)
        ossl_htable_dyn_add(&table, &e[i], key_hash(e[i].key));
    ossl_htable_dyn_doall_arg(&table, dyn_del_visited, &table);
    if (!TEST_true(ossl_htable_is_empty(&table)))
        goto end;
    for (i = 0; i < OSSL_NELEM(e); i++)
        if (!TEST_int_eq(e[i].visits, 1)
            || !TEST_false(ossl_queue_dyn_hashed(&e[i])))
            goto end;
    ret = 1;
end:
    ossl_htable_dyn_cleanup(&table);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_init);
    ADD_TEST(test_add_find_del);
    ADD_TEST(test_single_bucket);
    ADD_TEST(test_ruc);
    ADD_TEST(test_hash_mixing);
    ADD_TEST(test_dyn_grow);
    ADD_TEST(test_dyn_max_bits);
    ADD_TEST(test_dyn_hash_compare);
    ADD_TEST(test_dyn_reserve);
    ADD_TEST(test_dyn_grow_failure);
    ADD_TEST(test_dyn_doall_del);
    ADD_TEST(test_keyed_hash);
    ADD_TEST(test_keyed_init_failure);
    ADD_TEST(test_scan_typical);
    ADD_TEST(test_scan_duplicate_known);
    ADD_ALL_TESTS(test_scan_unknown, OSSL_NELEM(unknown_counts));
    ADD_TEST(test_scan_duplicate_unknown);
    ADD_TEST(test_scan_prefix_oids);
    ADD_TEST(test_scan_critical);
    ADD_TEST(test_scan_dynamic_nid);
    ADD_TEST(test_scan_zero_length_oid);
    ADD_TEST(test_scan_flood);
    return 1;
}
