#include <openssl/evp.h>
#include <openssl/lms.h>
#include "internal/packet.h"

#define HSS_MIN_L 1
#define HSS_MAX_L 8

#define LMS_TYPE_SHA256_N32_H5   0x00000005
#define LMS_TYPE_SHA256_N32_H10  0x00000006
#define LMS_TYPE_SHA256_N32_H15  0x00000007
#define LMS_TYPE_SHA256_N32_H20  0x00000008
#define LMS_TYPE_SHA256_N32_H25  0x00000009
#define LMS_TYPE_SHA256_N24_H5   0x0000000A
#define LMS_TYPE_SHA256_N24_H10  0x0000000B
#define LMS_TYPE_SHA256_N24_H15  0x0000000C
#define LMS_TYPE_SHA256_N24_H20  0x0000000D
#define LMS_TYPE_SHA256_N24_H25  0x0000000E
#define LMS_TYPE_SHAKE_N32_H5    0x0000000F
#define LMS_TYPE_SHAKE_N32_H10   0x00000010
#define LMS_TYPE_SHAKE_N32_H15   0x00000011
#define LMS_TYPE_SHAKE_N32_H20   0x00000012
#define LMS_TYPE_SHAKE_N32_H25   0x00000013
#define LMS_TYPE_SHAKE_N24_H5    0x00000014
#define LMS_TYPE_SHAKE_N24_H10   0x00000015
#define LMS_TYPE_SHAKE_N24_H15   0x00000016
#define LMS_TYPE_SHAKE_N24_H20   0x00000017
#define LMS_TYPE_SHAKE_N24_H25   0x00000018

#define LMOTS_TYPE_SHA256_N32_W1 0x00000001
#define LMOTS_TYPE_SHA256_N32_W2 0x00000002
#define LMOTS_TYPE_SHA256_N32_W4 0x00000003
#define LMOTS_TYPE_SHA256_N32_W8 0x00000004
#define LMOTS_TYPE_SHA256_N24_W1 0x00000005
#define LMOTS_TYPE_SHA256_N24_W2 0x00000006
#define LMOTS_TYPE_SHA256_N24_W4 0x00000007
#define LMOTS_TYPE_SHA256_N24_W8 0x00000008
#define LMOTS_TYPE_SHAKE_N32_W1  0x00000009
#define LMOTS_TYPE_SHAKE_N32_W2  0x0000000A
#define LMOTS_TYPE_SHAKE_N32_W4  0x0000000B
#define LMOTS_TYPE_SHAKE_N32_W8  0x0000000C
#define LMOTS_TYPE_SHAKE_N24_W1  0x0000000D
#define LMOTS_TYPE_SHAKE_N24_W2  0x0000000E
#define LMOTS_TYPE_SHAKE_N24_W4  0x0000000F
#define LMOTS_TYPE_SHAKE_N24_W8  0x00000010

#define U32STR(out, in)                      \
out[0] = (unsigned char)((in >> 24) & 0xff); \
out[1] = (unsigned char)((in >> 16) & 0xff); \
out[2] = (unsigned char)((in >> 8) & 0xff);  \
out[3] = (unsigned char)(in & 0xff)

#define U16STR(out, in)                      \
out[0] = (unsigned char)((in >> 8) & 0xff);  \
out[1] = (unsigned char)(in & 0xff)

/* Section 4.1 */
typedef struct LMOTSParams_st {
    uint32_t lmots_type;
    const char *digestname;   /* Hash Name */
    uint32_t n;           /* Hash output size in bytes */
    uint32_t w;           /* The width of the Winternitz coefficients in bits */
    uint32_t p;           /* The number of n-byte elements used for LMOTS signature */
} LMOTSParams;

typedef struct LMSParams_st {
    uint32_t lms_type;
    const char *digestname;
    uint32_t n;
    uint32_t h;
} LMSParams;

/*
 * OpenSSL does not have a "SHAKE256-192" algorithm, so we have to check the
 * digest size as well as the name.
 */
#define HASH_NOT_MATCHED(a, b) \
    a->n != b->n || (strcmp(a->digestname, b->digestname) != 0)

static unsigned char D_PBLC[] = { 0x80, 0x80 };
static unsigned char D_MESG[] = { 0x81, 0x81 };
static unsigned char D_LEAF[] = { 0x82, 0x82 };
static unsigned char D_INTR[] = { 0x83, 0x83 };

static const LMOTSParams lm_ots_params[] = {
    { LMOTS_TYPE_SHA256_N32_W1, "SHA256",     32, 1, 265 },
    { LMOTS_TYPE_SHA256_N32_W2, "SHA256",     32, 2, 133 },
    { LMOTS_TYPE_SHA256_N32_W4, "SHA256",     32, 4,  67 },
    { LMOTS_TYPE_SHA256_N32_W8, "SHA256",     32, 8,  34 },
    { LMOTS_TYPE_SHA256_N24_W1, "SHA256-192", 24, 1, 200 },
    { LMOTS_TYPE_SHA256_N24_W2, "SHA256-192", 24, 2, 101 },
    { LMOTS_TYPE_SHA256_N24_W4, "SHA256-192", 24, 4,  51 },
    { LMOTS_TYPE_SHA256_N24_W8, "SHA256-192", 24, 8,  26 },
    { LMOTS_TYPE_SHAKE_N32_W1,  "SHAKE-256",  32, 1, 265 },
    { LMOTS_TYPE_SHAKE_N32_W2,  "SHAKE-256",  32, 2, 133 },
    { LMOTS_TYPE_SHAKE_N32_W4,  "SHAKE-256",  32, 4,  67 },
    { LMOTS_TYPE_SHAKE_N32_W8,  "SHAKE-256",  32, 8,  34 },
    /* SHAKE-256/192 */
    { LMOTS_TYPE_SHAKE_N24_W1,  "SHAKE-256",  24, 1, 200 },
    { LMOTS_TYPE_SHAKE_N24_W2,  "SHAKE-256",  24, 2, 101 },
    { LMOTS_TYPE_SHAKE_N24_W4,  "SHAKE-256",  24, 4,  51 },
    { LMOTS_TYPE_SHAKE_N24_W8,  "SHAKE-256",  24, 8,  26 },

    { 0, NULL, 0, 0, 0 },
};

static const LMSParams lms_params[] = {
    { LMS_TYPE_SHA256_N32_H5,  "SHA256",     32,  5 },
    { LMS_TYPE_SHA256_N32_H10, "SHA256",     32, 10 },
    { LMS_TYPE_SHA256_N32_H15, "SHA256",     32, 15 },
    { LMS_TYPE_SHA256_N32_H20, "SHA256",     32, 20 },
    { LMS_TYPE_SHA256_N32_H25, "SHA256",     32, 25 },
    { LMS_TYPE_SHA256_N24_H5,  "SHA256-192", 24,  5 },
    { LMS_TYPE_SHA256_N24_H10, "SHA256-192", 24, 10 },
    { LMS_TYPE_SHA256_N24_H15, "SHA256-192", 24, 15 },
    { LMS_TYPE_SHA256_N24_H20, "SHA256-192", 24, 20 },
    { LMS_TYPE_SHA256_N24_H25, "SHA256-192", 24, 25 },
    { LMS_TYPE_SHAKE_N32_H5,   "SHAKE-256",  32,  5 },
    { LMS_TYPE_SHAKE_N32_H10,  "SHAKE-256",  32, 10 },
    { LMS_TYPE_SHAKE_N32_H15,  "SHAKE-256",  32, 15 },
    { LMS_TYPE_SHAKE_N32_H20,  "SHAKE-256",  32, 20 },
    { LMS_TYPE_SHAKE_N32_H25,  "SHAKE-256",  32, 25 },
    /* SHAKE-256/192 */
    { LMS_TYPE_SHAKE_N24_H5,   "SHAKE-256",  24,  5 },
    { LMS_TYPE_SHAKE_N24_H10,  "SHAKE-256",  24, 10 },
    { LMS_TYPE_SHAKE_N24_H15,  "SHAKE-256",  24, 15 },
    { LMS_TYPE_SHAKE_N24_H20,  "SHAKE-256",  24, 20 },
    { LMS_TYPE_SHAKE_N24_H25,  "SHAKE-256",  24, 25 },

    { 0, NULL, 0 , 0 }
};

typedef struct lm_ots_sig_st {
    const LMOTSParams *params;
    unsigned char *C; /* size is n */
    unsigned char *y; /* size is p * n */
} LMOTS_SIG;

typedef struct lms_signature_st {
  uint32_t q;
  LMOTS_SIG sig;
  unsigned char *paths; /* size is h * m */
} LMS_SIG;

typedef struct lms_public_key_st {
    const LMSParams *lms_params;
    const LMOTSParams *ots_params;
    unsigned char *I;               /* 16 bytes */
    unsigned char *K;               /* n bytes */

} LMS_PUB_KEY;

typedef struct hss_public_key_st {
    uint32_t L;
    LMS_PUB_KEY pub;
} HSS_PUB_KEY;

static const LMOTSParams *LMOTSParams_get(uint32_t lmots_type)
{
    const LMOTSParams *p;

    for (p = lm_ots_params; p->lmots_type != 0; ++p) {
        if (p->lmots_type == lmots_type)
            return p;
    }
    return NULL;
}

static const LMSParams *LMSParams_get(uint32_t lms_type)
{
    const LMSParams *p;

    for (p = lms_params; p->lms_type != 0; ++p) {
        if (p->lms_type == lms_type)
            return p;
    }
    return NULL;
}

static int coef(const unsigned char *S, int i, int w)
{
    int bitmask = (1 << w) - 1;
    int id = (i * w) / 8;
    int shift = 8 - (w * (i % (8 / w)) + w);

    return (S[id] >> shift) & bitmask;
}

static int checksum(const LMOTSParams *params, const unsigned char *S)
{
    int i, sum = 0;
    int bytes = 8 * params->n / params->w;
    int end = (1 << params->w) - 1;

    for (i = 0; i < bytes; ++i)
        sum += end - coef(S, i, params->w);
    return (sum << (8 - params->w));
}

static ossl_inline int PACKET_get_bytes_shallow(PACKET *pkt,
                                                unsigned char **out,
                                                size_t len)
{
    const unsigned char **data = (const unsigned char **)out;

    if (!PACKET_peek_bytes(pkt, data, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

static ossl_inline int PACKET_get_4_len(PACKET *pkt, uint32_t *data)
{
    size_t i = 0;
    int ret = PACKET_get_net_4_len(pkt, &i);

    if (ret)
        *data = (uint32_t)i;
    return ret;
}

static ossl_inline void INC16(unsigned char *tag)
{
    if ((tag[1] = tag[1] + 1) == 0)
        *tag = *tag + 1;
}

#define MAX_DIGEST_SIZE 32
#define ISIZE 16


typedef struct pubkey_ctx_st {
    const LMOTS_SIG *sig;
    EVP_MD_CTX *ctx, *ctxIq;
} LMOTS_PUBKEY_CTX;

typedef struct lms_verify_ctx_st {
    LMOTS_PUBKEY_CTX pubctx;
    const LMS_SIG *lms_sig;
    const LMS_PUB_KEY *key;
    LMS_SIG siglist[16];
    LMS_PUB_KEY publist[16];
} LMS_VERIFY_CTX;

static void lmots_compute_pubkey_cleanup(LMOTS_PUBKEY_CTX *pctx)
{
    EVP_MD_CTX_free(pctx->ctxIq);
    EVP_MD_CTX_free(pctx->ctx);
    pctx->ctx = NULL;
    pctx->ctxIq = NULL;
    pctx->sig = NULL;
}

/* Algorithm 4b */
static int lmots_compute_pubkey_init(LMOTS_PUBKEY_CTX *pctx,
                                     const LMOTS_SIG *sig,
                                     const LMOTSParams *pub,
                                     const unsigned char *I, uint32_t q)
{
    int ret = 0;
    EVP_MD *md;
    EVP_MD_CTX *ctx, *ctxIq;
    unsigned char iq[ISIZE+4], *qbuf = &iq[ISIZE];

    if (sig->params != pub)
        return 0;

    memcpy(iq, I, ISIZE);
    U32STR(qbuf, q);

    pctx->ctxIq = pctx->ctx = NULL;
    pctx->sig  = sig;
    ctxIq = EVP_MD_CTX_create();
    ctx = EVP_MD_CTX_create();
    if (ctxIq == NULL || ctx == NULL)
        goto err;

    /* TODO - add libctx and propq */
    md = EVP_MD_fetch(NULL, sig->params->digestname, NULL);
    if (md == NULL)
        goto err;

    if (!EVP_DigestInit_ex2(ctxIq, md, NULL)
        || !EVP_DigestUpdate(ctxIq, iq, sizeof(iq))
        || !EVP_MD_CTX_copy_ex(ctx, ctxIq))
        goto err;

    /* Q = H(I || u32str(q) || u16str(D_MESG) || C || ....) */
    if (!EVP_DigestUpdate(ctx, D_MESG, sizeof(D_MESG))
        || !EVP_DigestUpdate(ctx, sig->C, sig->params->n))
        goto err;
    pctx->ctx = ctx;
    pctx->ctxIq = ctxIq;
    return 1;
err:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctxIq);
    EVP_MD_CTX_free(ctx);
    return ret;
}

/* Algorithm 4b */
static int lmots_compute_pubkey_update(LMOTS_PUBKEY_CTX *pctx,
                                       const unsigned char *msg, size_t msglen)
{
    return EVP_DigestUpdate(pctx->ctx, msg, msglen) > 0;
}

/* Algorithm 4b */
static int lmots_compute_pubkey_final(LMOTS_PUBKEY_CTX *pctx, unsigned char *Kc)
{
    int ret = 0, i, j;
    EVP_MD_CTX *ctxKc = NULL;
    EVP_MD_CTX *ctx = pctx->ctx;
    EVP_MD_CTX *ctxIq = pctx->ctxIq;
    unsigned char tag[2 + 1], *tag2 = &tag[2];
    unsigned char Q[MAX_DIGEST_SIZE+2], *Qsum;
    unsigned char z[MAX_DIGEST_SIZE];
    uint16_t sum;
    const LMOTSParams *params = pctx->sig->params;
    int n = params->n;
    int p = params->p;
    int w = params->w;
    int end = (1 << w) - 1;
    int a;
    unsigned char *y;

    ctxKc = EVP_MD_CTX_create();
    if (ctxKc == NULL)
        goto err;

    if (!EVP_DigestFinal_ex(ctx, Q, NULL))
        goto err;

    sum = checksum(pctx->sig->params, Q);
    Qsum = Q + n;
    /* Q || Cksm(Q) */
    U16STR(Qsum, sum);

    if (!(EVP_MD_CTX_copy_ex(ctxKc, ctxIq))
        || !EVP_DigestUpdate(ctxKc, D_PBLC, sizeof(D_PBLC)))
        goto err;

    y = pctx->sig->y;
    tag[0] = 0; tag[1] = 0;

    for (i = 0; i < p; ++i) {
        a = coef(Q, i, w);
        memcpy(z, y, n);
        y += n;
        for (j = a; j < end; ++j) {
            *tag2 = (j & 0xFF);
            if (!(EVP_MD_CTX_copy_ex(ctx, ctxIq)))
                goto err;
            if (!EVP_DigestUpdate(ctx, tag, sizeof(tag))
                || !EVP_DigestUpdate(ctx, z, n)
                || !EVP_DigestFinal_ex(ctx, z, NULL))
                goto err;
        }
        INC16(tag);
        if (!EVP_DigestUpdate(ctxKc, z, n))
            goto err;
    }

    /* Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1]) */
    if (!EVP_DigestFinal(ctxKc, Kc, NULL))
        goto err;
    ret = 1;
err:
    EVP_MD_CTX_free(ctxKc);
    return ret;
}

static int lms_sig_verify_init(LMS_VERIFY_CTX *vctx,
                               const LMS_SIG *lms_sig,
                               const LMS_PUB_KEY *key)
{
    vctx->lms_sig = lms_sig;
    vctx->key = key;
    return lmots_compute_pubkey_init(&vctx->pubctx, &lms_sig->sig,
                                     key->ots_params, key->I, lms_sig->q);
}

static int lms_sig_verify_update(LMS_VERIFY_CTX *vctx,
                                 const unsigned char *msg, size_t msglen)
{
    return lmots_compute_pubkey_update(&vctx->pubctx, msg, msglen);
}

static int lms_sig_verify_final(LMS_VERIFY_CTX *vctx)
{
    EVP_MD_CTX *ctx = vctx->pubctx.ctx;
    EVP_MD_CTX *ctxI = vctx->pubctx.ctxIq;
    const LMS_PUB_KEY *key = vctx->key;
    const LMS_SIG *lms_sig = vctx->lms_sig;
    unsigned char Kc[MAX_DIGEST_SIZE];
    unsigned char Tc[MAX_DIGEST_SIZE];
    unsigned char buf[4];
    const LMSParams *lmsParams;
    uint32_t node_num, m;
    const unsigned char *path;

    if (!lmots_compute_pubkey_final(&vctx->pubctx, Kc))
        return 0;

    /* Compute the candidate LMS root value Tc */
    lmsParams = key->lms_params;
    m = lmsParams->n;
    node_num = (1 << lmsParams->h) + lms_sig->q;

    U32STR(buf, node_num);
    if (!EVP_DigestInit_ex2(ctx, NULL, NULL)
        || !EVP_DigestUpdate(ctx, key->I, ISIZE)
        || !EVP_MD_CTX_copy_ex(ctxI, ctx)
        || !EVP_DigestUpdate(ctx, buf, sizeof(buf))
        || !EVP_DigestUpdate(ctx, D_LEAF, sizeof(D_LEAF))
        || !EVP_DigestUpdate(ctx, Kc, m)
        || !EVP_DigestFinal_ex(ctx, Tc, NULL))
        goto err;

    path = lms_sig->paths;
    while (node_num > 1) {
        int odd = node_num & 1;

        node_num = node_num >> 1;
        U32STR(buf, node_num);

        if (!EVP_MD_CTX_copy_ex(ctx, ctxI)
            || !EVP_DigestUpdate(ctx, buf, sizeof(buf))
            || !EVP_DigestUpdate(ctx, D_INTR, sizeof(D_INTR)))
            goto err;

        if (odd) {
            if (!EVP_DigestUpdate(ctx, path, m)
                || !EVP_DigestUpdate(ctx, Tc, m))
                goto err;
        } else {
            if (!EVP_DigestUpdate(ctx, Tc, m)
                || !EVP_DigestUpdate(ctx, path, m))
                goto err;
        }
        if (!EVP_DigestFinal_ex(ctx, Tc, NULL))
            goto err;
        path += m;
    }
    return memcmp(key->K, Tc, m) == 0;
err:
    return 0;
}

static
LMS_VERIFY_CTX *OSSL_HSS_verify_new(void)
{
    LMS_VERIFY_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    return ctx;
}

static
void OSSL_HSS_verify_free(LMS_VERIFY_CTX *ctx)
{
    lmots_compute_pubkey_cleanup(&ctx->pubctx);
    ctx->lms_sig = NULL;
    ctx->key = NULL;
    OPENSSL_free(ctx);
}

static int lms_sig_verify(const LMS_SIG *lms_sig,
                          const LMS_PUB_KEY *key,
                          const unsigned char *msg, size_t msglen)
{
    int valid = 0;
    LMS_VERIFY_CTX *ctx;

    ctx = OSSL_HSS_verify_new();
    if (ctx == NULL)
        return 0;

    if (!lms_sig_verify_init(ctx, lms_sig, key))
        return 0;
    if (!lms_sig_verify_update(ctx, msg, msglen))
        goto end;
    if (!lms_sig_verify_final(ctx))
        goto end;
    valid = 1;
end:
    OSSL_HSS_verify_free(ctx);
    return valid;
}

/* RFC 8554 Algorithm 6a: Steps 1 and 2 */
static int lms_sig_from_pkt(PACKET *pkt, const LMS_PUB_KEY *pub, LMS_SIG *lsig)
{
    uint32_t sig_ots_type = 0, sig_lms_type = 0;
    const LMOTSParams *pub_ots_params = pub->ots_params;
    const LMOTSParams *sig_params;
    const LMSParams *lparams;

    if (!PACKET_get_4_len(pkt, &lsig->q))    /* q = Leaf Index */
        return 0;
    if (!PACKET_get_4_len(pkt, &sig_ots_type))
        return 0;
    if (pub_ots_params->lmots_type != sig_ots_type)
        return 0;
    sig_params = pub_ots_params;
    lsig->sig.params = sig_params;

    if (!PACKET_get_bytes_shallow(pkt, &lsig->sig.C, sig_params->n)) /* Random bytes of size n */
        return 0;
    if (!PACKET_get_bytes_shallow(pkt, &lsig->sig.y, sig_params->p * sig_params->n)) /* Y[P] hash values */
        return 0;

    if (!PACKET_get_4_len(pkt, &sig_lms_type))
        return 0;
    if (pub->lms_params->lms_type != sig_lms_type)
        return 0;
    lparams = pub->lms_params;
    if (HASH_NOT_MATCHED(pub->lms_params, sig_params))
        return 0;
    if (lsig->q >= (uint32_t)(1 << lparams->h))
        return 0;

    if (!PACKET_get_bytes_shallow(pkt, &lsig->paths, lparams->h * lparams->n)) /* path[h] hash values */
        return 0;
    return 1;
}

#if 0
static int lms_sig_from_data(const unsigned char *sig, size_t siglen,
                             const LMS_PUB_KEY *pub, LMS_SIG *out)
{
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, sig, siglen))
        return 0;
    if (!lms_sig_from_pkt(&pkt, pub, out))
        return 0;
    return PACKET_remaining(&pkt) == 0;
}
#endif

/*
 * RFC 8554 Algorithm 6: Steps 1 & 2.
 * Steps that involve checking the size of the public key data are
 * done indirectly by checking the return result of PACKET_get API's.
 */
static int lms_pubkey_from_pkt(PACKET *pkt, LMS_PUB_KEY *key)
{
    uint32_t lms_type;
    uint32_t ots_type;

    if (!PACKET_get_4_len(pkt, &lms_type))
        return 0;
    key->lms_params = LMSParams_get(lms_type);
    if (key->lms_params == NULL)
        return 0;

    if (!PACKET_get_4_len(pkt, &ots_type))
        return 0;
    key->ots_params = LMOTSParams_get(ots_type);
    if (key->ots_params == NULL)
        return 0;

    if (HASH_NOT_MATCHED(key->ots_params, key->lms_params))
        return 0;
    if (!PACKET_get_bytes_shallow(pkt, &key->I, ISIZE)) /* 16 byte Id */
        return 0;
    if (!PACKET_get_bytes_shallow(pkt, &key->K, key->lms_params->n))
        return 0;
    return 1;
}

#if 0
static int lms_pubkey_from_data(const unsigned char *pub, size_t publen,
                                LMS_PUB_KEY *key)
{
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, pub, publen))
        return 0;
    if (!lms_pubkey_from_pkt(&pkt, key))
        return 0;
    return PACKET_remaining(&pkt) == 0;
}
#endif

static int hss_pubkey_from_pkt(PACKET *pkt, HSS_PUB_KEY *key)
{
    if (!PACKET_get_4_len(pkt, &key->L))
        return 0;
    if (key->L < HSS_MIN_L || key->L > HSS_MAX_L)
        return 0;
    return lms_pubkey_from_pkt(pkt, &key->pub);
}

static
int OSSL_HSS_verify_init(LMS_VERIFY_CTX *ctx,
                         const unsigned char *pub, size_t publen,
                         const unsigned char *sig, size_t siglen)
{
    HSS_PUB_KEY hss_pub;
    const unsigned char *pubkey_blob[16];
    size_t pubkey_bloblen[16];
    PACKET pkt;
    uint32_t Nspk, i;
    int ret = 0;

    if (!PACKET_buf_init(&pkt, pub, publen))
        return 0;
    if (!hss_pubkey_from_pkt(&pkt, &hss_pub))
        return 0;
    if (PACKET_remaining(&pkt) > 0)
        return 0;
    ctx->publist[0] = hss_pub.pub;

    if (!PACKET_buf_init(&pkt, sig, siglen))
        return 0;
    if (!PACKET_get_4_len(&pkt, &Nspk)) /* Number of signed public keys */
        return 0;
    if (Nspk != (hss_pub.L - 1))
        return 0;

    for (i = 0; i < Nspk; ++i) {
        if (!lms_sig_from_pkt(&pkt, &ctx->publist[i], &ctx->siglist[i]))
            return 0;
        pubkey_blob[i] = PACKET_data(&pkt);
        if (!lms_pubkey_from_pkt(&pkt, &ctx->publist[i+1]))
            return 0;
        pubkey_bloblen[i] = PACKET_data(&pkt) - pubkey_blob[i];
    }
    if (!lms_sig_from_pkt(&pkt, &ctx->publist[Nspk], &ctx->siglist[Nspk]))
        return 0;
    if (PACKET_remaining(&pkt) > 0)
        return 0;

    for (i = 0; i < Nspk; ++i) {
        if (lms_sig_verify(&ctx->siglist[i], &ctx->publist[i],
                           pubkey_blob[i], pubkey_bloblen[i]) != 1)
            goto err;
    }
    if (lms_sig_verify_init(ctx, &ctx->siglist[Nspk], &ctx->publist[Nspk]) != 1)
        goto err;
    ret = 1;
err:
    return ret;
}

static
int OSSL_HSS_verify_update(LMS_VERIFY_CTX *ctx,
                           const unsigned char *msg, size_t msglen)
{
    return lms_sig_verify_update(ctx, msg, msglen);
}

static
int OSSL_HSS_verify_final(LMS_VERIFY_CTX *ctx)
{
    return lms_sig_verify_final(ctx);
}

int OSSL_HSS_verify(const unsigned char *pub, size_t publen,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *msg, size_t msglen)
{
    int ret = 0;
    LMS_VERIFY_CTX *ctx;

    ctx = OSSL_HSS_verify_new();
    if (ctx == NULL)
        return 0;
    ret = OSSL_HSS_verify_init(ctx, pub, publen, sig, siglen)
          && OSSL_HSS_verify_update(ctx, msg, msglen)
          && OSSL_HSS_verify_final(ctx);
    OSSL_HSS_verify_free(ctx);
    return ret;
}

#if 0
static
int OSSL_LMS_verify(LMS_VERIFY_CTX *ctx,
                    const unsigned char *pub, size_t publen,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *msg, size_t msglen)
{
    LMS_PUB_KEY pubkey;
    LMS_SIG s;

    if (!lms_pubkey_from_data(pub, publen, &pubkey))
        return 0;
    if (!lms_sig_from_data(sig, siglen, &pubkey, &s))
        return 0;
    return lms_sig_verify(&sig, &pubkey, msg, msglen);
}
#endif
