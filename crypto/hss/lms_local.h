/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_LMS_LOCAL_H
# define OSSL_LMS_LOCAL_H
# pragma once

#include "crypto/hss.h"

# define LMS_MAX_DIGEST_SIZE 32

/*
 * See RFC 8554 Section 9.1. Hash Formats
 *
 * The Hash function H() is used on the following data types.
 *
 * I || u32str(q) || u16str(i)      || u8str(j)    || tmp
 * I || u32str(q) || u16str(i)      || u8str(0xff) || SEED
 * I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1]
 * I || u32str(q) || u16str(D_MESG) || C || message
 * I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[r-2^h]
 * I || u32str(r) || u16str(D_INTR) || T[2*r] || T[2*r+1]
 *
 * So we use the following sizes and offsets to access the data
 */
# define LMS_SIZE_I 16
# define LMS_SIZE_q 4
# define LMS_SIZE_i 2
# define LMS_SIZE_DTAG LMS_SIZE_i
# define LMS_SIZE_j 1

# define LMS_OFFSET_q LMS_SIZE_I
# define LMS_OFFSET_i (LMS_OFFSET_q + LMS_SIZE_q)
# define LMS_OFFSET_j (LMS_OFFSET_i + LMS_SIZE_i)
# define LMS_OFFSET_SEED (LMS_OFFSET_j + LMS_SIZE_j)

/* The values defined for 8 byte TAGS */
extern const uint16_t OSSL_LMS_D_PBLC;      /* 8080 */
extern const uint16_t OSSL_LMS_D_MESG;      /* 8181 */
extern const uint16_t OSSL_LMS_D_LEAF;      /* 8282 */
extern const uint16_t OSSL_LMS_D_INTR;      /* 8383 */
/*
 * The following values are not defined in RFC 8554
 * They are used for ACVP testing, in order to have a deterministic sign,
 * See https://github.com/cisco/hash-sigs/blob/master/ACVP Definition.txt
 */
extern const uint16_t OSSL_LMS_D_C;         /* FFFD */
extern const uint16_t OSSL_LMS_D_CHILD_SEED;/* FFFE */
extern const uint16_t OSSL_LMS_D_CHILD_I;   /* FFFF */

/* XDR sizes when encoding and decoding */
# define LMS_SIZE_LMS_TYPE 4
# define LMS_SIZE_OTS_TYPE 4
# define LMS_SIZE_L        4
/* Used by OTS signature when doing Q || Cksm(Q) */
# define LMS_SIZE_CHECKSUM 2
# define LMS_SIZE_QSUM 2

/*
 * OpenSSL does not have a "SHAKE256-192" algorithm, so we have to check the
 * digest size as well as the name, when we check that the digest is the same
 * for each LMS tree in the HSS.
 */
# define HASH_NOT_MATCHED(a, b) \
a->n != b->n || (strcmp(a->digestname, b->digestname) != 0)

/* Convert a 32 bit value |in| to 4 bytes |out| */
# define U32STR(out, in)                       \
(out)[0] = (unsigned char)((in >> 24) & 0xff); \
(out)[1] = (unsigned char)((in >> 16) & 0xff); \
(out)[2] = (unsigned char)((in >> 8) & 0xff);  \
(out)[3] = (unsigned char)(in & 0xff)

int ossl_lms_hash(EVP_MD_CTX *ctx,
                  const unsigned char *in1, size_t in1len,
                  const unsigned char *in2, size_t in2len,
                  unsigned char *out);
int ossl_hss_sig_to_text(BIO *out, HSS_KEY *hsskey, int selection);

int ossl_lms_key_reset(LMS_KEY *lmskey, int nodeid, LMS_KEY *parent);
int ossl_lms_pubkey_compute(LMS_KEY *lmskey);
int ossl_lms_key_get_pubkey_from_nodeid(LMS_KEY *key,
                                        uint32_t nodeid, unsigned char *out);
size_t ossl_lms_pubkey_encode_len(LMS_KEY *lmskey);
int ossl_lms_pubkey_to_pkt(WPACKET *pkt, LMS_KEY *lmskey);
int ossl_lms_pubkey_decode(const unsigned char *pub, size_t publen,
                           LMS_KEY *lmskey);


int ossl_lm_ots_ctx_pubkey_init(LM_OTS_CTX *ctx,
                                const EVP_MD *md,
                                const LM_OTS_SIG *sig,
                                const LM_OTS_PARAMS *pub,
                                const unsigned char *I, uint32_t q);
int ossl_lm_ots_ctx_pubkey_update(LM_OTS_CTX *ctx,
                                  const unsigned char *msg, size_t msglen);
int ossl_lm_ots_ctx_pubkey_final(LM_OTS_CTX *ctx, unsigned char *Kc);

/**
 * @brief Helper function to return a ptr to a pkt buffer and move forward.
 * Used when decoding byte array XDR data.
 *
 * @param pkt A PACKET object that needs to have at least len bytes remaining.
 * @param out The returned ptr to the current position in the pkt buffer.
 * @param len The amount that we will move forward in the pkt buffer.
 * @returns 1 if there is enough bytes remaining to be able to skip forward,
 *          or 0 otherwise.
 */
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

/**
 * @brief Get 4 bytes in network order from |pkt| and store the value in |*data|
 * Similar to PACKET_get_net_4() except the data is uint32_t
 *
 * @param pkt Contains a buffer to read from
 * @param data The object to write the data to.
 * @returns 1 on success, or 0 otherwise.
 */
static ossl_inline int PACKET_get_4_len(PACKET *pkt, uint32_t *data)
{
    size_t i = 0;
    int ret = PACKET_get_net_4_len(pkt, &i);

    if (ret)
        *data = (uint32_t)i;
    return ret;
}

/**
 * @brief Helper function to go backwards |len| bytes in a WPACKET
 *
 * @param pkt Contain a a write buffer to go backwards in
 * @param len The number of bytes to reverse by.
 * @returns 1 on success, or 0 if we try to go past the start of the |pkt|.
 */
static ossl_inline int WPACKET_backward(WPACKET *pkt, size_t len)
{
    if (len > pkt->written)
        return 0;
    pkt->curr -= len;
    pkt->written -= len;
    return 1;
}

int ossl_lms_pubkey_cache_new(LMS_KEY *key);
void ossl_lms_pubkey_cache_free(LMS_KEY *key);
void ossl_lms_pubkey_cache_flush(LMS_KEY *key);
void ossl_lms_pubkey_cache_add(LMS_KEY *key, uint32_t nodeid,
                                const unsigned char *data);
int ossl_lms_pubkey_cache_get(LMS_KEY *key, uint32_t nodeid, unsigned char *out);

# if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
int ossl_lms_pubkey_cache_copy(LMS_KEY *dst, const LMS_KEY *src);

int ossl_lms_signature_gen_init(LMS_KEY *key, LMS_SIG *sig);
int ossl_lms_signature_gen_update(LMS_KEY *key,
                                  const unsigned char *msg, size_t msglen);
int ossl_lms_signature_gen_final(LMS_KEY *key, LMS_SIG *sig);
int ossl_lms_signature_gen(LMS_KEY *key,
                           const unsigned char *msg, size_t msglen,
                           LMS_SIG *sig);
LMS_SIG *ossl_lms_sig_deep_copy(const LMS_SIG *src);
LMS_KEY *ossl_lms_key_deep_copy(const LMS_KEY *src);
LMS_KEY *ossl_lms_key_gen(uint32_t lms_type, uint32_t ots_type,
                          OSSL_LIB_CTX *libctx, const char *propq,
                          LMS_KEY *parent);
int ossl_lms_sig_xdr_encode(LMS_SIG *sig, unsigned char *out, size_t *outlen);

int ossl_lm_ots_signature_gen(LMS_KEY *key,
                              const unsigned char *msg, size_t msglen,
                              LM_OTS_SIG *sig);
int ossl_lm_ots_signature_gen_init(LMS_KEY *key, LM_OTS_SIG *sig);
int ossl_lm_ots_signature_gen_update(LMS_KEY *key,
                                     const unsigned char *msg, size_t msglen);
int ossl_lm_ots_signature_gen_final(LMS_KEY *key, LM_OTS_SIG *sig);
# endif /* OPENSSL_NO_HSS_GEN */

#endif /* OSSL_LMS_LOCAL_H */
