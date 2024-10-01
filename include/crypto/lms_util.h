/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* @brief Internal LMS internal helper functions */

#include "internal/packet.h"

/*
 * This LMS implementation assumes that the hash algorithm must be the same for
 * LMS params and OTS params. Since OpenSSL does not have a "SHAKE256-192"
 * algorithm, we have to check the digest size as well as the name.
 * This macro can be used to compare 2 LMS_PARAMS, LMS_PARAMS and LM_OTS_PARAMS.
 */
#define HASH_NOT_MATCHED(a, b) \
    (a)->n != (b)->n || (strcmp((a)->digestname, (b)->digestname) != 0)

/* Convert a 32 bit value |in| to 4 bytes |out| */
#define U32STR(out, in)                             \
    (out)[0] = (unsigned char)(((in) >> 24) & 0xff); \
    (out)[1] = (unsigned char)(((in) >> 16) & 0xff); \
    (out)[2] = (unsigned char)(((in) >> 8) & 0xff);  \
    (out)[3] = (unsigned char)((in) & 0xff)

/* Convert a 16 bit value |in| to 2 bytes |out| */
#define U16STR(out, in)                             \
    (out)[0] = (unsigned char)(((in) >> 8) & 0xff); \
    (out)[1] = (unsigned char)((in) & 0xff)

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

/*
 * See RFC 8554 Section 3.1.3: Strings of w-bit Elements
 * w: Is one of {1,2,4,8}
 */
static ossl_inline uint8_t coef(const unsigned char *S, uint16_t i, uint8_t w)
{
    uint8_t bitmask = (1 << w) - 1;
    uint8_t shift = 8 - (w * (i % (8 / w)) + w);
    int id = (i * w) / 8;

    return (S[id] >> shift) & bitmask;
}

#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
static ossl_inline int evp_md_ctx_init(EVP_MD_CTX *ctx, const EVP_MD *md,
                                       const LMS_PARAMS *lms_params)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PARAM *p = NULL;

    /* The OpenSSL SHAKE implementation requires the xoflen to be set */
    if (strncmp(lms_params->digestname, "SHAKE", 5) == 0) {
        params[0] = OSSL_PARAM_construct_uint32(OSSL_DIGEST_PARAM_XOFLEN,
                                                (uint32_t *)&lms_params->n);
        p = params;
    }
    return EVP_DigestInit_ex2(ctx, md, p);
}
