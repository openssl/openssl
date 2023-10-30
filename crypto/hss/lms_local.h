/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_LMS_LOCAL_H
# define OSSL_LMS_LOCAL_H
# pragma once

# define LMS_MAX_DIGEST_SIZE 32
/*
 * OpenSSL does not have a "SHAKE256-192" algorithm, so we have to check the
 * digest size as well as the name.
 */
# define HASH_NOT_MATCHED(a, b) \
a->n != b->n || (strcmp(a->digestname, b->digestname) != 0)

# define U32STR(out, in)                      \
out[0] = (unsigned char)((in >> 24) & 0xff); \
out[1] = (unsigned char)((in >> 16) & 0xff); \
out[2] = (unsigned char)((in >> 8) & 0xff);  \
out[3] = (unsigned char)(in & 0xff)

int ossl_lm_ots_ctx_pubkey_init(LM_OTS_CTX *ctx,
                                const EVP_MD *md,
                                const LM_OTS_SIG *sig,
                                const LM_OTS_PARAMS *pub,
                                const unsigned char *I, uint32_t q);
int ossl_lm_ots_ctx_pubkey_update(LM_OTS_CTX *ctx,
                                  const unsigned char *msg, size_t msglen);
int ossl_lm_ots_ctx_pubkey_final(LM_OTS_CTX *ctx, unsigned char *Kc);

const LM_OTS_PARAMS *ossl_lm_ots_params_get(uint32_t ots_type);
const LMS_PARAMS *ossl_lms_params_get(uint32_t lms_type);

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

#endif /* OSSL_LMS_LOCAL_H */
