/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* An OpenSSL-based high level interface to HPKE */
#include <stddef.h>
#include <openssl/hpke.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <internal/packet.h>
#include <openssl/err.h>

int OSSL_HPKE_seal_base(OSSL_HPKE_SUITE suite,
						const unsigned char *receiver, size_t receiverlen,
						const unsigned char *pt, size_t ptlen,
						const unsigned char *aad, size_t aadlen,
						unsigned char **box, size_t *boxlen,
						OSSL_LIB_CTX *libctx, const char *propq)
{
    size_t ctlen;
    size_t enclen;
    unsigned char *enc = NULL;
    unsigned char *ct = NULL;
    OSSL_HPKE_CTX *ctx = NULL;
    WPACKET pkt;
    int ret = 0;

    if (box == NULL || *box != NULL || boxlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        goto end;
    }

    ctlen = OSSL_HPKE_get_ciphertext_size(suite, ptlen);
    if (ctlen == 0)
        goto end;
    enclen = OSSL_HPKE_get_public_encap_size(suite);
    if (enclen == 0)
        goto end;

    /*
	 * Format: 4 byte length, encapsulation.
     * 4 byte length, ciphertext.
     * No trailing data allowed.
     */
    *boxlen = 8 + enclen + ctlen;
    *box = OPENSSL_malloc(*boxlen);
    if (*box == NULL)
        goto boxerr;
    if (!WPACKET_init_static_len(&pkt, *box, *boxlen, 0))
        goto boxerr;

    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_SENDER, libctx, propq);
    if (ctx == NULL)
        goto err;

    if (!WPACKET_start_sub_packet_u32(&pkt)
        || !WPACKET_reserve_bytes(&pkt, enclen, &enc)
        || !OSSL_HPKE_encap(ctx, enc, &enclen, receiver, receiverlen, NULL, 0)
        || !WPACKET_allocate_bytes(&pkt, enclen, NULL)
        || !WPACKET_close(&pkt))
        goto err;

    if (!WPACKET_start_sub_packet_u32(&pkt)
        || !WPACKET_reserve_bytes(&pkt, ctlen, &ct)
        || !OSSL_HPKE_seal(ctx, ct, &ctlen, aad, aadlen, pt, ptlen)
        || !WPACKET_allocate_bytes(&pkt, ctlen, NULL)
        || !WPACKET_close(&pkt))
        goto err;

    if (!WPACKET_get_length(&pkt, boxlen)
        || !WPACKET_finish(&pkt))
        goto err;

    ret = 1;
    goto end;

 err:
    WPACKET_cleanup(&pkt);
 boxerr:
    OPENSSL_free(*box);
	*box = NULL;
	*boxlen = 0;
 end:
    OSSL_HPKE_CTX_free(ctx);
    return ret;
}

int OSSL_HPKE_open_base (OSSL_HPKE_SUITE suite,
						 EVP_PKEY *recippriv,
						 const unsigned char *box, size_t boxlen,
						 const unsigned char *aad, size_t aadlen,
						 unsigned char **ptx, size_t *ptlen,
						 OSSL_LIB_CTX *libctx,const char *propq)
{
    unsigned long  enclen;
    unsigned long  ctlen;
    OSSL_HPKE_CTX *ctx = NULL;
    PACKET pkt;
    PACKET encpkt;
    PACKET ctpkt;
    int ret = 0;
    if (ptx == NULL || *ptx != NULL || ptlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

	if (!PACKET_buf_init(&pkt, box, boxlen)
        || !PACKET_get_net_4(&pkt, &enclen)
        || !PACKET_get_sub_packet(&pkt, &encpkt, (size_t) enclen)
        || !PACKET_get_net_4(&pkt, &ctlen)
        || !PACKET_get_sub_packet(&pkt, &ctpkt, (size_t) ctlen)
        || PACKET_remaining(&pkt) != 0)
        goto err;

    *ptlen = ctlen;
    *ptx = OPENSSL_malloc(*ptlen);
    if (*ptx == NULL)
        goto err;

    ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_RECEIVER, libctx, propq);
    if (ctx == NULL)
        goto err;
    if (!OSSL_HPKE_decap(ctx, PACKET_data(&encpkt), enclen, recippriv, NULL, 0)
        || !OSSL_HPKE_open(ctx, *ptx, ptlen, aad, aadlen, PACKET_data(&ctpkt), ctlen))
        goto err;

    ret = 1;
    goto end;
err:
    OPENSSL_free(*ptx);
	*ptx = NULL;
	*ptlen = 0;
 end:
    OSSL_HPKE_CTX_free(ctx);
    return ret;
}
