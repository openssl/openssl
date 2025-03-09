/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "../ssl_local.h"
#include "ech_local.h"
#include "internal/ech_helpers.h"

/* TODO(ECH): move more code that's used by internals and test here */

/* used in ECH crypto derivations (odd format for EBCDIC goodness) */
/* "tls ech" */
static const char OSSL_ECH_CONTEXT_STRING[] = "\x74\x6c\x73\x20\x65\x63\x68";

/*
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * sh is the SH buffer
 * sh_len is the length of the SH
 * exts points to offset of extensions
 * echoffset points to offset of ECH
 * echtype points to the ext type of the ECH
 * return 1 for success, zero otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
int ossl_ech_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                            size_t *exts, size_t *echoffset,
                            uint16_t *echtype, uint16_t *echlen)
{
    unsigned int etype = 0, pi_tmp = 0;
    const unsigned char *pp_tmp = NULL, *shstart = NULL;
    PACKET pkt, session_id, extpkt, oneext;
    size_t extlens = 0;
    int done = 0;
#ifdef OSSL_ECH_SUPERVERBOSE
    size_t sessid_offset = 0, sessid_len = 0;
#endif

    if (sh == NULL || sh_len == 0 || exts == NULL || echoffset == NULL
        || echtype == NULL || echlen == NULL)
        return 0;
    *exts = *echoffset = *echtype = 0;
    if (!PACKET_buf_init(&pkt, sh, sh_len))
        return 0;
    shstart = PACKET_data(&pkt);
    if (!PACKET_get_net_2(&pkt, &pi_tmp))
        return 0;
    /*
     * TODO(ECH): we've had a TLSv1.2 test in the past where we add an
     * ECH to a TLSv1.2 CH to ensure server code ignores that properly.
     * We might or might not keep that, if we don't then the test below
     * should allow TLSv1.3 only.
     */
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (pi_tmp != TLS1_2_VERSION && pi_tmp != TLS1_3_VERSION)
        return 1;
    if (!PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
#ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_offset = PACKET_data(&pkt) - shstart) == 0
#endif
        || !PACKET_get_length_prefixed_1(&pkt, &session_id)
#ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_len = PACKET_remaining(&session_id)) == 0
#endif
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite */
        || !PACKET_get_1(&pkt, &pi_tmp) /* compression */
        || (*exts = PACKET_data(&pkt) - shstart) == 0
        || !PACKET_as_length_prefixed_2(&pkt, &extpkt)
        || PACKET_remaining(&pkt) != 0)
        return 0;
    extlens = PACKET_remaining(&extpkt);
    if (extlens == 0) /* not an error, in theory */
        return 1;
    while (PACKET_remaining(&extpkt) > 0 && done < 1) {
        if (!PACKET_get_net_2(&extpkt, &etype)
            || !PACKET_get_length_prefixed_2(&extpkt, &oneext))
            return 0;
        if (etype == TLSEXT_TYPE_ech) {
            if (PACKET_remaining(&oneext) != OSSL_ECH_SIGNAL_LEN)
                return 0;
            *echoffset = PACKET_data(&oneext) - shstart - 4;
            *echtype = etype;
            *echlen = (uint16_t)PACKET_remaining(&oneext) + 4;
            done++;
        }
    }
#ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig SH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ossl_ech_pbuf("orig SH", (unsigned char *)sh, sh_len);
    ossl_ech_pbuf("orig SH session_id", (unsigned char *)sh + sessid_offset,
                  sessid_len);
    ossl_ech_pbuf("orig SH exts", (unsigned char *)sh + *exts, extlens);
    ossl_ech_pbuf("orig SH/ECH ", (unsigned char *)sh + *echoffset, *echlen);
#endif
    return 1;
}

/*
 * make up HPKE "info" input as per spec
 * encoding is the ECHconfig being used
 * encoding_length is the length of ECHconfig being used
 * info is a caller-allocated buffer for results
 * info_len is the buffer size on input, used-length on output
 * return 1 for success, zero otherwise
 */
int ossl_ech_make_enc_info(unsigned char *encoding, size_t encoding_length,
                           unsigned char *info, size_t *info_len)
{
    WPACKET ipkt = { 0 };

    if (encoding == NULL || info == NULL || info_len == NULL)
        return 0;
    if (!WPACKET_init_static_len(&ipkt, info, *info_len, 0)
        || !WPACKET_memcpy(&ipkt, OSSL_ECH_CONTEXT_STRING,
                           sizeof(OSSL_ECH_CONTEXT_STRING) - 1)
        /*
         * the zero valued octet is required by the spec, section 7.1 so
         * a tiny bit better to add it explicitly rather than depend on
         * the context string being NUL terminated
         */
        || !WPACKET_put_bytes_u8(&ipkt, 0)
        || !WPACKET_memcpy(&ipkt, encoding, encoding_length)
        || !WPACKET_get_total_written(&ipkt, info_len)) {
        WPACKET_cleanup(&ipkt);
        return 0;
    }
    WPACKET_cleanup(&ipkt);
    return 1;
}
