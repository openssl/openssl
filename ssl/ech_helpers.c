/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * These functions are ECH helpers that are used by functions within
 * ssl/ech.c but also by test code e.g. in test/echcorrupttest.c
 */

#include <openssl/ssl.h>
#include <internal/ech_helpers.h>
#include <internal/packet.h>

#ifndef OPENSSL_NO_ECH

# ifndef CLIENT_VERSION_LEN
/*
 * This is the legacy version length, i.e. len(0x0303). The same
 * label is used in e.g. test/sslapitest.c and elsewhere but not
 * defined in a header file I could find.
 */
#  define CLIENT_VERSION_LEN 2
# endif

/*
 * Strings used in ECH crypto derivations (odd format for EBCDIC goodness)
 */
/* "tls ech" */
static const char OSSL_ECH_CONTEXT_STRING[] = "\x74\x6c\x73\x20\x65\x63\x68";

/*
 * @brief Given a CH find the offsets of the session id, extensions and ECH
 * @param: ch is the encoded client hello
 * @param: ch_len is the length of ch
 * @param: sessid returns offset of session_id length
 * @param: exts points to offset of extensions
 * @param: extlens returns length of extensions
 * @param: echoffset returns offset of ECH
 * @param: echtype returns the ext type of the ECH
 * @param: echlen returns the length of the ECH
 * @param: snioffset returns offset of (outer) SNI
 * @param: snilen returns the length of the SNI
 * @param: inner 1 if the ECH is marked as an inner, 0 for outer
 * @return 1 for success, other otherwise
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 *
 * Note: input here is untrusted!
 */
int ech_helper_get_ch_offsets(const unsigned char *ch, size_t ch_len,
                              size_t *sessid, size_t *exts, size_t *extlens,
                              size_t *echoffset, uint16_t *echtype,
                              size_t *echlen,
                              size_t *snioffset, size_t *snilen, int *inner)
{
    unsigned int elen = 0, etype = 0, pi_tmp = 0;
    const unsigned char *pp_tmp = NULL, *chstart = NULL, *estart = NULL;
    PACKET pkt;
    int done = 0;

    if (ch == NULL || ch_len == 0 || sessid == NULL || exts == NULL
        || echoffset == NULL || echtype == NULL || echlen == NULL
        || inner == NULL
        || snioffset == NULL)
        return 0;
    *sessid = *exts = *echoffset = *snioffset = *snilen = *echlen = 0;
    *echtype = 0xffff;
    if (!PACKET_buf_init(&pkt, ch, ch_len))
        return 0;
    chstart = PACKET_data(&pkt);
    if (!PACKET_get_net_2(&pkt, &pi_tmp))
        return 0;
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (pi_tmp != TLS1_2_VERSION && pi_tmp != TLS1_3_VERSION)
        return 1;
    /* chew up the packet to extensions */
    if (!PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
        || (*sessid = PACKET_data(&pkt) - chstart) == 0
        || !PACKET_get_1(&pkt, &pi_tmp) /* sessid len */
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* sessid */
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite len */
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* suites */
        || !PACKET_get_1(&pkt, &pi_tmp) /* compression meths */
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* comp meths */
        || (*exts = PACKET_data(&pkt) - chstart) == 0
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* len(extensions) */
        || (*extlens = (size_t) pi_tmp) == 0)
        /*
         * unexpectedly, we return 1 here, as doing otherwise will
         * break some non-ECH test code that truncates CH messages
         * The same is true below when looking through extensions.
         * That's ok though, we'll only set those offsets we've
         * found.
         */
        return 1;
    /* no extensions is theoretically ok, if uninteresting */
    if (*extlens == 0)
        return 1;
    /* find what we want from extensions */
    estart = PACKET_data(&pkt);
    while (PACKET_remaining(&pkt) > 0
           && (size_t)(PACKET_data(&pkt) - estart) < *extlens
           && done < 2) {
        if (!PACKET_get_net_2(&pkt, &etype)
            || !PACKET_get_net_2(&pkt, &elen))
            return 1; /* see note above */
        if (etype == TLSEXT_TYPE_ech) {
            if (elen == 0)
                return 0;
            *echoffset = PACKET_data(&pkt) - chstart - 4;
            *echtype = etype;
            *echlen = elen;
            done++;
        }
        if (etype == TLSEXT_TYPE_server_name) {
            *snioffset = PACKET_data(&pkt) - chstart - 4;
            *snilen = elen;
            done++;
        }
        if (!PACKET_get_bytes(&pkt, &pp_tmp, elen))
            return 1; /* see note above */
        if (etype == TLSEXT_TYPE_ech)
            *inner = pp_tmp[0];
    }
    return 1;
}

/*!
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * @param: sh is the SH buffer
 * @paramL sh_len is the length of the SH
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @return 1 for success, other otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
int ech_helper_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                              size_t *exts, size_t *echoffset,
                              uint16_t *echtype)
{
    unsigned int elen = 0, etype = 0, pi_tmp = 0;
    const unsigned char *pp_tmp = NULL, *shstart = NULL, *estart = NULL;
    PACKET pkt;
    size_t extlens = 0;
    int done = 0;
# ifdef OSSL_ECH_SUPERVERBOSE
    size_t echlen = 0; /* length of ECH, including type & ECH-internal length */
    size_t sessid_offset = 0;
    size_t sessid_len = 0;
# endif

    if (sh == NULL || sh_len == 0 || exts == NULL || echoffset == NULL
        || echtype == NULL)
        return 0;
    *exts = *echoffset = *echtype = 0;
    if (!PACKET_buf_init(&pkt, sh, sh_len))
        return 0;
    shstart = PACKET_data(&pkt);
    if (!PACKET_get_net_2(&pkt, &pi_tmp))
        return 0;
    /* if we're not TLSv1.2+ then we can bail, but it's not an error */
    if (pi_tmp != TLS1_2_VERSION && pi_tmp != TLS1_3_VERSION)
        return 1;
    if (!PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
# ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_offset = PACKET_data(&pkt) - shstart) == 0
# endif
        || !PACKET_get_1(&pkt, &pi_tmp) /* sessid len */
# ifdef OSSL_ECH_SUPERVERBOSE
        || (sessid_len = (size_t)pi_tmp) == 0
# endif
        || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* sessid */
        || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite */
        || !PACKET_get_1(&pkt, &pi_tmp) /* compression */
        || (*exts = PACKET_data(&pkt) - shstart) == 0
        || !PACKET_get_net_2(&pkt, &pi_tmp)) /* len(extensions) */
        return 0;
    extlens = (size_t)pi_tmp;
    if (extlens == 0) /* not an error, in theory */
        return 1;
    estart = PACKET_data(&pkt);
    while (PACKET_remaining(&pkt) > 0
           && (size_t)(PACKET_data(&pkt) - estart) < extlens
           && done < 1) {
        if (!PACKET_get_net_2(&pkt, &etype)
            || !PACKET_get_net_2(&pkt, &elen))
            return 0;
        if (etype == TLSEXT_TYPE_ech) {
            if (elen == 0)
                return 0;
            *echoffset = PACKET_data(&pkt) - shstart - 4;
            *echtype = etype;
# ifdef OSSL_ECH_SUPERVERBOSE
            echlen = elen + 4; /* type and length included */
# endif
            done++;
        }
        if (!PACKET_get_bytes(&pkt, &pp_tmp, elen))
            return 0;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig SH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ech_pbuf("orig SH", (unsigned char *)sh, sh_len);
    ech_pbuf("orig SH session_id", (unsigned char *)sh + sessid_offset,
             sessid_len);
    ech_pbuf("orig SH exts", (unsigned char *)sh + *exts, extlens);
    ech_pbuf("orig SH/ECH ", (unsigned char *)sh + *echoffset, echlen);
# endif
    return 1;
}

/*
 * @brief make up HPKE "info" input as per spec
 * @param encoding is the ECHconfig being used
 * @param encodinglen is the length of ECHconfig being used
 * @param info is a caller-allocated buffer for results
 * @param info_len is the buffer size on input, used-length on output
 * @return 1 for success, other otherwise
 */
int ech_helper_make_enc_info(unsigned char *encoding, size_t encoding_length,
                             unsigned char *info, size_t *info_len)
{
    unsigned char *ip = info;

    if (encoding == NULL || info == NULL || info_len == NULL)
        return 0;
    /*
     * note: we could use strlen() below but I guess sizeof is a litte
     * better - if using strlen() then we'd have a few "+ 1"'s below
     * as the sizeof is 1 bigger than the strlen
     */
    if (*info_len < (sizeof(OSSL_ECH_CONTEXT_STRING) + encoding_length))
        return 0;
    memcpy(ip, OSSL_ECH_CONTEXT_STRING, sizeof(OSSL_ECH_CONTEXT_STRING) - 1);
    ip += sizeof(OSSL_ECH_CONTEXT_STRING) - 1;
    *ip++ = 0x00;
    memcpy(ip, encoding, encoding_length);
    *info_len = sizeof(OSSL_ECH_CONTEXT_STRING) + encoding_length;
    return 1;
}

/*
 * @brief Decode from TXT RR to binary buffer
 * @param in is the base64 encoded string
 * @param inlen is the length of in
 * @param out is the binary equivalent
 * @return is the number of octets in |out| if successful, <=0 for failure
 */
int ech_helper_base64_decode(char *in, size_t inlen, unsigned char **out)
{
    int i = 0, outlen = 0;
    unsigned char *outbuf = NULL;

    if (in == NULL || out == NULL)
        return 0;
    if (inlen == 0) {
        *out = NULL;
        return 0;
    }
    /* overestimate of space but easier */
    outbuf = OPENSSL_malloc(inlen);
    if (outbuf == NULL)
        goto err;
    /* For ECH we'll never see this but just so we have bounds */
    if (inlen <= OSSL_ECH_MIN_ECHCONFIG_LEN
        || inlen > OSSL_ECH_MAX_ECHCONFIG_LEN)
        goto err;
    /* Check padding bytes in input.  More than 2 is malformed. */
    i = 0;
    while (in[inlen - i - 1] == '=') {
        if (++i > 2)
            goto err;
    }
    outlen = EVP_DecodeBlock(outbuf, (unsigned char *)in, inlen);
    outlen -= i; /* subtract padding */
    if (outlen < 0)
        goto err;
    *out = outbuf;
    return outlen;
err:
    OPENSSL_free(outbuf);
    *out = NULL;
    return 0;
}
#endif
