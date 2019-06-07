/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * A simple ASN.1 DER encoder/decoder for DSA-Sig-Value and ECDSA-Sig-Value.
 *
 * DSA-Sig-Value ::= SEQUENCE {
 *  r  INTEGER,
 *  s  INTEGER
 * }
 *
 * ECDSA-Sig-Value ::= SEQUENCE {
 *  r  INTEGER,
 *  s  INTEGER
 * }
 */

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "internal/asn1_dsa.h"
#include "internal/packet.h"

#define ID_SEQUENCE 0x30
#define ID_INTEGER 0x02

/*
 * Outputs the encoding of the length octets for a DER value with a content
 * length of cont_len bytes to *ppout and, if successful, increments *ppout
 * past the data just written.
 *
 * The maximum supported content length is 65535 (0xffff) bytes.
 * The maximum returned length in bytes of the encoded output is 3.
 *
 * If ppout is NULL then the output size is calculated and returned but no
 * output is produced.
 * If ppout is not NULL then *ppout must not be NULL.
 *
 * An attempt to produce more than len bytes results in an error.
 * Returns the number of bytes of output produced (or that would be produced)
 * or 0 if an error occurs.
 */
size_t encode_der_length(size_t cont_len, unsigned char **ppout, size_t len)
{
    size_t encoded_len;

    if (cont_len <= 0x7f) {
        encoded_len = 1;
    } else if (cont_len <= 0xff) {
        encoded_len = 2;
    } else if (cont_len <= 0xffff) {
        encoded_len = 3;
    } else {
        /* Too large for supported length encodings */
        return 0;
    }
    if (encoded_len > len)
        return 0;
    if (ppout != NULL) {
        unsigned char *out = *ppout;
        switch (encoded_len) {
        case 2:
            *out++ = 0x81;
            break;
        case 3:
            *out++ = 0x82;
            *out++ = (unsigned char)(cont_len >> 8);
            break;
        }
        *out++ = (unsigned char)cont_len;
        *ppout = out;
    }
    return encoded_len;
}

/*
 * Outputs the DER encoding of a positive ASN.1 INTEGER to *ppout and, if
 * successful, increments *ppout past the data just written.
 *
 * If n is negative then an error results.
 * If ppout is NULL then the output size is calculated and returned but no
 * output is produced.
 * If ppout is not NULL then *ppout must not be NULL.
 *
 * An attempt to produce more than len bytes results in an error.
 * Returns the number of bytes of output produced (or that would be produced)
 * or 0 if an error occurs.
 */
size_t encode_der_integer(const BIGNUM *n, unsigned char **ppout, size_t len)
{
    unsigned char *out = NULL;
    unsigned char **pp = NULL;
    size_t produced;
    size_t c;
    size_t cont_len;

    if (len < 1 || BN_is_negative(n))
        return 0;

    /*
     * Calculate the ASN.1 INTEGER DER content length for n.
     * This is the number of whole bytes required to represent n (i.e. rounded
     * down), plus one.
     * If n is zero then the content is a single zero byte (length = 1).
     * If the number of bits of n is a multiple of 8 then an extra zero padding
     * byte is included to ensure that the value is still treated as positive
     * in the INTEGER two's complement representation.
     */
    cont_len = BN_num_bits(n) / 8 + 1;

    if (ppout != NULL) {
        out = *ppout;
        pp = &out;
        *out++ = ID_INTEGER;
    }
    produced = 1;
    if ((c = encode_der_length(cont_len, pp, len - produced)) == 0)
        return 0;
    produced += c;
    if (cont_len > len - produced)
        return 0;
    if (pp != NULL) {
        if (BN_bn2binpad(n, out, (int)cont_len) != (int)cont_len)
            return 0;
        out += cont_len;
        *ppout = out;
    }
    produced += cont_len;
    return produced;
}

/*
 * Outputs the DER encoding of a DSA-Sig-Value or ECDSA-Sig-Value to *ppout
 * and increments *ppout past the data just written.
 *
 * If ppout is NULL then the output size is calculated and returned but no
 * output is produced.
 * If ppout is not NULL then *ppout must not be NULL.
 *
 * An attempt to produce more than len bytes results in an error.
 * Returns the number of bytes of output produced (or that would be produced)
 * or 0 if an error occurs.
 */
size_t encode_der_dsa_sig(const BIGNUM *r, const BIGNUM *s,
                          unsigned char **ppout, size_t len)
{
    unsigned char *out = NULL;
    unsigned char **pp = NULL;
    size_t produced;
    size_t c;
    size_t r_der_len;
    size_t s_der_len;
    size_t cont_len;

    if (len < 1
            || (r_der_len = encode_der_integer(r, NULL, SIZE_MAX)) == 0
            || (s_der_len = encode_der_integer(s, NULL, SIZE_MAX)) == 0)
        return 0;

    cont_len = r_der_len + s_der_len;

    if (ppout != NULL) {
        out = *ppout;
        pp = &out;
        *out++ = ID_SEQUENCE;
    }
    produced = 1;
    if ((c = encode_der_length(cont_len, pp, len - produced)) == 0)
        return 0;
    produced += c;
    if ((c = encode_der_integer(r, pp, len - produced)) == 0)
        return 0;
    produced += c;
    if ((c = encode_der_integer(s, pp, len - produced)) == 0)
        return 0;
    produced += c;
    if (pp != NULL)
        *ppout = out;
    return produced;
}

/*
 * Decodes the DER length octets in pkt and initialises subpkt with the
 * following bytes of that length.
 * 
 * Returns 1 on success or 0 on failure.
 */
int decode_der_length(PACKET *pkt, PACKET *subpkt)
{
    unsigned int byte;

    if (!PACKET_get_1(pkt, &byte))
        return 0;

    if (byte < 0x80)
        return PACKET_get_sub_packet(pkt, subpkt, (size_t)byte);
    if (byte == 0x81)
        return PACKET_get_length_prefixed_1(pkt, subpkt);
    if (byte == 0x82)
        return PACKET_get_length_prefixed_2(pkt, subpkt);

    /* Too large, invalid, or not DER. */
    return 0;
}

/*
 * Decodes a single ASN.1 INTEGER value from pkt, which must be DER encoded,
 * and updates n with the decoded value.
 *
 * The BIGNUM, n, must have already been allocated by calling BN_new().
 * pkt must not be NULL.
 *
 * An attempt to consume more than len bytes results in an error.
 * Returns 1 on success or 0 on error.
 *
 * If the PACKET is supposed to only contain a single INTEGER value with no
 * trailing garbage then it is up to the caller to verify that all bytes
 * were consumed.
 */
int decode_der_integer(PACKET *pkt, BIGNUM *n)
{
    PACKET contpkt, tmppkt;
    unsigned int tag, tmp;

    /* Check we have an integer and get the content bytes */
    if (!PACKET_get_1(pkt, &tag)
            || tag != ID_INTEGER
            || !decode_der_length(pkt, &contpkt))
        return 0;

    /* Peek ahead at the first bytes to check for proper encoding */
    tmppkt = contpkt;
    /* The INTEGER must be positive */
    if (!PACKET_get_1(&tmppkt, &tmp)
            || (tmp & 0x80) != 0)
        return 0;
    /* If there a zero padding byte the next byte must have the msb set */
    if (PACKET_remaining(&tmppkt) > 0 && tmp == 0) {
        if (!PACKET_get_1(&tmppkt, &tmp)
                || (tmp & 0x80) == 0)
            return 0;
    }

    if (BN_bin2bn(PACKET_data(&contpkt),
                  (int)PACKET_remaining(&contpkt), n) == NULL)
        return 0;

    return 1;
}

/*
 * Decodes a single DSA-Sig-Value or ECDSA-Sig-Value from *ppin, which must be
 * DER encoded, updates r and s with the decoded values, and increments *ppin
 * past the data that was consumed.
 *
 * The BIGNUMs, r and s, must have already been allocated by calls to BN_new().
 * ppin and *ppin must not be NULL.
 *
 * An attempt to consume more than len bytes results in an error.
 * Returns the number of bytes of input consumed or 0 if an error occurs.
 *
 * If the buffer is supposed to only contain a single [EC]DSA-Sig-Value with no
 * trailing garbage then it is up to the caller to verify that all bytes
 * were consumed.
 */
size_t decode_der_dsa_sig(BIGNUM *r, BIGNUM *s, const unsigned char **ppin,
                          size_t len)
{
    size_t consumed;
    PACKET pkt, contpkt;
    unsigned int tag;

    if (!PACKET_buf_init(&pkt, *ppin, len)
            || !PACKET_get_1(&pkt, &tag)
            || tag != ID_SEQUENCE
            || !decode_der_length(&pkt, &contpkt)
            || !decode_der_integer(&contpkt, r)
            || !decode_der_integer(&contpkt, s)
            || PACKET_remaining(&contpkt) != 0)
        return 0;

    consumed = PACKET_data(&pkt) - *ppin;
    *ppin += consumed;
    return consumed;
}

