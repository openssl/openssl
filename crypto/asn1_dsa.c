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
 * Decodes the DER length octets at *ppin, stores the decoded length to
 * *pcont_len and, if successful, increments *ppin past the data that was
 * consumed.
 *
 * pcont_len, ppin and *ppin must not be NULL.
 *
 * An attempt to consume more than len bytes results in an error.
 * Returns the number of bytes of input consumed or 0 if an error occurs.
 */
size_t decode_der_length(size_t *pcont_len, const unsigned char **ppin,
                         size_t len)
{
    const unsigned char *in = *ppin;
    size_t consumed;
    size_t n;

    if (len < 1)
        return 0;
    n = *in++;
    consumed = 1;
    if (n > 0x7f) {
        if (n == 0x81 && len - consumed >= 1) {
            n = *in++;
            if (n <= 0x7f)
                return 0; /* Not DER. */
            ++consumed;
        } else if (n == 0x82 && len - consumed >= 2) {
            n = *in++ << 8;
            n |= *in++;
            if (n <= 0xff)
                return 0; /* Not DER. */
            consumed += 2;
        } else {
            return 0; /* Too large, invalid, or not DER. */
        }
    }
    *pcont_len = n;
    *ppin = in;
    return consumed;
}

/*
 * Decodes a single ASN.1 INTEGER value from *ppin, which must be DER encoded,
 * updates n with the decoded value, and, if successful, increments *ppin past
 * the data that was consumed.
 *
 * The BIGNUM, n, must have already been allocated by calling BN_new().
 * ppin and *ppin must not be NULL.
 *
 * An attempt to consume more than len bytes results in an error.
 * Returns the number of bytes of input consumed or 0 if an error occurs.
 *
 * If the buffer is supposed to only contain a single INTEGER value with no
 * trailing garbage then it is up to the caller to verify that all bytes
 * were consumed.
 */
size_t decode_der_integer(BIGNUM *n, const unsigned char **ppin, size_t len)
{
    const unsigned char *in = *ppin;
    size_t consumed;
    size_t c;
    size_t cont_len;

    if (len < 1 || n == NULL || *in++ != ID_INTEGER)
        return 0;
    consumed = 1;
    if ((c = decode_der_length(&cont_len, &in, len - consumed)) == 0)
        return 0;
    consumed += c;
    /* Check for a positive INTEGER with valid content encoding and decode. */
    if (cont_len > len - consumed || cont_len < 1 || (in[0] & 0x80) != 0
            || (cont_len >= 2 && in[0] == 0 && (in[1] & 0x80) == 0)
            || BN_bin2bn(in, (int)cont_len, n) == NULL)
        return 0;
    in += cont_len;
    consumed += cont_len;
    *ppin = in;
    return consumed;
}

static size_t decode_dsa_sig_content(BIGNUM *r, BIGNUM *s,
                                     const unsigned char **ppin, size_t len)
{
    const unsigned char *in = *ppin;
    size_t consumed = 0;
    size_t c;

    if ((c = decode_der_integer(r, &in, len - consumed)) == 0)
        return 0;
    consumed += c;
    if ((c = decode_der_integer(s, &in, len - consumed)) == 0)
        return 0;
    consumed += c;
    *ppin = in;
    return consumed;
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
    const unsigned char *in = *ppin;
    size_t consumed;
    size_t c;
    size_t cont_len;

    if (len < 1 || *in++ != ID_SEQUENCE)
        return 0;
    consumed = 1;
    if ((c = decode_der_length(&cont_len, &in, len - consumed)) == 0)
        return 0;
    consumed += c;
    if (cont_len > len - consumed
            || (c = decode_dsa_sig_content(r, s, &in, cont_len)) == 0
            || c != cont_len)
        return 0;
    consumed += c;
    *ppin = in;
    return consumed;
}

