/*
 * Copyright 2020-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_DER_H
#define OSSL_INTERNAL_DER_H
#pragma once

#include <openssl/bn.h>
#include "internal/packet.h"

/*
 * NOTE: X.690 numbers the identifier octet bits 1 to 8.
 * We use the same numbering in comments here.
 */

/* Well known primitive tags */

/*
 * DER UNIVERSAL tags, occupying bits 1-5 in the DER identifier byte
 * These are only valid for the UNIVERSAL class.  With the other classes,
 * these bits have a different meaning.
 */
#define DER_P_EOC 0 /* BER End Of Contents tag */
#define DER_P_BOOLEAN 1
#define DER_P_INTEGER 2
#define DER_P_BIT_STRING 3
#define DER_P_OCTET_STRING 4
#define DER_P_NULL 5
#define DER_P_OBJECT 6
#define DER_P_OBJECT_DESCRIPTOR 7
#define DER_P_EXTERNAL 8
#define DER_P_REAL 9
#define DER_P_ENUMERATED 10
#define DER_P_UTF8STRING 12
#define DER_P_SEQUENCE 16
#define DER_P_SET 17
#define DER_P_NUMERICSTRING 18
#define DER_P_PRINTABLESTRING 19
#define DER_P_T61STRING 20
#define DER_P_VIDEOTEXSTRING 21
#define DER_P_IA5STRING 22
#define DER_P_UTCTIME 23
#define DER_P_GENERALIZEDTIME 24
#define DER_P_GRAPHICSTRING 25
#define DER_P_ISO64STRING 26
#define DER_P_GENERALSTRING 27
#define DER_P_UNIVERSALSTRING 28
#define DER_P_BMPSTRING 30

/* DER Flags, occupying bit 6 in the DER identifier byte */
#define DER_F_PRIMITIVE 0x00
#define DER_F_CONSTRUCTED 0x20

/* DER classes tags, occupying bits 7-8 in the DER identifier byte */
#define DER_C_UNIVERSAL 0x00
#define DER_C_APPLICATION 0x40
#define DER_C_CONTEXT 0x80
#define DER_C_PRIVATE 0xC0

/*
 * Run-time constructors.
 *
 * They all construct DER backwards, so care should be taken to use them
 * that way.
 */

/* This can be used for all items that don't have a context */
#define DER_NO_CONTEXT -1

int ossl_DER_w_precompiled(WPACKET *pkt, int tag,
    const unsigned char *precompiled,
    size_t precompiled_n);

int ossl_DER_w_boolean(WPACKET *pkt, int tag, int b);
int ossl_DER_w_uint32(WPACKET *pkt, int tag, uint32_t v);
int ossl_DER_w_bn(WPACKET *pkt, int tag, const BIGNUM *v);
int ossl_DER_w_null(WPACKET *pkt, int tag);
int ossl_DER_w_octet_string(WPACKET *pkt, int tag,
    const unsigned char *data, size_t data_n);
int ossl_DER_w_octet_string_uint32(WPACKET *pkt, int tag, uint32_t value);

/*
 * All constructors for constructed elements have a begin and a end function
 */
int ossl_DER_w_begin_sequence(WPACKET *pkt, int tag);
int ossl_DER_w_end_sequence(WPACKET *pkt, int tag);

/*
 * Run-time parsers, the reading counterparts of the writers above.
 *
 * They use the same |tag| conventions as the writers: DER_NO_CONTEXT for
 * the bare element with its universal tag, or a context tag number (0-30)
 * for a constructed context specific element wrapping the value, exactly
 * as the corresponding writer produces it.  This means that anything the
 * writers produce can be read back with the corresponding reader using
 * the same |tag| argument.
 *
 * The parsers are strict: only valid DER is accepted.  Indefinite
 * lengths, non-minimal length encodings (the long form where the short
 * form would do, or with superfluous leading zero octets), INTEGERs
 * with superfluous sign padding octets, and BOOLEAN TRUE values other
 * than 0xFF are all rejected, as is the high-tag-number form (tag
 * numbers larger than 30), which is unsupported.  This matches what
 * the writers produce.
 *
 * The readers are atomic: |pkt| is advanced on success and left
 * unchanged on failure, so trial parsing (of CHOICE or OPTIONAL
 * elements, for example) is safe.
 */

/**
 * @brief Lowest level reader: read one DER element from |pkt|.
 * @param pkt the packet to read from; advanced past the element on
 * success, left unchanged on failure
 * @param identifier receives the identifier octet (the DER class, the
 * constructed flag and the tag number)
 * @param contents receives a sub-PACKET holding the contents octets;
 * may be NULL to merely skip the element
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_element(PACKET *pkt, unsigned int *identifier,
    PACKET *contents);

/**
 * @brief Peek variant: reads the same as ossl_DER_r_element(), but
 * doesn't advance |pkt|.
 * @param pkt the packet to read from
 * @param identifier receives the identifier octet
 * @param contents receives a sub-PACKET holding the contents octets;
 * may be NULL to merely skip the element
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_peek_element(const PACKET *pkt, unsigned int *identifier,
    PACKET *contents);

/**
 * @brief Read an element that must match a given precompiled encoding
 * octet for octet.
 *
 * With DER_NO_CONTEXT as |tag|, the next |precompiled_n| octets of
 * |pkt| must match |precompiled| exactly; with a context tag number,
 * the contents of the constructed context specific element must match.
 *
 * @param pkt the packet to read from
 * @param tag the expected tag (see the conventions above)
 * @param precompiled the expected precompiled encoding
 * @param precompiled_n the length of |precompiled|
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_precompiled(PACKET *pkt, int tag,
    const unsigned char *precompiled,
    size_t precompiled_n);

/**
 * @brief Read a BOOLEAN element.
 * @param pkt the packet to read from
 * @param tag the expected tag (see the conventions above)
 * @param b receives the value, 0 or 1
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_boolean(PACKET *pkt, int tag, int *b);

/**
 * @brief Read an INTEGER element as a non-negative uint32_t value.
 * @param pkt the packet to read from
 * @param tag the expected tag (see the conventions above)
 * @param v receives the value
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_uint32(PACKET *pkt, int tag, uint32_t *v);

/**
 * @brief Read an INTEGER element as a BIGNUM.
 *
 * Like the writer, only non-negative integers are supported.
 *
 * @param pkt the packet to read from
 * @param tag the expected tag (see the conventions above)
 * @param v receives a freshly allocated BIGNUM, which the caller must
 * free with BN_free()
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_bn(PACKET *pkt, int tag, BIGNUM **v);

/**
 * @brief Read a NULL element.
 * @param pkt the packet to read from
 * @param tag the expected tag (see the conventions above)
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_null(PACKET *pkt, int tag);

/**
 * @brief Read an OCTET STRING element.
 * @param pkt the packet to read from
 * @param tag the expected tag (see the conventions above)
 * @param contents receives a sub-PACKET holding the string octets
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_octet_string(PACKET *pkt, int tag, PACKET *contents);

/**
 * @brief Read the beginning of a SEQUENCE, handing back its contents.
 *
 * There is no end function; the end is when the contents sub-PACKET has
 * been fully consumed (or abandoned).
 *
 * @param pkt the packet to read from
 * @param tag the expected tag (see the conventions above)
 * @param contents receives a sub-PACKET holding the sequence contents
 * @returns 1 on success, 0 on failure
 */
int ossl_DER_r_begin_sequence(PACKET *pkt, int tag, PACKET *contents);

#endif
