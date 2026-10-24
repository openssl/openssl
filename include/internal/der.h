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
 * The parsers are lenient in what they accept, as long as it's definite
 * length: non-minimal length encodings are accepted, while indefinite
 * lengths and the high-tag-number form (tag numbers larger than 30) are
 * rejected.  This matches what the writers produce, and tolerates the
 * BER-ish sloppiness that's common in the wild.
 */

/*
 * Lowest level reader: read one DER element from |pkt|.  On success,
 * |*identifier| receives the identifier octet (the DER class, the
 * constructed flag and the tag number), |*contents| is filled in with a
 * sub-PACKET holding the contents octets (it may be NULL to merely skip
 * the element), and |pkt| is advanced past the element.
 */
int ossl_DER_r_element(PACKET *pkt, unsigned int *identifier,
    PACKET *contents);

/*
 * Peek variant: reads the same as ossl_DER_r_element(), but doesn't
 * advance |pkt|
 */
int ossl_DER_r_peek_element(const PACKET *pkt, unsigned int *identifier,
    PACKET *contents);

int ossl_DER_r_precompiled(PACKET *pkt, int tag,
    const unsigned char *precompiled,
    size_t precompiled_n);
int ossl_DER_r_boolean(PACKET *pkt, int tag, int *b);
int ossl_DER_r_uint32(PACKET *pkt, int tag, uint32_t *v);

/*
 * On success, |*v| receives a freshly allocated BIGNUM, which the caller
 * must free with BN_free().  Like the writer, only non-negative integers
 * are supported.
 */
int ossl_DER_r_bn(PACKET *pkt, int tag, BIGNUM **v);
int ossl_DER_r_null(PACKET *pkt, int tag);
int ossl_DER_r_octet_string(PACKET *pkt, int tag, PACKET *contents);

/*
 * The constructed parser hands back the sequence contents in |contents|;
 * there is no end function, the end is when the contents sub-PACKET has
 * been fully consumed (or abandoned).
 */
int ossl_DER_r_begin_sequence(PACKET *pkt, int tag, PACKET *contents);

#endif
