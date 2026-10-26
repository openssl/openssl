/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file bytestring.h
 * Bytestrings are used for parsing and building TLS and ASN.1 messages.
 *
 * A "CBS" (CRYPTO ByteString) represents a string of bytes in memory and
 * provides utility functions for safely parsing length-prefixed structures
 * like TLS and ASN.1 from it. A CBS does not own the bytes it points to
 *
 * These functions are originally from BoringSSL, where they are public, and
 * they are internal in LibreSSL.
 *
 * As of yet, this does not include the CBB type which is also present
 * in BoringSSL and LibreSSL.
 */

#if !defined(OSSL_INTERNAL_BYTESTRING_H)
#define OSSL_INTERNAL_BYTESTRING_H

#include <stddef.h>
#include <stdint.h>

typedef struct cbs_st {
    const uint8_t *data; /**< The contents of the CBS */
    size_t initial_len; /**< The length of the original data */
    size_t len; /**< The number of bytes remaining in the CBS */
} CBS;

#define CBS_ASN1_UNIVERSAL 0x00u
#define CBS_ASN1_APPLICATION 0x40u
#define CBS_ASN1_CONTEXT_SPECIFIC 0x80u
#define CBS_ASN1_PRIVATE 0xc0u

#define CBS_ASN1_CONSTRUCTED 0x20u

#define CBS_ASN1_BOOLEAN 0x01u
#define CBS_ASN1_INTEGER 0x02u
#define CBS_ASN1_BITSTRING 0x03u
#define CBS_ASN1_OCTETSTRING 0x04u
#define CBS_ASN1_NULL 0x05u
#define CBS_ASN1_OBJECT 0x06u
#define CBS_ASN1_ENUMERATED 0x0au
#define CBS_ASN1_UTF8STRING 0x0cu
#define CBS_ASN1_SEQUENCE (0x10u | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_SET (0x11u | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_PRINTABLESTRING 0x13u
#define CBS_ASN1_IA5STRING 0x16u
#define CBS_ASN1_UTCTIME 0x17u
#define CBS_ASN1_GENERALIZEDTIME 0x18u

/**
 * @brief CBS_init sets cbs to point to data. It does not take ownership of
 * data.
 * @param cbs the CBS to initialise
 * @param data the data
 * @param len the length of data
 */
void CBS_init(CBS *cbs, const uint8_t *data, size_t len);

/**
 * @brief CBS_dup sets out to point to cbs's data and len. It results in two
 * CBS that point to the same buffer.
 * @param cbs the CBS to copy
 * @param out the CBS to set
 */
void CBS_dup(const CBS *cbs, CBS *out);

/**
 * @brief CBS_data returns a pointer to the contents of cbs.
 * @param cbs the CBS
 * @returns a pointer to the contents of cbs
 */
const uint8_t *CBS_data(const CBS *cbs);

/**
 * @brief CBS_len returns the number of bytes remaining in cbs.
 * @param cbs the CBS
 * @returns the number of bytes remaining in cbs
 */
size_t CBS_len(const CBS *cbs);

/**
 * @brief CBS_offset returns the current offset into the original data of cbs.
 * @param cbs the CBS
 * @returns the current offset into the original data
 */
size_t CBS_offset(const CBS *cbs);

/**
 * @brief CBS_stow copies the current contents of cbs into *out_ptr and
 * *out_len. If *out_ptr is not NULL, the contents are freed with
 * OPENSSL_free. On success, *out_ptr should be freed with OPENSSL_free. If
 * cbs is empty, *out_ptr will be NULL.
 * @param cbs the CBS
 * @param out_ptr the pointer to set
 * @param out_len the length to set
 * @returns one on success and zero on allocation failure
 */
int CBS_stow(const CBS *cbs, uint8_t **out_ptr, size_t *out_len);

/**
 * @brief CBS_skip advances cbs by len bytes.
 * @param cbs the CBS
 * @param len the number of bytes to advance
 * @returns one on success and zero otherwise
 */
int CBS_skip(CBS *cbs, size_t len);

/**
 * @brief CBS_mem_equal compares the current contents of cbs with the len bytes
 * starting at data. If the lengths match, it uses a constant-time
 * comparison.
 * @param cbs the CBS
 * @param data the bytes to compare with
 * @param len the length of data
 * @returns one if they're equal, otherwise zero
 */
int CBS_mem_equal(const CBS *cbs, const uint8_t *data, size_t len);

/**
 * @brief CBS_contains_zero_byte checks the current contents of cbs for a NUL
 * byte.
 * @param cbs the CBS
 * @returns one if cbs contains a NUL byte and zero otherwise
 */
int CBS_contains_zero_byte(const CBS *cbs);

/**
 * @brief CBS_get_u8 sets *out to the next uint8_t from cbs and advances cbs.
 * @param cbs the CBS
 * @param out the uint8_t to set
 * @returns one on success and zero on error
 */
int CBS_get_u8(CBS *cbs, uint8_t *out);

/**
 * @brief CBS_get_u16 sets *out to the next, big-endian uint16_t from cbs and
 * advances cbs.
 * @param cbs the CBS
 * @param out the uint16_t to set
 * @returns one on success and zero on error
 */
int CBS_get_u16(CBS *cbs, uint16_t *out);

/**
 * @brief CBS_get_u24 sets *out to the next, big-endian 24-bit value from cbs
 * and advances cbs.
 * @param cbs the CBS
 * @param out the uint32_t to set
 * @returns one on success and zero on error
 */
int CBS_get_u24(CBS *cbs, uint32_t *out);

/**
 * @brief CBS_get_u32 sets *out to the next, big-endian uint32_t value from cbs
 * and advances cbs.
 * @param cbs the CBS
 * @param out the uint32_t to set
 * @returns one on success and zero on error
 */
int CBS_get_u32(CBS *cbs, uint32_t *out);

/**
 * @brief CBS_get_u48 sets *out to the next, big-endian 48-bit value from cbs
 * and advances cbs.
 * @param cbs the CBS
 * @param out the uint64_t to set
 * @returns one on success and zero on error
 */
int CBS_get_u48(CBS *cbs, uint64_t *out);

/**
 * @brief CBS_get_u64 sets *out to the next, big-endian uint64_t value from cbs
 * and advances cbs.
 * @param cbs the CBS
 * @param out the uint64_t to set
 * @returns one on success and zero on error
 */
int CBS_get_u64(CBS *cbs, uint64_t *out);

/**
 * @brief CBS_peek_u8 sets *out to the next uint8_t from cbs, but does not
 * advance cbs.
 * @param cbs the CBS
 * @param out the uint8_t to set
 * @returns one on success and zero on error
 */
int CBS_peek_u8(const CBS *cbs, uint8_t *out);

/**
 * @brief CBS_get_bytes sets *out to the next len bytes from cbs and advances
 * cbs.
 * @param cbs the CBS
 * @param out the CBS to set
 * @param len the number of bytes
 * @returns one on success and zero on error
 */
int CBS_get_bytes(CBS *cbs, CBS *out, size_t len);

/**
 * @brief CBS_get_u8_length_prefixed sets *out to the contents of an 8-bit,
 * length-prefixed value from cbs and advances cbs over it.
 * @param cbs the CBS
 * @param out the CBS to set
 * @returns one on success and zero on error
 */
int CBS_get_u8_length_prefixed(CBS *cbs, CBS *out);

/**
 * @brief CBS_get_u16_length_prefixed sets *out to the contents of a 16-bit,
 * big-endian, length-prefixed value from cbs and advances cbs over it.
 * @param cbs the CBS
 * @param out the CBS to set
 * @returns one on success and zero on error
 */
int CBS_get_u16_length_prefixed(CBS *cbs, CBS *out);

/**
 * @brief CBS_get_u24_length_prefixed sets *out to the contents of a 24-bit,
 * big-endian, length-prefixed value from cbs and advances cbs over it.
 * @param cbs the CBS
 * @param out the CBS to set
 * @returns one on success and zero on error
 */
int CBS_get_u24_length_prefixed(CBS *cbs, CBS *out);

/**
 * @brief CBS_get_any_asn1_element sets *out to contain the next ASN.1 element
 * from *cbs (including header bytes) and advances *cbs. It sets *out_tag
 * to the tag number and *out_header_len to the length of the ASN.1
 * header. Each of out, out_tag, and out_header_len may be NULL to ignore
 * the value.
 *
 * Tag numbers greater than 30 are not supported (i.e. short form only).
 * @param cbs the CBS
 * @param out the CBS to set, or NULL
 * @param out_tag the tag to set, or NULL
 * @param out_header_len the header length to set, or NULL
 * @returns one on success and zero on error
 */
int CBS_get_any_asn1_element(CBS *cbs, CBS *out, unsigned int *out_tag,
    size_t *out_header_len);

/**
 * @brief CBS_get_asn1 sets *out to the contents of DER-encoded, ASN.1 element
 * (not including tag and length bytes) and advances cbs over it. The ASN.1
 * element must match tag.
 *
 * Tag numbers greater than 30 are not supported (i.e. short form only).
 * @param cbs the CBS
 * @param out the CBS to set
 * @param tag the tag the element must match
 * @returns one on success and zero on error
 */
int CBS_get_asn1(CBS *cbs, CBS *out, unsigned int tag);

/**
 * @brief CBS_get_asn1_element acts like CBS_get_asn1 but out will include the
 * ASN.1 header bytes too.
 * @param cbs the CBS
 * @param out the CBS to set
 * @param tag the tag the element must match
 * @returns one on success and zero on error
 */
int CBS_get_asn1_element(CBS *cbs, CBS *out, unsigned int tag);

/**
 * @brief CBS_peek_asn1_tag looks ahead at the next ASN.1 tag.
 * @param cbs the CBS
 * @param tag the tag to look for
 * @returns one if the next ASN.1 element on cbs would have tag tag, zero
 *          if cbs is empty or the tag does not match
 */
int CBS_peek_asn1_tag(const CBS *cbs, unsigned int tag);

/**
 * @brief CBS_get_optional_asn1 gets an optional explicitly-tagged element
 * from cbs tagged with tag and sets *out to its contents. If present, it
 * sets *out_present to one, otherwise zero.
 * @param cbs the CBS
 * @param out the CBS to set
 * @param out_present set to one if the element is present, otherwise zero
 * @param tag the tag of the element
 * @returns one on success, whether or not the element was present, and zero on
 *          decode failure
 */
int CBS_get_optional_asn1(CBS *cbs, CBS *out, int *out_present,
    unsigned int tag);

/**
 * @brief CBS_get_asn1_uint64 gets an ASN.1 INTEGER from cbs using CBS_get_asn1
 * and sets *out to its value.
 * @param cbs the CBS
 * @param out the uint64_t to set
 * @returns one on success and zero on error, where error includes the integer
 *          being negative, or too large to represent in 64 bits
 */
int CBS_get_asn1_uint64(CBS *cbs, uint64_t *out);

#endif /* !defined(OSSL_INTERNAL_BYTESTRING_H) */
