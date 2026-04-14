/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include "internal/encoder.h"
#include "internal/nelem.h"
#include "internal/packet.h"
#include "prov/hss_lms_codecs.h"

/*-
 * The DER ASN.1 encoding of HSS public keys prepends 20 bytes
 * to the encoded public key:
 *
 * - 2 byte outer sequence tag and length
 * -  2 byte algorithm sequence tag and length
 * -    2 byte algorithm OID tag and length
 * -      11 byte algorithm OID (from NIST CSOR OID arc)
 * -  2 byte bit string tag and length
 * -    1 bitstring lead byte
 *
 * The HSS public key consists of
 *  4 byte L (which is the number of levels ranging from 1..8). For LMS this is 1
 * Followed by a LMS public key of
 *  4 byte LMS type
 *  4 byte OTS type
 *  16 byte Id
 *  n bytes of K where n = 32 or 24.
 *  i.e. 24 + n bytes
 */

#define HSS_LMS_SPKI_OVERHEAD 20
#define HSS_LMS_HEADER(n) {                                           \
    0x30, 0x2E + n, 0x30, 0x0d,                                       \
    0x06, 0x0b,                                                       \
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x11, \
    0x03, 0x1D + n,                                                   \
    0x00                                                              \
}

typedef struct {
    const uint8_t header[HSS_LMS_SPKI_OVERHEAD];
} LMS_SPKI_FMT;

static const LMS_SPKI_FMT hss_lms_32_spkifmt = {
    HSS_LMS_HEADER(32)
};
static const LMS_SPKI_FMT hss_lms_24_spkifmt = {
    HSS_LMS_HEADER(24)
};

typedef struct {
    const LMS_SPKI_FMT *spkifmt;
} LMS_CODEC;

static const LMS_CODEC codecs[2] = {
    { &hss_lms_32_spkifmt },
    { &hss_lms_24_spkifmt }
};

static const LMS_SPKI_FMT *find_spkifmt(const uint8_t *pk, int pk_len)
{
    size_t i;

    if (pk_len <= HSS_LMS_SPKI_OVERHEAD)
        return NULL;

    for (i = 0; i < OSSL_NELEM(codecs); ++i) {
        if (memcmp(pk, codecs[i].spkifmt->header, HSS_LMS_SPKI_OVERHEAD) == 0)
            return codecs[i].spkifmt;
    }
    return NULL;
}

HSS_LMS_KEY *
ossl_hss_lms_d2i_PUBKEY(const uint8_t *pk, int pk_len, PROV_CTX *provctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    HSS_LMS_KEY *ret;
    const LMS_SPKI_FMT *spkifmt;

    spkifmt = find_spkifmt(pk, pk_len);
    if (spkifmt == NULL)
        return NULL;

    pk += sizeof(spkifmt->header);
    pk_len -= sizeof(spkifmt->header);

    if ((ret = ossl_hss_lms_key_new(libctx, NULL)) == NULL)
        return NULL;
    if (!ossl_hss_lms_pubkey_decode(NULL, pk, (size_t)pk_len, ret)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "error parsing LMS public key from input SPKI");
        ossl_hss_lms_key_free(ret);
        return NULL;
    }

    return ret;
}

int ossl_hss_lms_i2d_pubkey(const HSS_LMS_KEY *hss, unsigned char **out)
{
    const LMS_KEY *key = &hss->public;
    if (key->pub.encoded == NULL || key->pub.encodedlen == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
            "no LMS public key data available");
        return 0;
    }
    if (out != NULL) {
        WPACKET pkt;
        size_t sz = key->pub.encodedlen;
        uint8_t *buf = OPENSSL_malloc(sz);
        int ret;

        if (buf == NULL)
            return 0;
        ret = WPACKET_init_static_len(&pkt, buf, sz, 0)
            /* Output the HSS or LMS encoded public key */
            && WPACKET_memcpy(&pkt, key->pub.encoded, key->pub.encodedlen);
        WPACKET_cleanup(&pkt);
        if (ret == 0) {
            OPENSSL_free(buf);
            return 0;
        }
        *out = buf;
    }
    return (int)key->pub.encodedlen;
}

static const char *get_digest(const char *name)
{
    if (strcmp(name, "SHAKE-256") == 0)
        return "SHAKE";
    return strcmp(name, "SHA256-192") == 0 ? "SHA256" : name;
}

int ossl_hss_lms_key_to_text(BIO *out, const HSS_LMS_KEY *hss, int selection)
{
    const LMS_KEY *key;
    const LMS_PARAMS *lms_params;
    const LM_OTS_PARAMS *ots_params;

    if (out == NULL || hss == NULL || (key = &hss->public) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    lms_params = key->lms_params;
    ots_params = key->ots_params;

    if (key->pub.encoded == NULL || key->pub.encodedlen == 0) {
        /* Regardless of the |selection|, there must be a public key */
        ERR_raise_data(ERR_LIB_PROV, PROV_R_MISSING_KEY,
            "no LMS key material available");
        return 0;
    }
    if (hss->L > 1) {
        if (BIO_printf(out, "HSS Public-Key:\nLevels: %d\n", (int)hss->L) <= 0)
            return 0;
    }
    if (BIO_printf(out, "lms-type: %s-N%d-H%d (0x%x)\n",
            get_digest(lms_params->digestname),
            (int)lms_params->n, (int)lms_params->h, (int)lms_params->lms_type)
        <= 0)
        return 0;
    if (BIO_printf(out, "lm-ots-type: %s-N%d-W%d (0x%x)\n",
            get_digest(ots_params->digestname),
            (int)ots_params->n, (int)ots_params->w, (int)ots_params->lm_ots_type)
        <= 0)
        return 0;
    if (!ossl_bio_print_labeled_buf(out, "Id:", key->Id, 16))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* Private keys are not supported */
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (BIO_printf(out, "LMS Public-Key:\n") <= 0)
            return 0;
    }
    if (!ossl_bio_print_labeled_buf(out, "K:", key->pub.K, lms_params->n))
        return 0;
    return 1;
}
