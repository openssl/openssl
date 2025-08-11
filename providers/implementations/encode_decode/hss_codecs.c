/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include "endecoder_local.h"
#include "crypto/hss.h"
#include "prov/bio.h"
#include "prov/implementations.h"
#include "hss_codecs.h"
#include "internal/encoder.h"
#include "internal/nelem.h"

/*
 * The number of bytes in the header to read in order to determine the expected
 * length of the data. The LMS_TYPE determines the value of 'n'.
 */
#define HSS_HEADER_SIZE (HSS_SIZE_L + LMS_SIZE_LMS_TYPE)

static OSSL_FUNC_decoder_newctx_fn hssxdr2key_newctx;
static OSSL_FUNC_decoder_freectx_fn hssxdr2key_freectx;
static OSSL_FUNC_decoder_decode_fn hssxdr2key_decode;
static OSSL_FUNC_decoder_export_object_fn hssxdr2key_export_object;

/* Context used for xdr to key decoding. */
struct hssxdr2key_ctx_st {
    PROV_CTX *provctx;
    int selection; /* The selection that is passed to hssxdr2key_decode() */
};

static void *hssxdr2key_newctx(void *provctx)
{
    struct hssxdr2key_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void hssxdr2key_freectx(void *vctx)
{
    struct hssxdr2key_ctx_st *ctx = vctx;

    OPENSSL_free(ctx);
}

static int hssxdr2key_does_selection(void *provctx, int selection)
{
    if (selection == 0)
        return 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return 1;

    return 0;
}

static int hssxdr2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                             OSSL_CALLBACK *data_cb, void *data_cbarg,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct hssxdr2key_ctx_st *ctx = vctx;
    HSS_KEY *key = NULL;
    unsigned char buf[HSS_MAX_PUBKEY];
    size_t length;
    int ok = 0, readlen;
    BIO *in;

    in = ossl_bio_new_from_core_bio(ctx->provctx, cin);
    if (in == NULL)
        return 0;

    ctx->selection = selection;
    /* Read the header to determine the size */
    ERR_set_mark();
    readlen = BIO_read(in, buf, HSS_HEADER_SIZE);
    ERR_pop_to_mark();
    if (readlen != HSS_HEADER_SIZE)
        goto next;

    length = ossl_hss_pubkey_length(buf, HSS_HEADER_SIZE);
    if (length == 0)
        goto next;
    ERR_set_mark();
    readlen = BIO_read(in, buf + HSS_HEADER_SIZE, length - HSS_HEADER_SIZE);
    ERR_pop_to_mark();
    if (readlen != (int)(length - HSS_HEADER_SIZE))
        goto next;
    if (selection == 0 || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        key = ossl_hss_key_new(PROV_LIBCTX_OF(ctx->provctx), NULL);
        if (key == NULL || !ossl_hss_pubkey_decode(buf, length, key, 0)) {
            ossl_hss_key_free(key);
            key = NULL;
        }
    }
 next:
    /*
     * Indicated that we successfully decoded something, or not at all.
     * Ending up "empty handed" is not an error.
     */
    ok = 1;

    /*
     * We free resources here so it's not held up during the callback, because
     * we know the process is recursive and the allocated chunks of memory
     * add up.
     */
    BIO_free(in);
    in = NULL;
    if (key != NULL) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;

        params[0] =
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             (char *)"HSS", 0);
        /* The address of the key becomes the octet string */
        params[2] =
            OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }

    BIO_free(in);
    ossl_hss_key_free(key);
    return ok;
}

static int hssxdr2key_export_object(void *vctx,
                                    const void *reference, size_t reference_sz,
                                    OSSL_CALLBACK *export_cb,
                                    void *export_cbarg)
{
    struct hssxdr2key_ctx_st *ctx = vctx;
    OSSL_FUNC_keymgmt_export_fn *export =
        ossl_prov_get_keymgmt_export(ossl_hss_keymgmt_functions);
    void *keydata;

    if (reference_sz == sizeof(keydata) && export != NULL) {
        int selection = ctx->selection;

        if (selection == 0)
            selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        /* The contents of the reference is the address to our object */
        keydata = *(void **)reference;

        return export(keydata, selection, export_cb, export_cbarg);
    }
    return 0;
}

const OSSL_DISPATCH ossl_xdr_to_hss_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))hssxdr2key_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))hssxdr2key_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))hssxdr2key_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))hssxdr2key_decode },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,
      (void (*)(void))hssxdr2key_export_object },
    OSSL_DISPATCH_END
};

/***************************************************************/

/*-
 * The DER ASN.1 encoding of HSS public keys has 20 leading bytes
 * before the encoded public key consisting of:
 *
 * - 2 byte outer sequence tag and length
 * -  2 byte algorithm sequence tag and length
 * -    2 byte algorithm OID tag and length
 * -      11 byte algorithm OID
 * -  2 byte bit string tag and length
 * -    1 bitstring lead byte of 00
 */
#  define HSS_SPKI_OVERHEAD   20
typedef struct {
   const uint8_t asn1_prefix[HSS_SPKI_OVERHEAD];
} HSS_SPKI_FMT;

typedef struct {
    int len;
    size_t n;
    const HSS_SPKI_FMT *spkifmt;
} HSS_CODEC;

static const HSS_SPKI_FMT hss_n32_spkifmt = {
    { 0x30, 0x4e, 0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86,
      0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03,
      0x11, 0x03, 0x3D, 0x00 }
};
static const HSS_SPKI_FMT hss_n24_spkifmt = {
    { 0x30, 0x46, 0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86,
      0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03,
      0x11, 0x03, 0x35, 0x00 }
};

static HSS_CODEC codecs[2] = {
    { HSS_MIN_PUBKEY, 24, &hss_n24_spkifmt },
    { HSS_MAX_PUBKEY, 32, &hss_n32_spkifmt }
};

HSS_KEY *
ossl_hss_d2i_PUBKEY(const uint8_t *pk, int pk_len, int evp_type,
                    PROV_CTX *provctx, const char *propq)
{
    int i;

    for (i = OSSL_NELEM(codecs) - 1; i >= 0; --i) {
        if ((codecs[i].len + HSS_SPKI_OVERHEAD) == pk_len
                && memcmp(codecs[i].spkifmt->asn1_prefix, pk, HSS_SPKI_OVERHEAD) == 0) {
            HSS_KEY *ret = NULL;
            OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);

            if ((ret = ossl_hss_key_new(libctx, propq)) == NULL)
                return NULL;

            pk += HSS_SPKI_OVERHEAD;
            pk_len -= HSS_SPKI_OVERHEAD;
            if (!ossl_hss_pubkey_decode(pk, (size_t)pk_len, ret, 0)) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
                               "error parsing %s public key from input SPKI",
                               "HSS");
                ossl_hss_key_free(ret);
                return NULL;
            }
            return ret;
        }
    }
    return NULL;
}

int ossl_hss_i2d_pubkey(const HSS_KEY *key, unsigned char **out)
{
    const LMS_KEY *lms = ossl_hss_key_get_public(key);
    size_t len;

    if (lms == NULL || lms->pub.encoded == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
                       "no %s public key data available", "HSS");
        return 0;
    }
    len = ossl_hss_pubkey_encode(key, out);
    return len;
}

static int lms_key_to_text(BIO *out, const LMS_KEY *key, int selection)
{
    if (BIO_printf(out, "LMS Type: %s\n", key->lms_params->desc) <= 0)
        return 0;
    if (BIO_printf(out, "LMOTS Type: %s\n", key->ots_params->desc) <= 0)
        return 0;
    if (key->Id != NULL
            && !ossl_bio_print_labeled_buf(out, "I:", key->Id, LMS_SIZE_I))
        return 0;
    if (key->pub.K != NULL
            && !ossl_bio_print_labeled_buf(out, "K:", key->pub.K,
                                           key->lms_params->n))
        return 0;
    return 1;
}

int ossl_hss_key_to_text(BIO *out, const HSS_KEY *key, int selection)
{
    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_MISSING_KEY,
                       "no %s key material available", "HSS");
            return 0;
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        LMS_KEY *lms = ossl_hss_key_get_public(key);

        if (lms == NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_MISSING_KEY,
                           "no HSS key material available");
            return 0;
        }
        if (BIO_printf(out, "HSS Public-Key:\n") <= 0)
            return 0;
        if (!BIO_printf(out, "Levels: %lu\n", (unsigned long)key->L))
            return 0;
        if (!lms_key_to_text(out, lms, selection))
            return 0;
    }
    return 1;
}
