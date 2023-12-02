/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/params.h>
#include "endecoder_local.h"
#include "crypto/hss.h"
#include "prov/bio.h"
#include "prov/implementations.h"

static OSSL_FUNC_decoder_newctx_fn hssblob2key_newctx;
static OSSL_FUNC_decoder_freectx_fn hssblob2key_freectx;
static OSSL_FUNC_decoder_decode_fn hssblob2key_decode;
static OSSL_FUNC_decoder_export_object_fn hssblob2key_export_object;

/* Context used for blob to key decoding. */
struct hssblob2key_ctx_st {
    PROV_CTX *provctx;
    int selection; /* The selection that is passed to hssblob2key_decode() */
};

static void *hssblob2key_newctx(void *provctx)
{
    struct hssblob2key_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void hssblob2key_freectx(void *vctx)
{
    struct hssblob2key_ctx_st *ctx = vctx;

    OPENSSL_free(ctx);
}

static int hssblob2key_does_selection(void *provctx, int selection)
{
    if (selection == 0)
        return 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  != 0)
        return 1;

    return 0;
}

static int hssblob2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                              OSSL_CALLBACK *data_cb, void *data_cbarg,
                              OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct hssblob2key_ctx_st *ctx = vctx;
    HSS_KEY *key = NULL;
    unsigned char buf[HSS_MAX_PUBKEY];
    size_t length;
    int ok = 0;
    BIO *in;

    in = ossl_bio_new_from_core_bio(ctx->provctx, cin);
    if (in == NULL)
        return 0;

    ERR_set_mark();
    ctx->selection = selection;
    /* Read the header to determine the size */
    if (BIO_read(in, buf, 8) != 8)
        goto next;

    length = ossl_hss_pubkey_length(buf, 8);
    if (length == 0)
        goto next;
    if (BIO_read(in, buf + 8, length - 8) != (int)(length - 8))
        goto next;
    if (selection == 0 || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        key = ossl_hss_key_new(PROV_LIBCTX_OF(ctx->provctx), NULL);
        if (key == NULL || !ossl_hss_pub_key_decode(buf, length, key)) {
            ossl_hss_key_free(key);
            key = NULL;
        }
    }
 next:
    ERR_clear_last_mark();
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

static int hssblob2key_export_object(void *vctx,
                                     const void *reference, size_t reference_sz,
                                     OSSL_CALLBACK *export_cb,
                                     void *export_cbarg)
{
    struct hssblob2key_ctx_st *ctx = vctx;
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

const OSSL_DISPATCH ossl_hssblob_to_key_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))hssblob2key_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))hssblob2key_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))hssblob2key_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))hssblob2key_decode },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,
      (void (*)(void))hssblob2key_export_object },
    OSSL_DISPATCH_END
};
