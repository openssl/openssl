/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ui.h>
#include <openssl/decoder.h>
#include <openssl/safestack.h>
#include <openssl/trace.h>
#include "crypto/evp.h"
#include "crypto/decoder.h"
#include "encoder_local.h"
#include "e_os.h"                /* strcasecmp on Windows */

int OSSL_DECODER_set_passphrase(OSSL_DECODER *decoder,
                                const unsigned char *kstr, size_t klen)
{
    return ossl_pw_set_passphrase(&decoder->pwdata, kstr, klen);
}

int OSSL_DECODER_set_passphrase_ui(OSSL_DECODER *decoder,
                                   const UI_METHOD *ui_method, void *ui_data)
{
    return ossl_pw_set_ui_method(&decoder->pwdata, ui_method, ui_data);
}

int OSSL_DECODER_set_pem_password_cb(OSSL_DECODER *decoder,
                                     pem_password_cb *cb, void *cbarg)
{
    return ossl_pw_set_pem_password_cb(&decoder->pwdata, cb, cbarg);
}

int OSSL_DECODER_set_passphrase_cb(OSSL_DECODER *decoder,
                                   OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_pw_set_ossl_passphrase_cb(&decoder->pwdata, cb, cbarg);
}

/*
 * Support for OSSL_DECODER_new_by_EVP_PKEY:
 * The construct data, and collecting keymgmt information for it
 */

DEFINE_STACK_OF(EVP_KEYMGMT)

struct decoder_EVP_PKEY_data_st {
    OSSL_LIB_CTX *libctx;
    char *propq;

    char *object_type;           /* recorded object data type, may be NULL */
    void **object;               /* Where the result should end up */
};

static int decoder_construct_EVP_PKEY(OSSL_DECODER_INSTANCE *decoder_inst,
                                      const OSSL_PARAM *params,
                                      void *construct_data)
{
    struct decoder_EVP_PKEY_data_st *data = construct_data;
    OSSL_DECODER_METHOD *decoder_meth =
        OSSL_DECODER_INSTANCE_get_method(decoder_inst);
    void *decoderctx =
        OSSL_DECODER_INSTANCE_get_method_ctx(decoder_inst);
    EVP_KEYMGMT *keymgmt = NULL;
    /*
     * |object_ref| points to a provider reference to an object, its exact
     * contents entirely opaque to us, but may be passed to any provider
     * function that expects this (such as OSSL_FUNC_keymgmt_load().
     *
     * This pointer is considered volatile, i.e. whatever it points at
     * is assumed to be freed as soon as this function returns.
     */
    void *object_ref = NULL;
    size_t object_ref_sz = 0;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
    if (p != NULL) {
        char *object_type = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &object_type, 0))
            return 0;
        OPENSSL_free(data->object_type);
        data->object_type = object_type;
    }

    /*
     * For stuff that should end up in an EVP_PKEY, we only accept an object
     * reference for the moment.  This enforces that the key data itself
     * remains with the provider.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;
    object_ref = p->data;
    object_ref_sz = p->data_size;

    keymgmt = EVP_KEYMGMT_fetch(data->libctx, data->object_type, data->propq);

    if (keymgmt != NULL) {
        EVP_PKEY *pkey = NULL;
        void *keydata = NULL;
        const OSSL_PROVIDER *keymgmt_prov = EVP_KEYMGMT_provider(keymgmt);
        const OSSL_PROVIDER *decoder_prov =
            OSSL_DECODER_METHOD_provider(decoder_meth);

        /*
         * If the EVP_KEYMGMT and the OSSL_DECODER_METHOD are from the
         * same provider, we assume that the KEYMGMT has a key loading
         * function that can handle the provider reference we hold.
         *
         * Otherwise, we export from the decoder and import the
         * result in the keymgmt.
         */
        if (keymgmt_prov == decoder_prov) {
            keydata = evp_keymgmt_load(keymgmt, object_ref, object_ref_sz);
        } else {
            struct evp_keymgmt_util_try_import_data_st import_data;

            import_data.keymgmt = keymgmt;
            import_data.keydata = NULL;
            import_data.selection = OSSL_KEYMGMT_SELECT_ALL;

            /*
             * No need to check for errors here, the value of
             * |import_data.keydata| is as much an indicator.
             */
            (void)decoder_meth->export_object(decoderctx,
                                              object_ref, object_ref_sz,
                                              &evp_keymgmt_util_try_import,
                                              &import_data);
            keydata = import_data.keydata;
            import_data.keydata = NULL;
        }

        if (keydata != NULL
            && (pkey = evp_keymgmt_util_make_pkey(keymgmt, keydata)) == NULL)
            evp_keymgmt_freedata(keymgmt, keydata);

        *data->object = pkey;

        /*
         * evp_keymgmt_util_make_pkey() increments the reference count when
         * assigning the EVP_PKEY, so we can free the keymgmt here.
         */
        EVP_KEYMGMT_free(keymgmt);
    }
    /*
     * We successfully looked through, |*decoder->object| determines if we
     * actually found something.
     */
    return (*data->object != NULL);
}

static void decoder_clean_EVP_PKEY_construct_arg(void *construct_data)
{
    struct decoder_EVP_PKEY_data_st *data = construct_data;

    if (data != NULL) {
        OPENSSL_free(data->propq);
        OPENSSL_free(data->object_type);
        OPENSSL_free(data);
    }
}

static void collect_name(const char *name, void *arg)
{
    STACK_OF(OPENSSL_CSTRING) *names = arg;

    sk_OPENSSL_CSTRING_push(names, name);
}

static void collect_keymgmt(EVP_KEYMGMT *keymgmt, void *arg)
{
    STACK_OF(EVP_KEYMGMT) *keymgmts = arg;

    if (!EVP_KEYMGMT_up_ref(keymgmt) /* ref++ */)
        return;
    if (sk_EVP_KEYMGMT_push(keymgmts, keymgmt) <= 0) {
        EVP_KEYMGMT_free(keymgmt);   /* ref-- */
        return;
    }
}

/*
 * The input structure check is only done on the initial decoder
 * implementations.
 */
static int decoder_check_input_structure(OSSL_DECODER *decoder,
                                         OSSL_DECODER_INSTANCE *di)
{
    int di_is_was_set = 0;
    const char *di_is =
        OSSL_DECODER_INSTANCE_get_input_structure(di, &di_is_was_set);

    /*
     * If caller didn't give an input structure name, the decoder is accepted
     * unconditionally with regards to the input structure.
     */
    if (decoder->input_structure == NULL)
        return 1;
    /*
     * If the caller did give an input structure name, the decoder must have
     * a matching input structure to be accepted.
     */
    if (di_is != NULL && strcasecmp(decoder->input_structure, di_is) == 0)
        return 1;
    return 0;
}

struct collect_decoder_data_st {
    STACK_OF(OPENSSL_CSTRING) *names;
    OSSL_DECODER *decoder;

    unsigned int error_occured:1;
};

static void collect_decoder(OSSL_DECODER_METHOD *decoder_meth, void *arg)
{
    struct collect_decoder_data_st *data = arg;
    size_t i, end_i;
    const OSSL_PROVIDER *prov = OSSL_DECODER_METHOD_provider(decoder_meth);
    void *provctx = OSSL_PROVIDER_get0_provider_ctx(prov);

    if (data->error_occured)
        return;

    data->error_occured = 1;         /* Assume the worst */
    if (data->names == NULL)
        return;

    end_i = sk_OPENSSL_CSTRING_num(data->names);
    for (i = 0; i < end_i; i++) {
        const char *name = sk_OPENSSL_CSTRING_value(data->names, i);
        void *decoderctx = NULL;
        OSSL_DECODER_INSTANCE *di = NULL;

        if (OSSL_DECODER_METHOD_is_a(decoder_meth, name)
            /*
             * Either the caller didn't give a selection, or if they did,
             * the decoder must tell us if it supports that selection to
             * be accepted.  If the decoder doesn't have |does_selection|,
             * it's seen as taking anything.
             */
            && (decoder_meth->does_selection == NULL
                || decoder_meth->does_selection(provctx,
                                                data->decoder->selection))
            && (decoderctx = decoder_meth->newctx(provctx)) != NULL
            && (di = ossl_decoder_instance_new(decoder_meth,
                                               decoderctx)) != NULL) {
            /* If successful so far, don't free these directly */
            decoderctx = NULL;

            if (decoder_check_input_structure(data->decoder, di)
                && ossl_decoder_add_decoder_inst(data->decoder, di))
                di = NULL;      /* If successfully added, don't free it */
        }

        /* Free what can be freed */
        ossl_decoder_instance_free(di);
        decoder_meth->freectx(decoderctx);
    }

    data->error_occured = 0;         /* All is good now */
}

int ossl_decoder_setup_for_EVP_PKEY(OSSL_DECODER *decoder,
                                    EVP_PKEY **pkey, const char *keytype,
                                    OSSL_LIB_CTX *libctx, const char *propquery)
{
    struct decoder_EVP_PKEY_data_st *process_data = NULL;
    STACK_OF(EVP_KEYMGMT) *keymgmts = NULL;
    STACK_OF(OPENSSL_CSTRING) *names = NULL;
    int ok = 0;

    if ((process_data = OPENSSL_zalloc(sizeof(*process_data))) == NULL
        || (propquery != NULL
            && (process_data->propq = OPENSSL_strdup(propquery)) == NULL)
        || (keymgmts = sk_EVP_KEYMGMT_new_null()) == NULL
        || (names = sk_OPENSSL_CSTRING_new_null()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    process_data->object = (void **)pkey;
    process_data->libctx = libctx;

    /* First, find all keymgmts to form goals */
    EVP_KEYMGMT_do_all_provided(libctx, collect_keymgmt, keymgmts);

    /* Then, we collect all the keymgmt names */
    while (sk_EVP_KEYMGMT_num(keymgmts) > 0) {
        EVP_KEYMGMT *keymgmt = sk_EVP_KEYMGMT_shift(keymgmts);

        /*
         * If the key type is given by the caller, we only use the matching
         * KEYMGMTs, otherwise we use them all.
         */
        if (keytype == NULL || EVP_KEYMGMT_is_a(keymgmt, keytype))
            EVP_KEYMGMT_names_do_all(keymgmt, collect_name, names);

        EVP_KEYMGMT_free(keymgmt);
    }
    sk_EVP_KEYMGMT_free(keymgmts);

    /*
     * Finally, find all decoders that have any keymgmt of the collected
     * keymgmt names
     */
    {
        struct collect_decoder_data_st collect_decoder_data = { NULL, };

        collect_decoder_data.names = names;
        collect_decoder_data.decoder = decoder;
        OSSL_DECODER_METHOD_do_all_provided(libctx, collect_decoder,
                                            &collect_decoder_data);
        sk_OPENSSL_CSTRING_free(names);

        if (collect_decoder_data.error_occured)
            goto err;
    }

    if (OSSL_DECODER_get_num_methods(decoder) != 0) {
        if (!OSSL_DECODER_set_construct(decoder, decoder_construct_EVP_PKEY)
            || !OSSL_DECODER_set_construct_data(decoder, process_data)
            || !OSSL_DECODER_set_cleanup(decoder,
                                         decoder_clean_EVP_PKEY_construct_arg))
            goto err;

        process_data = NULL; /* Avoid it being freed */
    }

    ok = 1;
 err:
    decoder_clean_EVP_PKEY_construct_arg(process_data);
    return ok;
}

OSSL_DECODER *OSSL_DECODER_new_by_EVP_PKEY(EVP_PKEY **pkey,
                                           const char *input_type,
                                           const char *input_structure,
                                           const char *keytype, int selection,
                                           OSSL_LIB_CTX *libctx,
                                           const char *propquery)
{
    OSSL_DECODER *decoder = NULL;

    if ((decoder = OSSL_DECODER_new()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    OSSL_TRACE_BEGIN(DECODER) {
        BIO_printf(trc_out,
                   "(decoder %p) Looking for %s decoders with selection %d\n",
                   (void *)decoder, keytype, selection);
        BIO_printf(trc_out, "    input type: %s, input structure: %s\n",
                   input_type, input_structure);
    } OSSL_TRACE_END(DECODER);

    if (OSSL_DECODER_set_input_type(decoder, input_type)
        && OSSL_DECODER_set_input_structure(decoder, input_structure)
        && OSSL_DECODER_set_selection(decoder, selection)
        && ossl_decoder_setup_for_EVP_PKEY(decoder, pkey, keytype,
                                           libctx, propquery)
        && OSSL_DECODER_add_extra_methods(decoder, libctx, propquery)) {
        OSSL_TRACE_BEGIN(DECODER) {
            BIO_printf(trc_out, "(decoder %p) Got %d methods\n",
                       (void *)decoder, OSSL_DECODER_get_num_methods(decoder));
        } OSSL_TRACE_END(DECODER);
        return decoder;
    }

    OSSL_DECODER_free(decoder);
    return NULL;
}
