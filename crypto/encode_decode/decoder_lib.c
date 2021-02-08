/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/evperr.h>
#include <openssl/ecerr.h>
#include <openssl/x509err.h>
#include <openssl/trace.h>
#include "internal/passphrase.h"
#include "crypto/decoder.h"
#include "encoder_local.h"
#include "e_os.h"

struct decoder_process_data_st {
    OSSL_DECODER_CTX *ctx;

    /* Current BIO */
    BIO *bio;

    /* Index of the current decoder instance to be processed */
    size_t current_decoder_inst_index;
};

static int decoder_process(const OSSL_PARAM params[], void *arg);

int OSSL_DECODER_from_bio(OSSL_DECODER_CTX *ctx, BIO *in)
{
    struct decoder_process_data_st data;
    int ok = 0;

    memset(&data, 0, sizeof(data));
    data.ctx = ctx;
    data.bio = in;

    /* Enable passphrase caching */
    (void)ossl_pw_enable_passphrase_caching(&ctx->pwdata);

    ok = decoder_process(NULL, &data);

    /* Clear any internally cached passphrase */
    (void)ossl_pw_clear_passphrase_cache(&ctx->pwdata);

    return ok;
}

#ifndef OPENSSL_NO_STDIO
static BIO *bio_from_file(FILE *fp)
{
    BIO *b;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_BIO_LIB);
        return NULL;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    return b;
}

int OSSL_DECODER_from_fp(OSSL_DECODER_CTX *ctx, FILE *fp)
{
    BIO *b = bio_from_file(fp);
    int ret = 0;

    if (b != NULL)
        ret = OSSL_DECODER_from_bio(ctx, b);

    BIO_free(b);
    return ret;
}
#endif

int OSSL_DECODER_from_data(OSSL_DECODER_CTX *ctx, const unsigned char **pdata,
                           size_t *pdata_len)
{
    BIO *membio;
    int ret = 0;

    if (pdata == NULL || *pdata == NULL || pdata_len == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    membio = BIO_new_mem_buf(*pdata, (int)*pdata_len);
    if (OSSL_DECODER_from_bio(ctx, membio)) {
        *pdata_len = (size_t)BIO_get_mem_data(membio, pdata);
        ret = 1;
    }
    BIO_free(membio);

    return ret;
}

int OSSL_DECODER_CTX_set_selection(OSSL_DECODER_CTX *ctx, int selection)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * 0 is a valid selection, and means that the caller leaves
     * it to code to discover what the selection is.
     */
    ctx->selection = selection;
    return 1;
}

int OSSL_DECODER_CTX_set_input_type(OSSL_DECODER_CTX *ctx,
                                    const char *input_type)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * NULL is a valid starting input type, and means that the caller leaves
     * it to code to discover what the starting input type is.
     */
    ctx->start_input_type = input_type;
    return 1;
}

int OSSL_DECODER_CTX_set_input_structure(OSSL_DECODER_CTX *ctx,
                                         const char *input_structure)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * NULL is a valid starting input type, and means that the caller leaves
     * it to code to discover what the starting input type is.
     */
    ctx->input_structure = input_structure;
    return 1;
}

OSSL_DECODER_INSTANCE *ossl_decoder_instance_new(OSSL_DECODER *decoder,
                                                 void *decoderctx)
{
    OSSL_DECODER_INSTANCE *decoder_inst = NULL;
    OSSL_PARAM params[3];

    if (!ossl_assert(decoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (decoder->get_params == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER,
                  OSSL_DECODER_R_MISSING_GET_PARAMS);
        return 0;
    }

    if ((decoder_inst = OPENSSL_zalloc(sizeof(*decoder_inst))) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!OSSL_DECODER_up_ref(decoder)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Cache the input type for this decoder */
    params[0] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_DECODER_PARAM_INPUT_TYPE,
                                      (char **)&decoder_inst->input_type, 0);
    params[1] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_DECODER_PARAM_INPUT_STRUCTURE,
                                      (char **)&decoder_inst->input_structure,
                                      0);
    params[2] = OSSL_PARAM_construct_end();

    if (!decoder->get_params(params)
        || !OSSL_PARAM_modified(&params[0]))
        goto err;

    decoder_inst->flag_input_structure_was_set =
        OSSL_PARAM_modified(&params[1]);
    decoder_inst->decoder = decoder;
    decoder_inst->decoderctx = decoderctx;
    return decoder_inst;
 err:
    ossl_decoder_instance_free(decoder_inst);
    return NULL;
}

void ossl_decoder_instance_free(OSSL_DECODER_INSTANCE *decoder_inst)
{
    if (decoder_inst != NULL) {
        if (decoder_inst->decoder != NULL)
            decoder_inst->decoder->freectx(decoder_inst->decoderctx);
        decoder_inst->decoderctx = NULL;
        OSSL_DECODER_free(decoder_inst->decoder);
        decoder_inst->decoder = NULL;
        OPENSSL_free(decoder_inst);
    }
}

int ossl_decoder_ctx_add_decoder_inst(OSSL_DECODER_CTX *ctx,
                                      OSSL_DECODER_INSTANCE *di)
{
    int ok;

    if (ctx->decoder_insts == NULL
        && (ctx->decoder_insts =
            sk_OSSL_DECODER_INSTANCE_new_null()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ok = (sk_OSSL_DECODER_INSTANCE_push(ctx->decoder_insts, di) > 0);
    if (ok) {
        OSSL_TRACE_BEGIN(DECODER) {
            BIO_printf(trc_out,
                       "(ctx %p) Added decoder instance %p (decoder %p) with:\n",
                       (void *)ctx, (void *)di, (void *)di->decoder);
            BIO_printf(trc_out,
                       "    input type: %s, input structure: %s\n",
                       di->input_type, di->input_structure);
        } OSSL_TRACE_END(DECODER);
    }
    return ok;
}

int OSSL_DECODER_CTX_add_decoder(OSSL_DECODER_CTX *ctx, OSSL_DECODER *decoder)
{
    OSSL_DECODER_INSTANCE *decoder_inst = NULL;
    const OSSL_PROVIDER *prov = NULL;
    void *decoderctx = NULL;
    void *provctx = NULL;

    if (!ossl_assert(ctx != NULL) || !ossl_assert(decoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    prov = OSSL_DECODER_provider(decoder);
    provctx = OSSL_PROVIDER_get0_provider_ctx(prov);

    if ((decoderctx = decoder->newctx(provctx)) == NULL
        || (decoder_inst =
            ossl_decoder_instance_new(decoder, decoderctx)) == NULL)
        goto err;
    /* Avoid double free of decoderctx on further errors */
    decoderctx = NULL;

    if (!ossl_decoder_ctx_add_decoder_inst(ctx, decoder_inst))
        goto err;

    return 1;
 err:
    ossl_decoder_instance_free(decoder_inst);
    if (decoderctx != NULL)
        decoder->freectx(decoderctx);
    return 0;
}

int OSSL_DECODER_CTX_add_extra(OSSL_DECODER_CTX *ctx,
                               OSSL_LIB_CTX *libctx, const char *propq)
{
    /*
     * This function goes through existing decoder methods in
     * |ctx->decoder_insts|, and tries to fetch new decoders that produce
     * what the existing ones want as input, and push those newly fetched
     * decoders on top of the same stack.
     * Then it does the same again, but looping over the newly fetched
     * decoders, until there are no more decoders to be fetched, or
     * when we have done this 10 times.
     *
     * we do this with sliding windows on the stack by keeping track of indexes
     * and of the end.
     *
     * +----------------+
     * |   DER to RSA   | <--- w_prev_start
     * +----------------+
     * |   DER to DSA   |
     * +----------------+
     * |   DER to DH    |
     * +----------------+
     * |   PEM to DER   | <--- w_prev_end, w_new_start
     * +----------------+
     *                    <--- w_new_end
     */
    size_t w_prev_start, w_prev_end; /* "previous" decoders */
    size_t w_new_start, w_new_end;   /* "new" decoders */
    size_t count = 0; /* Calculates how many were added in each iteration */
    size_t depth = 0; /* Counts the number of iterations */

    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * If there is no stack of OSSL_DECODER_INSTANCE, we have nothing
     * more to add.  That's fine.
     */
    if (ctx->decoder_insts == NULL)
        return 1;

    w_prev_start = 0;
    w_prev_end = sk_OSSL_DECODER_INSTANCE_num(ctx->decoder_insts);
    do {
        size_t i;

        w_new_start = w_new_end = w_prev_end;

        for (i = w_prev_start; i < w_prev_end; i++) {
            OSSL_DECODER_INSTANCE *decoder_inst =
                sk_OSSL_DECODER_INSTANCE_value(ctx->decoder_insts, i);
            const char *input_type =
                OSSL_DECODER_INSTANCE_get_input_type(decoder_inst);
            OSSL_DECODER *decoder = NULL;

            /*
             * If the caller has specified what the initial input should be,
             * and the decoder implementation we're looking at has that
             * input type, there's no point adding on more implementations
             * on top of this one, so we don't.
             */
            if (ctx->start_input_type != NULL
                && strcasecmp(ctx->start_input_type, input_type) == 0)
                continue;

            ERR_set_mark();
            decoder = OSSL_DECODER_fetch(libctx, input_type, propq);
            ERR_pop_to_mark();

            if (decoder != NULL) {
                size_t j;

                /*
                 * Check that we don't already have this decoder in our
                 * stack We only need to check among the newly added ones.
                 */
                for (j = w_new_start; j < w_new_end; j++) {
                    OSSL_DECODER_INSTANCE *check_inst =
                        sk_OSSL_DECODER_INSTANCE_value(ctx->decoder_insts, j);

                    if (decoder == check_inst->decoder) {
                        /* We found it, so drop the new fetch */
                        OSSL_DECODER_free(decoder);
                        decoder = NULL;
                        break;
                    }
                }
            }

            if (decoder == NULL)
                continue;

            /*
             * Apart from keeping w_new_end up to date, We don't care about
             * errors here.  If it doesn't collect, then it doesn't...
             */
            if (OSSL_DECODER_CTX_add_decoder(ctx, decoder)) /* ref++ */
                w_new_end++;
            OSSL_DECODER_free(decoder); /* ref-- */
        }
        /* How many were added in this iteration */
        count = w_new_end - w_new_start;

        /* Slide the "previous decoder" windows */
        w_prev_start = w_new_start;
        w_prev_end = w_new_end;

        depth++;
    } while (count != 0 && depth <= 10);

    return 1;
}

int OSSL_DECODER_CTX_get_num_decoders(OSSL_DECODER_CTX *ctx)
{
    if (ctx == NULL || ctx->decoder_insts == NULL)
        return 0;
    return sk_OSSL_DECODER_INSTANCE_num(ctx->decoder_insts);
}

int OSSL_DECODER_CTX_set_construct(OSSL_DECODER_CTX *ctx,
                                   OSSL_DECODER_CONSTRUCT *construct)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx->construct = construct;
    return 1;
}

int OSSL_DECODER_CTX_set_construct_data(OSSL_DECODER_CTX *ctx,
                                        void *construct_data)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx->construct_data = construct_data;
    return 1;
}

int OSSL_DECODER_CTX_set_cleanup(OSSL_DECODER_CTX *ctx,
                                 OSSL_DECODER_CLEANUP *cleanup)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx->cleanup = cleanup;
    return 1;
}

OSSL_DECODER_CONSTRUCT *
OSSL_DECODER_CTX_get_construct(OSSL_DECODER_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->construct;
}

void *OSSL_DECODER_CTX_get_construct_data(OSSL_DECODER_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->construct_data;
}

OSSL_DECODER_CLEANUP *
OSSL_DECODER_CTX_get_cleanup(OSSL_DECODER_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->cleanup;
}

int OSSL_DECODER_export(OSSL_DECODER_INSTANCE *decoder_inst,
                        void *reference, size_t reference_sz,
                        OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    OSSL_DECODER *decoder = NULL;
    void *decoderctx = NULL;

    if (!(ossl_assert(decoder_inst != NULL)
          && ossl_assert(reference != NULL)
          && ossl_assert(export_cb != NULL)
          && ossl_assert(export_cbarg != NULL))) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    decoder = OSSL_DECODER_INSTANCE_get_decoder(decoder_inst);
    decoderctx = OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst);
    return decoder->export_object(decoderctx, reference, reference_sz,
                                  export_cb, export_cbarg);
}

OSSL_DECODER *
OSSL_DECODER_INSTANCE_get_decoder(OSSL_DECODER_INSTANCE *decoder_inst)
{
    if (decoder_inst == NULL)
        return NULL;
    return decoder_inst->decoder;
}

void *
OSSL_DECODER_INSTANCE_get_decoder_ctx(OSSL_DECODER_INSTANCE *decoder_inst)
{
    if (decoder_inst == NULL)
        return NULL;
    return decoder_inst->decoderctx;
}

const char *
OSSL_DECODER_INSTANCE_get_input_type(OSSL_DECODER_INSTANCE *decoder_inst)
{
    if (decoder_inst == NULL)
        return NULL;
    return decoder_inst->input_type;
}

const char *
OSSL_DECODER_INSTANCE_get_input_structure(OSSL_DECODER_INSTANCE *decoder_inst,
                                          int *was_set)
{
    if (decoder_inst == NULL)
        return NULL;
    *was_set = decoder_inst->flag_input_structure_was_set;
    return decoder_inst->input_structure;
}

static int decoder_process(const OSSL_PARAM params[], void *arg)
{
    struct decoder_process_data_st *data = arg;
    OSSL_DECODER_CTX *ctx = data->ctx;
    OSSL_DECODER_INSTANCE *decoder_inst = NULL;
    OSSL_DECODER *decoder = NULL;
    BIO *bio = data->bio;
    long loc;
    size_t i;
    int err, ok = 0;
    /* For recursions */
    struct decoder_process_data_st new_data;
    const char *object_type = NULL;

    memset(&new_data, 0, sizeof(new_data));
    new_data.ctx = data->ctx;

    if (params == NULL) {
        /* First iteration, where we prepare for what is to come */

        data->current_decoder_inst_index =
            OSSL_DECODER_CTX_get_num_decoders(ctx);

        bio = data->bio;
    } else {
        const OSSL_PARAM *p;

        decoder_inst =
            sk_OSSL_DECODER_INSTANCE_value(ctx->decoder_insts,
                                           data->current_decoder_inst_index);
        decoder = OSSL_DECODER_INSTANCE_get_decoder(decoder_inst);

        if (ctx->construct != NULL
            && ctx->construct(decoder_inst, params, ctx->construct_data)) {
            ok = 1;
            goto end;
        }

        /* The constructor didn't return success */

        /*
         * so we try to use the object we got and feed it to any next
         * decoder that will take it.  Object references are not
         * allowed for this.
         * If this data isn't present, decoding has failed.
         */

        p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA);
        if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            goto end;
        new_data.bio = BIO_new_mem_buf(p->data, (int)p->data_size);
        if (new_data.bio == NULL)
            goto end;
        bio = new_data.bio;

        /* Get the object type if there is one */
        p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
        if (p != NULL && !OSSL_PARAM_get_utf8_string_ptr(p, &object_type))
            goto end;
    }

    /*
     * If we have no more decoders to look through at this point,
     * we failed
     */
    if (data->current_decoder_inst_index == 0)
        goto end;

    if ((loc = BIO_tell(bio)) < 0) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_BIO_LIB);
        goto end;
    }

    for (i = data->current_decoder_inst_index; i-- > 0;) {
        OSSL_DECODER_INSTANCE *new_decoder_inst =
            sk_OSSL_DECODER_INSTANCE_value(ctx->decoder_insts, i);
        OSSL_DECODER *new_decoder =
            OSSL_DECODER_INSTANCE_get_decoder(new_decoder_inst);
        void *new_decoderctx =
            OSSL_DECODER_INSTANCE_get_decoder_ctx(new_decoder_inst);
        const char *new_input_type =
            OSSL_DECODER_INSTANCE_get_input_type(new_decoder_inst);

        /*
         * If |decoder| is NULL, it means we've just started, and the caller
         * may have specified what it expects the initial input to be.  If
         * that's the case, we do this extra check.
         */
        if (decoder == NULL && ctx->start_input_type != NULL
            && strcasecmp(ctx->start_input_type, new_input_type) != 0)
            continue;

        /*
         * If we have a previous decoder, we check that the input type
         * of the next to be used matches the type of this previous one.
         * input_type is a cache of the parameter "input-type" value for
         * that decoder.
         */
        if (decoder != NULL && !OSSL_DECODER_is_a(decoder, new_input_type))
            continue;

        /*
         * If the previous decoder gave us an object type, we check to see
         * if that matches the decoder we're currently considering.
         */
        if (object_type != NULL && !OSSL_DECODER_is_a(new_decoder, object_type))
            continue;

        /*
         * Checking the return value of BIO_reset() or BIO_seek() is unsafe.
         * Furthermore, BIO_reset() is unsafe to use if the source BIO happens
         * to be a BIO_s_mem(), because the earlier BIO_tell() gives us zero
         * no matter where we are in the underlying buffer we're reading from.
         *
         * So, we simply do a BIO_seek(), and use BIO_tell() that we're back
         * at the same position.  This is a best effort attempt, but BIO_seek()
         * and BIO_tell() should come as a pair...
         */
        (void)BIO_seek(bio, loc);
        if (BIO_tell(bio) != loc)
            goto end;

        /* Recurse */
        new_data.current_decoder_inst_index = i;
        ok = new_decoder->decode(new_decoderctx, (OSSL_CORE_BIO *)bio,
                                 new_data.ctx->selection,
                                 decoder_process, &new_data,
                                 ossl_pw_passphrase_callback_dec,
                                 &new_data.ctx->pwdata);

        OSSL_TRACE_BEGIN(DECODER) {
            BIO_printf(trc_out,
                       "(ctx %p) Running decoder instance %p => %d\n",
                       (void *)new_data.ctx, (void *)new_decoder_inst, ok);
        } OSSL_TRACE_END(DECODER);

        if (ok)
            break;
        err = ERR_peek_last_error();
        if ((ERR_GET_LIB(err) == ERR_LIB_EVP
             && ERR_GET_REASON(err) == EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM)
#ifndef OPENSSL_NO_EC
            || (ERR_GET_LIB(err) == ERR_LIB_EC
                && ERR_GET_REASON(err) == EC_R_UNKNOWN_GROUP)
#endif
            || (ERR_GET_LIB(err) == ERR_LIB_X509
                && ERR_GET_REASON(err) == X509_R_UNSUPPORTED_ALGORITHM))
            break; /* fatal error; preserve it on the error queue and stop */
    }

 end:
    BIO_free(new_data.bio);
    return ok;
}
