/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"                /* strcasecmp on Windows */
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/encoder.h>
#include <openssl/buffer.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include "encoder_local.h"

static int encoder_process(OSSL_ENCODER_CTX *ctx, BIO *out);

int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out)
{
    return encoder_process(ctx, out);
}

#ifndef OPENSSL_NO_STDIO
static BIO *bio_from_file(FILE *fp)
{
    BIO *b;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_BUF_LIB);
        return NULL;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    return b;
}

int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp)
{
    BIO *b = bio_from_file(fp);
    int ret = 0;

    if (b != NULL)
        ret = OSSL_ENCODER_to_bio(ctx, b);

    BIO_free(b);
    return ret;
}
#endif

int OSSL_ENCODER_to_data(OSSL_ENCODER_CTX *ctx, unsigned char **pdata,
                         size_t *pdata_len)
{
    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *buf = NULL;
    int ret = 0;

    if (pdata_len == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (OSSL_ENCODER_to_bio(ctx, out)
        && BIO_get_mem_ptr(out, &buf) > 0) {
        ret = 1; /* Hope for the best. A too small buffer will clear this */

        if (pdata != NULL && *pdata != NULL) {
            if (*pdata_len < buf->length)
                /*
                 * It's tempting to do |*pdata_len = (size_t)buf->length|
                 * However, it's believed to be confusing more than helpful,
                 * so we don't.
                 */
                ret = 0;
            else
                *pdata_len -= buf->length;
        } else {
            /* The buffer with the right size is already allocated for us */
            *pdata_len = (size_t)buf->length;
        }

        if (ret) {
            if (pdata != NULL) {
                if (*pdata != NULL) {
                    memcpy(*pdata, buf->data, buf->length);
                    *pdata += buf->length;
                } else {
                    /* In this case, we steal the data from BIO_s_mem() */
                    *pdata = (unsigned char *)buf->data;
                    buf->data = NULL;
                }
            }
        }
    }
    BIO_free(out);
    return ret;
}

int OSSL_ENCODER_CTX_set_output_type(OSSL_ENCODER_CTX *ctx,
                                     const char *output_type)
{
    if (!ossl_assert(ctx != NULL) || !ossl_assert(output_type != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx->output_type = output_type;
    return 1;
}

int OSSL_ENCODER_CTX_set_selection(OSSL_ENCODER_CTX *ctx, int selection)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!ossl_assert(selection != 0)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ctx->selection = selection;
    return 1;
}

static OSSL_ENCODER_INSTANCE *ossl_encoder_instance_new(OSSL_ENCODER *encoder,
                                                        void *encoderctx)
{
    OSSL_ENCODER_INSTANCE *encoder_inst = NULL;
    OSSL_PARAM params[3];

    if (!ossl_assert(encoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (encoder->get_params == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER,
                  OSSL_ENCODER_R_MISSING_GET_PARAMS);
        return 0;
    }

    if ((encoder_inst = OPENSSL_zalloc(sizeof(*encoder_inst))) == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * Cache the input and output types for this encoder.  The output type
     * is mandatory.
     */
    params[0] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_ENCODER_PARAM_OUTPUT_TYPE,
                                      (char **)&encoder_inst->output_type, 0);
    params[1] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_ENCODER_PARAM_INPUT_TYPE,
                                      (char **)&encoder_inst->input_type, 0);
    params[2] = OSSL_PARAM_construct_end();

    if (!encoder->get_params(params)
        || !OSSL_PARAM_modified(&params[1]))
        goto err;

    if (!OSSL_ENCODER_up_ref(encoder)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    encoder_inst->encoder = encoder;
    encoder_inst->encoderctx = encoderctx;
    return encoder_inst;
 err:
    ossl_encoder_instance_free(encoder_inst);
    return NULL;
}

void ossl_encoder_instance_free(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst != NULL) {
        if (encoder_inst->encoder != NULL)
            encoder_inst->encoder->freectx(encoder_inst->encoderctx);
        encoder_inst->encoderctx = NULL;
        OSSL_ENCODER_free(encoder_inst->encoder);
        encoder_inst->encoder = NULL;
        OPENSSL_free(encoder_inst);
    }
}

static int ossl_encoder_ctx_add_encoder_inst(OSSL_ENCODER_CTX *ctx,
                                             OSSL_ENCODER_INSTANCE *ei)
{
    if (ctx->encoder_insts == NULL
        && (ctx->encoder_insts =
            sk_OSSL_ENCODER_INSTANCE_new_null()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return (sk_OSSL_ENCODER_INSTANCE_push(ctx->encoder_insts, ei) > 0);
}

int OSSL_ENCODER_CTX_add_encoder(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER *encoder)
{
    OSSL_ENCODER_INSTANCE *encoder_inst = NULL;
    const OSSL_PROVIDER *prov = NULL;
    void *encoderctx = NULL;
    void *provctx = NULL;

    if (!ossl_assert(ctx != NULL) || !ossl_assert(encoder != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    prov = OSSL_ENCODER_provider(encoder);
    provctx = OSSL_PROVIDER_get0_provider_ctx(prov);

    if ((encoderctx = encoder->newctx(provctx)) == NULL
        || (encoder_inst =
            ossl_encoder_instance_new(encoder, encoderctx)) == NULL)
        goto err;
    /* Avoid double free of encoderctx on further errors */
    encoderctx = NULL;

    if (!ossl_encoder_ctx_add_encoder_inst(ctx, encoder_inst))
        goto err;

    return 1;
 err:
    ossl_encoder_instance_free(encoder_inst);
    if (encoderctx != NULL)
        encoder->freectx(encoderctx);
    return 0;
}

int OSSL_ENCODER_CTX_add_extra(OSSL_ENCODER_CTX *ctx,
                               OPENSSL_CTX *libctx, const char *propq)
{
    return 1;
}

int OSSL_ENCODER_CTX_get_num_encoders(OSSL_ENCODER_CTX *ctx)
{
    if (ctx == NULL || ctx->encoder_insts == NULL)
        return 0;
    return sk_OSSL_ENCODER_INSTANCE_num(ctx->encoder_insts);
}

int OSSL_ENCODER_CTX_set_construct(OSSL_ENCODER_CTX *ctx,
                                   OSSL_ENCODER_CONSTRUCT *construct)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx->construct = construct;
    return 1;
}

int OSSL_ENCODER_CTX_set_construct_data(OSSL_ENCODER_CTX *ctx,
                                        void *construct_data)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx->construct_data = construct_data;
    return 1;
}

int OSSL_ENCODER_CTX_set_cleanup(OSSL_ENCODER_CTX *ctx,
                                 OSSL_ENCODER_CLEANUP *cleanup)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx->cleanup = cleanup;
    return 1;
}

OSSL_ENCODER *
OSSL_ENCODER_INSTANCE_get_encoder(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->encoder;
}

void *
OSSL_ENCODER_INSTANCE_get_encoder_ctx(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->encoderctx;
}

const char *
OSSL_ENCODER_INSTANCE_get_input_type(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->input_type;
}

const char *
OSSL_ENCODER_INSTANCE_get_output_type(OSSL_ENCODER_INSTANCE *encoder_inst)
{
    if (encoder_inst == NULL)
        return NULL;
    return encoder_inst->output_type;
}

static int encoder_process(OSSL_ENCODER_CTX *ctx, BIO *out)
{
    size_t i, end;
    void *latest_output = NULL;
    size_t latest_output_length = 0;
    const char *latest_output_type = NULL;
    const char *last_input_type = NULL;
    int ok = 0;

    end = OSSL_ENCODER_CTX_get_num_encoders(ctx);
    for (i = 0; i < end; i++) {
        OSSL_ENCODER_INSTANCE *encoder_inst =
            sk_OSSL_ENCODER_INSTANCE_value(ctx->encoder_insts, i);
        OSSL_ENCODER *encoder = OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
        void *encoderctx = OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst);
        const char *current_input_type =
            OSSL_ENCODER_INSTANCE_get_input_type(encoder_inst);
        const char *current_output_type =
            OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst);
        BIO *current_out;
        BIO *allocated_out = NULL;
        const void *current_data = NULL;
        OSSL_PARAM abstract[3];
        OSSL_PARAM *abstract_p;
        const OSSL_PARAM *current_abstract = NULL;

        if (latest_output_type == NULL) {
            /*
             * This is the first iteration, so we prepare the object to be
             * encoded
             */

            current_data = ctx->construct(encoder_inst, ctx->construct_data);

            /* Assume that the constructor recorded an error */
            if (current_data == NULL)
                goto loop_end;
        } else {
            /*
             * Check that the latest output type matches the currently
             * considered encoder
             */
            if (!OSSL_ENCODER_is_a(encoder, latest_output_type))
                continue;

            /*
             * If there is a latest output type, there should be a latest output
             */
            if (!ossl_assert(latest_output != NULL)) {
                ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR);
                goto loop_end;
            }

            /*
             * Create an object abstraction from the latest output, which was
             * stolen from the previous round.
             */
            abstract_p = abstract;
            if (last_input_type != NULL)
                *abstract_p++ =
                    OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     (char *)last_input_type, 0);
            *abstract_p++ =
                OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                  latest_output,
                                                  latest_output_length);
            *abstract_p = OSSL_PARAM_construct_end();
            current_abstract = abstract;
        }

        /*
         * If the desired output type matches the output type of the currently
         * considered encoder, we're setting up final output.  Otherwise, set
         * up an intermediary memory output.
         */
        if (strcasecmp(ctx->output_type, current_output_type) == 0)
            current_out = out;
        else if ((current_out = allocated_out = BIO_new(BIO_s_mem())) == NULL)
            goto loop_end;     /* Assume BIO_new() recorded an error */

        ok = encoder->encode(encoderctx, (OSSL_CORE_BIO *)current_out,
                             current_data, current_abstract, ctx->selection,
                             ossl_pw_passphrase_callback_enc, &ctx->pwdata);

        if (current_input_type != NULL)
            last_input_type = current_input_type;

        if (!ok)
            goto loop_end;

        OPENSSL_free(latest_output);

        /*
         * Steal the output from the BIO_s_mem, if we did allocate one.
         * That'll be the data for an object abstraction in the next round.
         */
        if (allocated_out != NULL) {
            BUF_MEM *buf;

            BIO_get_mem_ptr(allocated_out, &buf);
            latest_output = buf->data;
            latest_output_length = buf->length;
            memset(buf, 0, sizeof(*buf));
            BIO_free(allocated_out);
        }

     loop_end:
        if (current_data != NULL)
            ctx->cleanup(ctx->construct_data);

        if (ok)
            break;
    }

    OPENSSL_free(latest_output);
    return ok;
}
