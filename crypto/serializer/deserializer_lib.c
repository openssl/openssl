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
#include "serializer_local.h"
#include "e_os.h"

struct deser_process_data_st {
    OSSL_DESERIALIZER_CTX *ctx;

    /* Current BIO */
    BIO *bio;

    /* Index of the current deserializer instance to be processed */
    size_t current_deser_inst_index;
};

static int deser_process(const OSSL_PARAM params[], void *arg);

int OSSL_DESERIALIZER_from_bio(OSSL_DESERIALIZER_CTX *ctx, BIO *in)
{
    struct deser_process_data_st data;
    int ok = 0;

    memset(&data, 0, sizeof(data));
    data.ctx = ctx;
    data.bio = in;

    ok = deser_process(NULL, &data);

    /* Clear any cached passphrase */
    OPENSSL_clear_free(ctx->cached_passphrase, ctx->cached_passphrase_len);
    ctx->cached_passphrase = NULL;
    ctx->cached_passphrase_len = 0;
    return ok;
}

#ifndef OPENSSL_NO_STDIO
static BIO *bio_from_file(FILE *fp)
{
    BIO *b;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_BIO_LIB);
        return NULL;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    return b;
}

int OSSL_DESERIALIZER_from_fp(OSSL_DESERIALIZER_CTX *ctx, FILE *fp)
{
    BIO *b = bio_from_file(fp);
    int ret = 0;

    if (b != NULL)
        ret = OSSL_DESERIALIZER_from_bio(ctx, b);

    BIO_free(b);
    return ret;
}
#endif

int OSSL_DESERIALIZER_CTX_set_input_type(OSSL_DESERIALIZER_CTX *ctx,
                                         const char *input_type)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * NULL is a valid starting input type, and means that the caller leaves
     * it to code to discover what the starting input type is.
     */
    ctx->start_input_type = input_type;
    return 1;
}

int OSSL_DESERIALIZER_CTX_add_deserializer(OSSL_DESERIALIZER_CTX *ctx,
                                           OSSL_DESERIALIZER *deser)
{
    OSSL_DESERIALIZER_INSTANCE *deser_inst = NULL;
    const OSSL_PROVIDER *prov = NULL;
    OSSL_PARAM params[2];
    void *provctx = NULL;

    if (!ossl_assert(ctx != NULL) || !ossl_assert(deser != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (deser->get_params == NULL) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER,
                  OSSL_DESERIALIZER_R_MISSING_GET_PARAMS);
        return 0;
    }

    if (ctx->deser_insts == NULL
        && (ctx->deser_insts =
            sk_OSSL_DESERIALIZER_INSTANCE_new_null()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if ((deser_inst = OPENSSL_zalloc(sizeof(*deser_inst))) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!OSSL_DESERIALIZER_up_ref(deser)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    deser_inst->deser = deser;

    prov = OSSL_DESERIALIZER_provider(deser_inst->deser);
    provctx = OSSL_PROVIDER_get0_provider_ctx(prov);

    /* Cache the input type for this serializer */
    params[0] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_DESERIALIZER_PARAM_INPUT_TYPE,
                                      (char **)&deser_inst->input_type, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!deser_inst->deser->get_params(params)
        || !OSSL_PARAM_modified(&params[0]))
        goto err;

    if ((deser_inst->deserctx = deser_inst->deser->newctx(provctx))
        == NULL)
        goto err;

    if (sk_OSSL_DESERIALIZER_INSTANCE_push(ctx->deser_insts, deser_inst) <= 0)
        goto err;

    return 1;
 err:
    if (deser_inst != NULL) {
        if (deser_inst->deser != NULL)
            deser_inst->deser->freectx(deser_inst->deserctx);
        OSSL_DESERIALIZER_free(deser_inst->deser);
        OPENSSL_free(deser_inst);
    }
    return 0;
}

int OSSL_DESERIALIZER_CTX_add_extra(OSSL_DESERIALIZER_CTX *ctx,
                                    OPENSSL_CTX *libctx, const char *propq)
{
    /*
     * This function goes through existing deserializer methods in
     * |ctx->deser_insts|, and tries to fetch new deserializers that produce
     * what the existing ones want as input, and push those newly fetched
     * deserializers on top of the same stack.
     * Then it does the same again, but looping over the newly fetched
     * deserializers, until there are no more serializers to be fetched, or
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
    size_t w_prev_start, w_prev_end; /* "previous" deserializers */
    size_t w_new_start, w_new_end;   /* "new" deserializers */
    size_t count = 0; /* Calculates how many were added in each iteration */
    size_t depth = 0; /* Counts the number of iterations */

    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * If there is no stack of OSSL_DESERIALIZER_INSTANCE, we have nothing
     * more to add.  That's fine.
     */
    if (ctx->deser_insts == NULL)
        return 1;

    w_prev_start = 0;
    w_prev_end = sk_OSSL_DESERIALIZER_INSTANCE_num(ctx->deser_insts);
    do {
        size_t i;

        w_new_start = w_new_end = w_prev_end;

        for (i = w_prev_start; i < w_prev_end; i++) {
            OSSL_DESERIALIZER_INSTANCE *deser_inst =
                sk_OSSL_DESERIALIZER_INSTANCE_value(ctx->deser_insts, i);
            const char *name = deser_inst->input_type;
            OSSL_DESERIALIZER *deser = NULL;

            /*
             * If the caller has specified what the initial input should be,
             * and the deserializer implementation we're looking at has that
             * input type, there's no point adding on more implementations
             * on top of this one, so we don't.
             */
            if (ctx->start_input_type != NULL
                && strcasecmp(ctx->start_input_type,
                              deser_inst->input_type) != 0)
                continue;

            ERR_set_mark();
            deser = OSSL_DESERIALIZER_fetch(libctx, name, propq);
            ERR_pop_to_mark();

            if (deser != NULL) {
                size_t j;

                /*
                 * Check that we don't already have this deserializer in our
                 * stack We only need to check among the newly added ones.
                 */
                for (j = w_new_start; j < w_new_end; j++) {
                    OSSL_DESERIALIZER_INSTANCE *check_inst =
                        sk_OSSL_DESERIALIZER_INSTANCE_value(ctx->deser_insts, j);

                    if (deser == check_inst->deser) {
                        /* We found it, so drop the new fetch */
                        OSSL_DESERIALIZER_free(deser);
                        deser = NULL;
                        break;
                    }
                }
            }

            if (deser == NULL)
                continue;

            /*
             * Apart from keeping w_new_end up to date, We don't care about
             * errors here.  If it doesn't collect, then it doesn't...
             */
            if (OSSL_DESERIALIZER_CTX_add_deserializer(ctx, deser)) /* ref++ */
                w_new_end++;
            OSSL_DESERIALIZER_free(deser); /* ref-- */
        }
        /* How many were added in this iteration */
        count = w_new_end - w_new_start;

        /* Slide the "previous deserializer" windows */
        w_prev_start = w_new_start;
        w_prev_end = w_new_end;

        depth++;
    } while (count != 0 && depth <= 10);

    return 1;
}

int OSSL_DESERIALIZER_CTX_num_deserializers(OSSL_DESERIALIZER_CTX *ctx)
{
    if (ctx == NULL || ctx->deser_insts == NULL)
        return 0;
    return sk_OSSL_DESERIALIZER_INSTANCE_num(ctx->deser_insts);
}

int OSSL_DESERIALIZER_CTX_set_finalizer(OSSL_DESERIALIZER_CTX *ctx,
                                        OSSL_DESERIALIZER_FINALIZER *finalizer,
                                        OSSL_DESERIALIZER_CLEANER *cleaner,
                                        void *finalize_arg)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx->finalizer = finalizer;
    ctx->cleaner = cleaner;
    ctx->finalize_arg = finalize_arg;
    return 1;
}

int OSSL_DESERIALIZER_export(OSSL_DESERIALIZER_INSTANCE *deser_inst,
                             void *reference, size_t reference_sz,
                             OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    if (!(ossl_assert(deser_inst != NULL)
          && ossl_assert(reference != NULL)
          && ossl_assert(export_cb != NULL)
          && ossl_assert(export_cbarg != NULL))) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return deser_inst->deser->export_object(deser_inst->deserctx,
                                            reference, reference_sz,
                                            export_cb, export_cbarg);
}

OSSL_DESERIALIZER *OSSL_DESERIALIZER_INSTANCE_deserializer
    (OSSL_DESERIALIZER_INSTANCE *deser_inst)
{
    if (deser_inst == NULL)
        return NULL;
    return deser_inst->deser;
}

void *OSSL_DESERIALIZER_INSTANCE_deserializer_ctx
    (OSSL_DESERIALIZER_INSTANCE *deser_inst)
{
    if (deser_inst == NULL)
        return NULL;
    return deser_inst->deserctx;
}

static int deser_process(const OSSL_PARAM params[], void *arg)
{
    struct deser_process_data_st *data = arg;
    OSSL_DESERIALIZER_CTX *ctx = data->ctx;
    OSSL_DESERIALIZER_INSTANCE *deser_inst = NULL;
    OSSL_DESERIALIZER *deser = NULL;
    BIO *bio = data->bio;
    long loc;
    size_t i;
    int ok = 0;
    /* For recursions */
    struct deser_process_data_st new_data;

    memset(&new_data, 0, sizeof(new_data));
    new_data.ctx = data->ctx;

    if (params == NULL) {
        /* First iteration, where we prepare for what is to come */

        data->current_deser_inst_index =
            OSSL_DESERIALIZER_CTX_num_deserializers(ctx);

        bio = data->bio;
    } else {
        const OSSL_PARAM *p;

        deser_inst =
            sk_OSSL_DESERIALIZER_INSTANCE_value(ctx->deser_insts,
                                                data->current_deser_inst_index);
        deser = OSSL_DESERIALIZER_INSTANCE_deserializer(deser_inst);

        if (ctx->finalizer(deser_inst, params, ctx->finalize_arg)) {
            ok = 1;
            goto end;
        }

        /* The finalizer didn't return success */

        /*
         * so we try to use the object we got and feed it to any next
         * deserializer that will take it.  Object references are not
         * allowed for this.
         * If this data isn't present, deserialization has failed.
         */

        p = OSSL_PARAM_locate_const(params, OSSL_DESERIALIZER_PARAM_DATA);
        if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            goto end;
        new_data.bio = BIO_new_mem_buf(p->data, (int)p->data_size);
        if (new_data.bio == NULL)
            goto end;
        bio = new_data.bio;
    }

    /*
     * If we have no more deserializers to look through at this point,
     * we failed
     */
    if (data->current_deser_inst_index == 0)
        goto end;

    if ((loc = BIO_tell(bio)) < 0) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_BIO_LIB);
        goto end;
    }

    for (i = data->current_deser_inst_index; i-- > 0;) {
        OSSL_DESERIALIZER_INSTANCE *new_deser_inst =
            sk_OSSL_DESERIALIZER_INSTANCE_value(ctx->deser_insts, i);
        OSSL_DESERIALIZER *new_deser =
            OSSL_DESERIALIZER_INSTANCE_deserializer(new_deser_inst);

        /*
         * If |deser| is NULL, it means we've just started, and the caller
         * may have specified what it expects the initial input to be.  If
         * that's the case, we do this extra check.
         */
        if (deser == NULL && ctx->start_input_type != NULL
            && strcasecmp(ctx->start_input_type, deser_inst->input_type) != 0)
            continue;

        /*
         * If we have a previous deserializer, we check that the input type
         * of the next to be used matches the type of this previous one.
         * deser_inst->input_type is a cache of the parameter "input-type"
         * value for that deserializer.
         */
        if (deser != NULL
            && !OSSL_DESERIALIZER_is_a(deser, new_deser_inst->input_type))
            continue;

        if (loc == 0) {
            if (BIO_reset(bio) <= 0)
                goto end;
        } else {
            if (BIO_seek(bio, loc) <= 0)
                goto end;
        }

        /* Recurse */
        new_data.current_deser_inst_index = i;
        ok = new_deser->deserialize(new_deser_inst->deserctx,
                                    (OSSL_CORE_BIO *)bio,
                                    deser_process, &new_data,
                                    NULL /* ossl_deserializer_passphrase_in_cb */,
                                    new_data.ctx);
        if (ok)
            break;
    }

 end:
    BIO_free(new_data.bio);
    return ok;
}
