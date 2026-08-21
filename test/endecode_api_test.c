/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Low-level OSSL_ENCODER / OSSL_DECODER API tests, using a test provider
 * that implements a two-stage encoder chain ("TEST-KEY" -> "inter" -> "pem")
 * and the corresponding decoder chain in the opposite direction.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include "testutil.h"

#define KEY_NAME "TEST-KEY"
#define INTER_NAME "inter"
#define PEM_NAME "pem"
#define STRUCTURE_NAME "test-structure"

#define PEM_HEADER "-----BEGIN " KEY_NAME "-----\n"
#define PEM_FOOTER "\n-----END " KEY_NAME "-----\n"
#define INTER_PREFIX "test-key-v1:"

#define TEST_SELECTION 0x07
/* A seed value that makes the "TEST-KEY" encoder implementation fail */
#define FAIL_SEED 666

static OSSL_LIB_CTX *testctx = NULL;
static OSSL_PROVIDER *testprov = NULL;

struct test_key_st {
    unsigned int seed;
    char label[32];
};

/*
 * The test provider.
 *
 * It supplies two encoders: one encoding a test key into an intermediate
 * "inter" format, and one wrapping "inter" data into a PEM-like format.
 * OSSL_ENCODER_to_bio() is expected to chain them, giving the deeper
 * encoder an intermediate memory BIO and passing its output to the outer
 * encoder as an abstract object.  The decoders mirror the encoders.
 *
 * The provider context is a child library context, so that the codec
 * implementations can use BIO_new_from_core_bio().
 */

static void *codec_newctx(void *provctx)
{
    return provctx;
}

static void codec_freectx(void *vctx)
{
}

static int key2inter_encode(void *vctx, OSSL_CORE_BIO *cout,
    const void *obj_raw, const OSSL_PARAM obj_abstract[],
    int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    const struct test_key_st *key = obj_raw;
    BIO *out;
    int ok;

    /* The deepest encoder is given the object as passed by the constructor */
    if (key == NULL || obj_abstract != NULL || selection != TEST_SELECTION)
        return 0;
    if (key->seed == FAIL_SEED)
        return 0;
    if ((out = BIO_new_from_core_bio(vctx, cout)) == NULL)
        return 0;
    ok = BIO_printf(out, INTER_PREFIX "%u:%s", key->seed, key->label) > 0;
    BIO_free(out);
    return ok;
}

static const OSSL_DISPATCH key2inter_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))codec_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))codec_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))key2inter_encode },
    OSSL_DISPATCH_END
};

static int inter2pem_encode(void *vctx, OSSL_CORE_BIO *cout,
    const void *obj_raw, const OSSL_PARAM obj_abstract[],
    int selection,
    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    const OSSL_PARAM *p;
    BIO *out;
    int ok;

    /* A chained encoder is given an abstract object, not a raw one */
    if (obj_abstract == NULL || obj_raw != NULL)
        return 0;

    /* The data structure of the previous encoding round must be passed on */
    p = OSSL_PARAM_locate_const(obj_abstract, OSSL_OBJECT_PARAM_DATA_STRUCTURE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING
        || p->data_size != strlen(STRUCTURE_NAME)
        || memcmp(p->data, STRUCTURE_NAME, p->data_size) != 0)
        return 0;

    /* Likewise the data type, naming the encoder that produced the data */
    p = OSSL_PARAM_locate_const(obj_abstract, OSSL_OBJECT_PARAM_DATA_TYPE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING
        || p->data == NULL || p->data_size != strlen(KEY_NAME)
        || memcmp(p->data, KEY_NAME, p->data_size) != 0)
        return 0;

    p = OSSL_PARAM_locate_const(obj_abstract, OSSL_OBJECT_PARAM_DATA);
    if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;

    if ((out = BIO_new_from_core_bio(vctx, cout)) == NULL)
        return 0;
    ok = BIO_printf(out, "%s", PEM_HEADER) > 0
        && BIO_write(out, p->data, (int)p->data_size) == (int)p->data_size
        && BIO_printf(out, "%s", PEM_FOOTER) > 0;
    BIO_free(out);
    return ok;
}

static const OSSL_DISPATCH inter2pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))codec_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))codec_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))inter2pem_encode },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM test_encoders[] = {
    { KEY_NAME, "provider=apitest,output=" INTER_NAME ",structure=" STRUCTURE_NAME,
        key2inter_encoder_functions },
    { INTER_NAME, "provider=apitest,output=" PEM_NAME,
        inter2pem_encoder_functions },
    { NULL, NULL, NULL }
};

/* Read everything from a core BIO into |buf| as a NUL terminated string */
static int read_core_bio(void *provctx, OSSL_CORE_BIO *cin,
    char *buf, size_t bufsz, size_t *readlen)
{
    BIO *in;
    size_t total = 0;
    int l;

    if ((in = BIO_new_from_core_bio(provctx, cin)) == NULL)
        return 0;
    while (total < bufsz - 1
        && (l = BIO_read(in, buf + total, (int)(bufsz - 1 - total))) > 0)
        total += l;
    BIO_free(in);
    buf[total] = '\0';
    *readlen = total;
    return 1;
}

static int pem2inter_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
    OSSL_CALLBACK *data_cb, void *data_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    char buf[1024];
    size_t len, payload_len;
    OSSL_PARAM params[5];

    if (!read_core_bio(vctx, cin, buf, sizeof(buf), &len))
        return 0;

    /* If it isn't wrapped in our PEM-like format, it's not for us */
    if (len < sizeof(PEM_HEADER) - 1 + sizeof(PEM_FOOTER) - 1
        || strncmp(buf, PEM_HEADER, sizeof(PEM_HEADER) - 1) != 0
        || strcmp(buf + len - (sizeof(PEM_FOOTER) - 1), PEM_FOOTER) != 0)
        return 1;

    payload_len = len - (sizeof(PEM_HEADER) - 1) - (sizeof(PEM_FOOTER) - 1);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
        buf + sizeof(PEM_HEADER) - 1,
        payload_len);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char *)KEY_NAME, 0);
    params[2] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
        (char *)STRUCTURE_NAME, 0);
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_INPUT_TYPE,
        (char *)INTER_NAME, 0);
    params[4] = OSSL_PARAM_construct_end();

    return data_cb(params, data_cbarg);
}

static const OSSL_DISPATCH pem2inter_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))codec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))codec_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))pem2inter_decode },
    OSSL_DISPATCH_END
};

static int inter2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
    OSSL_CALLBACK *data_cb, void *data_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    char buf[1024];
    size_t len;
    unsigned long seed;
    const char *label;
    char *end;
    struct test_key_st *key;
    OSSL_PARAM params[4];
    int ok;

    if (!read_core_bio(vctx, cin, buf, sizeof(buf), &len))
        return 0;

    /* Data that doesn't parse simply isn't ours; no fatal error */
    if (strncmp(buf, INTER_PREFIX, sizeof(INTER_PREFIX) - 1) != 0)
        return 1;
    seed = strtoul(buf + sizeof(INTER_PREFIX) - 1, &end, 10);
    if (end == buf + sizeof(INTER_PREFIX) - 1 || *end != ':')
        return 1;
    label = end + 1;

    if ((key = OPENSSL_zalloc(sizeof(*key))) == NULL)
        return 0;
    key->seed = (unsigned int)seed;
    OPENSSL_strlcpy(key->label, label, sizeof(key->label));

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &key, sizeof(key));
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char *)KEY_NAME, 0);
    params[2] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
        (char *)STRUCTURE_NAME, 0);
    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);
    OPENSSL_free(key);
    return ok;
}

static int key_export_object(void *vctx, const void *objref, size_t objref_sz,
    OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    struct test_key_st *key;
    OSSL_PARAM params[3];

    if (objref_sz != sizeof(key))
        return 0;
    memcpy(&key, objref, sizeof(key));

    params[0] = OSSL_PARAM_construct_uint("seed", &key->seed);
    params[1] = OSSL_PARAM_construct_utf8_string("label", key->label, 0);
    params[2] = OSSL_PARAM_construct_end();

    return export_cb(params, export_cbarg);
}

static const OSSL_DISPATCH inter2key_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))codec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))codec_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))inter2key_decode },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))key_export_object },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM test_decoders[] = {
    { KEY_NAME, "provider=apitest,input=" INTER_NAME ",structure=" STRUCTURE_NAME,
        inter2key_decoder_functions },
    { INTER_NAME, "provider=apitest,input=" PEM_NAME,
        pem2inter_decoder_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *apitest_query(void *provctx, int operation_id,
    int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_ENCODER:
        return test_encoders;
    case OSSL_OP_DECODER:
        return test_decoders;
    }
    return NULL;
}

static const OSSL_DISPATCH apitest_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))apitest_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
    OSSL_DISPATCH_END
};

static int apitest_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_child(handle, in);

    if (libctx == NULL)
        return 0;
    *provctx = libctx;
    *out = apitest_dispatch_table;
    return 1;
}

/*
 * The encoder/decoder context callbacks used by the tests
 */

struct enc_construct_data_st {
    const struct test_key_st *key;
    int fail_construct;
    int cleanup_calls;
};

static const void *enc_construct(OSSL_ENCODER_INSTANCE *encoder_inst,
    void *arg)
{
    struct enc_construct_data_st *data = arg;

    if (data->fail_construct)
        return NULL;
    /* The constructor gets the deepest matching encoder instance */
    if (!TEST_true(OSSL_ENCODER_is_a(
            OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst), KEY_NAME))
        || !TEST_ptr(OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst))
        || !TEST_str_eq(OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst),
            INTER_NAME)
        || !TEST_str_eq(OSSL_ENCODER_INSTANCE_get_output_structure(
                            encoder_inst),
            STRUCTURE_NAME))
        return NULL;
    return data->key;
}

static void enc_cleanup(void *arg)
{
    struct enc_construct_data_st *data = arg;

    data->cleanup_calls++;
}

struct dec_construct_data_st {
    unsigned int seed;
    char label[64];
    int constructed;
    int construct_calls;
    int cleanup_calls;
};

static int dec_export_cb(const OSSL_PARAM params[], void *arg)
{
    struct dec_construct_data_st *data = arg;
    const OSSL_PARAM *p;
    char *label = data->label;

    if (!TEST_ptr(p = OSSL_PARAM_locate_const(params, "seed"))
        || !TEST_true(OSSL_PARAM_get_uint(p, &data->seed))
        || !TEST_ptr(p = OSSL_PARAM_locate_const(params, "label"))
        || !TEST_true(OSSL_PARAM_get_utf8_string(p, &label,
            sizeof(data->label))))
        return 0;
    data->constructed = 1;
    return 1;
}

static int dec_construct(OSSL_DECODER_INSTANCE *decoder_inst,
    const OSSL_PARAM *params, void *arg)
{
    struct dec_construct_data_st *data = arg;
    const OSSL_PARAM *p;
    int was_set = 0;

    data->construct_calls++;

    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p == NULL) {
        /*
         * An intermediate decoding result (from the "inter" decoder);
         * report it as not constructible so that processing continues
         * with the next decoder in the chain.
         */
        return 0;
    }

    if (!TEST_true(OSSL_DECODER_is_a(
            OSSL_DECODER_INSTANCE_get_decoder(decoder_inst), KEY_NAME))
        || !TEST_ptr(OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst))
        || !TEST_str_eq(OSSL_DECODER_INSTANCE_get_input_type(decoder_inst),
            INTER_NAME)
        || !TEST_str_eq(OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst,
                            &was_set),
            STRUCTURE_NAME))
        return 0;
    if (!TEST_int_eq(p->data_type, OSSL_PARAM_OCTET_STRING))
        return 0;

    return OSSL_DECODER_export(decoder_inst, p->data, p->data_size,
        dec_export_cb, data);
}

static void dec_cleanup(void *arg)
{
    struct dec_construct_data_st *data = arg;

    data->cleanup_calls++;
}

/*
 * Test helpers
 */

/*
 * Create an encoder context with the "TEST-KEY" -> "inter" -> "pem" encoder
 * chain set up.  The construct data is allocated here because
 * OSSL_ENCODER_CTX_free() frees it; |*cdata_out| is an alias that stays
 * valid for as long as the returned context lives.
 */
static OSSL_ENCODER_CTX *make_encoder_ctx(const struct test_key_st *key,
    const char *structure,
    struct enc_construct_data_st **cdata_out)
{
    OSSL_ENCODER_CTX *ctx = NULL;
    OSSL_ENCODER *e_key = NULL, *e_inter = NULL;
    struct enc_construct_data_st *cdata = NULL;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_ENCODER_CTX_new())
        || !TEST_ptr(cdata = OPENSSL_zalloc(sizeof(*cdata)))
        || !TEST_true(OSSL_ENCODER_CTX_set_construct_data(ctx, cdata)))
        goto end;
    cdata->key = key;
    *cdata_out = cdata;
    cdata = NULL; /* Owned by ctx now */

    if (!TEST_ptr(e_key = OSSL_ENCODER_fetch(testctx, KEY_NAME, NULL))
        || !TEST_ptr(e_inter = OSSL_ENCODER_fetch(testctx, INTER_NAME, NULL)))
        goto end;

    /*
     * The encoder chain is walked from the last added encoder towards the
     * first one, so the deepest encoder must be added first.
     */
    if (!TEST_true(OSSL_ENCODER_CTX_add_encoder(ctx, e_key))
        || !TEST_true(OSSL_ENCODER_CTX_add_encoder(ctx, e_inter))
        || !TEST_int_eq(OSSL_ENCODER_CTX_get_num_encoders(ctx), 2)
        || !TEST_true(OSSL_ENCODER_CTX_add_extra(ctx, testctx, NULL))
        || !TEST_true(OSSL_ENCODER_CTX_set_output_type(ctx, PEM_NAME))
        || (structure != NULL
            && !TEST_true(OSSL_ENCODER_CTX_set_output_structure(ctx,
                structure)))
        || !TEST_true(OSSL_ENCODER_CTX_set_selection(ctx, TEST_SELECTION))
        || !TEST_true(OSSL_ENCODER_CTX_set_construct(ctx, enc_construct))
        || !TEST_true(OSSL_ENCODER_CTX_set_cleanup(ctx, enc_cleanup)))
        goto end;
    ok = 1;
end:
    OSSL_ENCODER_free(e_key);
    OSSL_ENCODER_free(e_inter);
    OPENSSL_free(cdata);
    if (!ok) {
        OSSL_ENCODER_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

static OSSL_DECODER_CTX *make_decoder_ctx(struct dec_construct_data_st *cdata)
{
    OSSL_DECODER_CTX *ctx = NULL;
    OSSL_DECODER *d_key = NULL, *d_inter = NULL;
    int ok = 0;

    if (!TEST_ptr(ctx = OSSL_DECODER_CTX_new())
        || !TEST_int_eq(OSSL_DECODER_CTX_get_num_decoders(ctx), 0)
        || !TEST_ptr(d_key = OSSL_DECODER_fetch(testctx, KEY_NAME, NULL))
        || !TEST_ptr(d_inter = OSSL_DECODER_fetch(testctx, INTER_NAME, NULL)))
        goto end;

    /*
     * The decoder chain is walked from the last added decoder towards the
     * first one, so the final decoder must be added first.
     */
    if (!TEST_true(OSSL_DECODER_CTX_add_decoder(ctx, d_key))
        || !TEST_true(OSSL_DECODER_CTX_add_decoder(ctx, d_inter))
        || !TEST_int_eq(OSSL_DECODER_CTX_get_num_decoders(ctx), 2)
        || !TEST_true(OSSL_DECODER_CTX_set_input_type(ctx, PEM_NAME))
        || !TEST_true(OSSL_DECODER_CTX_set_input_structure(ctx,
            STRUCTURE_NAME))
        || !TEST_true(OSSL_DECODER_CTX_set_selection(ctx, TEST_SELECTION))
        || !TEST_true(OSSL_DECODER_CTX_set_construct(ctx, dec_construct))
        || !TEST_true(OSSL_DECODER_CTX_set_construct_data(ctx, cdata))
        || !TEST_true(OSSL_DECODER_CTX_set_cleanup(ctx, dec_cleanup)))
        goto end;
    ok = 1;
end:
    OSSL_DECODER_free(d_key);
    OSSL_DECODER_free(d_inter);
    if (!ok) {
        OSSL_DECODER_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

static int make_expected(const struct test_key_st *key, char *buf,
    size_t bufsz, size_t *len)
{
    int n = BIO_snprintf(buf, bufsz,
        PEM_HEADER INTER_PREFIX "%u:%s" PEM_FOOTER, key->seed, key->label);

    if (n <= 0)
        return 0;
    *len = (size_t)n;
    return 1;
}

/*
 * Encode a test key through the two-stage encoder chain into a BIO and
 * check the result.
 */
static int test_chain_encode_to_bio(void)
{
    const struct test_key_st key = { 12345, "chained" };
    struct enc_construct_data_st *cdata = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    BIO *out = NULL;
    BUF_MEM *mem = NULL;
    char expected[256];
    size_t expected_len = 0;
    int ok = 0;

    if (!TEST_true(make_expected(&key, expected, sizeof(expected), &expected_len))
        || !TEST_ptr(ectx = make_encoder_ctx(&key, STRUCTURE_NAME, &cdata)))
        goto end;

    if (!TEST_ptr(out = BIO_new(BIO_s_mem()))
        || !TEST_true(OSSL_ENCODER_to_bio(ectx, out))
        || !TEST_true(BIO_get_mem_ptr(out, &mem) > 0)
        || !TEST_mem_eq(mem->data, mem->length, expected, expected_len))
        goto end;

    /* The cleanup callback must have been called exactly once */
    if (!TEST_int_eq(cdata->cleanup_calls, 1))
        goto end;

    ok = 1;
end:
    BIO_free(out);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

/* Exercise the various OSSL_ENCODER_to_data() modes of operation */
static int test_chain_encode_to_data(void)
{
    const struct test_key_st key = { 999, "to-data" };
    struct enc_construct_data_st *cdata = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    unsigned char *buf = NULL, *p, *allocated = NULL;
    char expected[256];
    size_t expected_len = 0, len, sz;
    int ok = 0;

    if (!TEST_true(make_expected(&key, expected, sizeof(expected), &expected_len))
        /* No output structure this time; the chain works without one too */
        || !TEST_ptr(ectx = make_encoder_ctx(&key, NULL, &cdata)))
        goto end;

    /* A NULL pdata_len is an error */
    if (!TEST_false(OSSL_ENCODER_to_data(ectx, NULL, NULL)))
        goto end;

    /* Size query */
    len = 0;
    if (!TEST_true(OSSL_ENCODER_to_data(ectx, NULL, &len))
        || !TEST_size_t_eq(len, expected_len))
        goto end;

    /* Encoding into a pre-allocated buffer of exactly the right size */
    if (!TEST_ptr(buf = OPENSSL_malloc(len)))
        goto end;
    p = buf;
    sz = len;
    if (!TEST_true(OSSL_ENCODER_to_data(ectx, &p, &sz))
        || !TEST_size_t_eq(sz, 0)
        || !TEST_ptr_eq(p, buf + expected_len)
        || !TEST_mem_eq(buf, expected_len, expected, expected_len))
        goto end;

    /* A too small pre-allocated buffer is an error */
    p = buf;
    sz = expected_len - 1;
    if (!TEST_false(OSSL_ENCODER_to_data(ectx, &p, &sz)))
        goto end;

    /* With *pdata == NULL, the buffer is allocated for us */
    sz = 0;
    if (!TEST_true(OSSL_ENCODER_to_data(ectx, &allocated, &sz))
        || !TEST_mem_eq(allocated, sz, expected, expected_len))
        goto end;

    ok = 1;
end:
    OPENSSL_free(buf);
    OPENSSL_free(allocated);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

/* Decode through the decoder chain and check the constructed object */
static int test_chain_decode_from_data(void)
{
    const struct test_key_st key = { 4711, "decode" };
    struct dec_construct_data_st dcdata;
    OSSL_DECODER_CTX *dctx = NULL;
    char encoded[256];
    size_t encoded_len = 0;
    const unsigned char *pdata;
    size_t pdata_len;
    int ok = 0;

    memset(&dcdata, 0, sizeof(dcdata));
    if (!TEST_true(make_expected(&key, encoded, sizeof(encoded), &encoded_len))
        || !TEST_ptr(dctx = make_decoder_ctx(&dcdata)))
        goto end;

    pdata = (unsigned char *)encoded;
    pdata_len = encoded_len;
    if (!TEST_true(OSSL_DECODER_from_data(dctx, &pdata, &pdata_len))
        || !TEST_size_t_eq(pdata_len, 0)
        || !TEST_true(dcdata.constructed)
        || !TEST_uint_eq(dcdata.seed, key.seed)
        || !TEST_str_eq(dcdata.label, key.label)
        /* Once for the intermediate decoder, once for the final one */
        || !TEST_int_eq(dcdata.construct_calls, 2))
        goto end;

    OSSL_DECODER_CTX_free(dctx);
    dctx = NULL;
    /* The cleanup callback is called when the context is freed */
    if (!TEST_int_eq(dcdata.cleanup_calls, 1))
        goto end;

    ok = 1;
end:
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}

#ifndef OPENSSL_NO_STDIO
/* Round-trip via OSSL_ENCODER_to_fp() and OSSL_DECODER_from_fp() */
static int test_chain_roundtrip_fp(void)
{
    const struct test_key_st key = { 31337, "stdio" };
    struct enc_construct_data_st *ecdata = NULL;
    struct dec_construct_data_st dcdata;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    const char *fname = "endecode_api_test.tmp";
    FILE *fp = NULL;
    int ok = 0;

    memset(&dcdata, 0, sizeof(dcdata));
    if (!TEST_ptr(ectx = make_encoder_ctx(&key, STRUCTURE_NAME, &ecdata))
        || !TEST_ptr(dctx = make_decoder_ctx(&dcdata)))
        goto end;

    if (!TEST_ptr(fp = fopen(fname, "w+b"))
        || !TEST_true(OSSL_ENCODER_to_fp(ectx, fp)))
        goto end;
    rewind(fp);
    if (!TEST_true(OSSL_DECODER_from_fp(dctx, fp))
        || !TEST_true(dcdata.constructed)
        || !TEST_uint_eq(dcdata.seed, key.seed)
        || !TEST_str_eq(dcdata.label, key.label))
        goto end;

    ok = 1;
end:
    if (fp != NULL) {
        fclose(fp);
        remove(fname);
    }
    OSSL_ENCODER_CTX_free(ectx);
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}
#endif

/*
 * A source BIO that doesn't support BIO_tell(), forcing
 * OSSL_DECODER_from_bio() to wrap it with a read buffer filter BIO.
 */

struct nonseek_state_st {
    const unsigned char *data;
    size_t len;
    size_t pos;
};

static int nonseek_read(BIO *b, char *out, int outl)
{
    struct nonseek_state_st *st = BIO_get_data(b);
    size_t n = st->len - st->pos;

    if (n == 0)
        return 0;
    if (n > (size_t)outl)
        n = (size_t)outl;
    memcpy(out, st->data + st->pos, n);
    st->pos += n;
    return (int)n;
}

static long nonseek_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    struct nonseek_state_st *st = BIO_get_data(b);

    switch (cmd) {
    case BIO_CTRL_EOF:
        return st->pos >= st->len;
    case BIO_C_FILE_TELL:
        return -1;
    }
    return 0;
}

static BIO_METHOD *nonseek_meth = NULL;

static int test_decode_non_seekable_bio(void)
{
    const struct test_key_st key = { 2222, "nonseek" };
    struct dec_construct_data_st dcdata;
    OSSL_DECODER_CTX *dctx = NULL;
    struct nonseek_state_st st;
    BIO *in = NULL;
    char encoded[256];
    size_t encoded_len = 0;
    int ok = 0;

    memset(&dcdata, 0, sizeof(dcdata));
    if (!TEST_true(make_expected(&key, encoded, sizeof(encoded), &encoded_len))
        || !TEST_ptr(dctx = make_decoder_ctx(&dcdata)))
        goto end;

    st.data = (unsigned char *)encoded;
    st.len = encoded_len;
    st.pos = 0;
    if (!TEST_ptr(in = BIO_new(nonseek_meth)))
        goto end;
    BIO_set_data(in, &st);
    BIO_set_init(in, 1);

    if (!TEST_int_lt(BIO_tell(in), 0)
        || !TEST_true(OSSL_DECODER_from_bio(dctx, in))
        || !TEST_true(dcdata.constructed)
        || !TEST_uint_eq(dcdata.seed, key.seed)
        || !TEST_str_eq(dcdata.label, key.label))
        goto end;

    ok = 1;
end:
    BIO_free(in);
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}

/* Various ways an encoding attempt can fail */
static int test_encode_failures(void)
{
    const struct test_key_st key = { 1, "fail" };
    const struct test_key_st failkey = { FAIL_SEED, "fail" };
    struct enc_construct_data_st *cdata = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_ENCODER *encoder = NULL;
    BIO *out = NULL;
    int ok = 0;

    if (!TEST_ptr(out = BIO_new(BIO_s_mem())))
        goto end;

    /* An empty encoder context finds no encoders */
    if (!TEST_ptr(ectx = OSSL_ENCODER_CTX_new())
        || !TEST_false(OSSL_ENCODER_to_bio(ectx, out)))
        goto end;
    OSSL_ENCODER_CTX_free(ectx);
    ectx = NULL;

    /* A context without a constructor cannot encode */
    if (!TEST_ptr(ectx = OSSL_ENCODER_CTX_new())
        || !TEST_ptr(encoder = OSSL_ENCODER_fetch(testctx, INTER_NAME, NULL))
        || !TEST_true(OSSL_ENCODER_CTX_add_encoder(ectx, encoder))
        || !TEST_false(OSSL_ENCODER_to_bio(ectx, out)))
        goto end;
    OSSL_ENCODER_CTX_free(ectx);
    ectx = NULL;

    /* An output structure that no encoder implements */
    if (!TEST_ptr(ectx = make_encoder_ctx(&key, "unknown-structure", &cdata))
        || !TEST_false(OSSL_ENCODER_to_bio(ectx, out)))
        goto end;
    OSSL_ENCODER_CTX_free(ectx);
    ectx = NULL;

    /* A failing constructor makes the encoding fail */
    if (!TEST_ptr(ectx = make_encoder_ctx(&key, STRUCTURE_NAME, &cdata)))
        goto end;
    cdata->fail_construct = 1;
    if (!TEST_false(OSSL_ENCODER_to_bio(ectx, out))
        || !TEST_int_eq(cdata->cleanup_calls, 0))
        goto end;
    OSSL_ENCODER_CTX_free(ectx);
    ectx = NULL;

    /* A failing encoder implementation makes the encoding fail */
    if (!TEST_ptr(ectx = make_encoder_ctx(&failkey, STRUCTURE_NAME, &cdata))
        || !TEST_false(OSSL_ENCODER_to_bio(ectx, out))
        /* The constructor succeeded, so the cleanup must have been called */
        || !TEST_int_eq(cdata->cleanup_calls, 1))
        goto end;

    ok = 1;
end:
    OSSL_ENCODER_free(encoder);
    OSSL_ENCODER_CTX_free(ectx);
    BIO_free(out);
    return ok;
}

/* Undecodable input must fail without constructing anything */
static int test_decode_garbage(void)
{
    struct dec_construct_data_st dcdata;
    OSSL_DECODER_CTX *dctx = NULL;
    static const char garbage[] = "this is not an encoded test key";
    const unsigned char *pdata = (const unsigned char *)garbage;
    size_t pdata_len = sizeof(garbage) - 1;
    int ok = 0;

    memset(&dcdata, 0, sizeof(dcdata));
    if (!TEST_ptr(dctx = make_decoder_ctx(&dcdata)))
        goto end;

    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdata_len))
        || !TEST_false(dcdata.constructed))
        goto end;

    ok = 1;
end:
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}

/* NULL argument checks on the encoder API */
static int test_encoder_null_args(void)
{
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_ENCODER *encoder = NULL;
    unsigned char *pdata = NULL;
    int ok = 0;

    if (!TEST_ptr(ectx = OSSL_ENCODER_CTX_new())
        || !TEST_ptr(encoder = OSSL_ENCODER_fetch(testctx, KEY_NAME, NULL)))
        goto end;

    if (!TEST_false(OSSL_ENCODER_CTX_set_selection(NULL, TEST_SELECTION))
        || !TEST_false(OSSL_ENCODER_CTX_set_selection(ectx, 0))
        || !TEST_false(OSSL_ENCODER_CTX_set_output_type(NULL, PEM_NAME))
        || !TEST_false(OSSL_ENCODER_CTX_set_output_type(ectx, NULL))
        || !TEST_false(OSSL_ENCODER_CTX_set_output_structure(NULL, STRUCTURE_NAME))
        || !TEST_false(OSSL_ENCODER_CTX_set_output_structure(ectx, NULL))
        || !TEST_false(OSSL_ENCODER_CTX_add_encoder(NULL, encoder))
        || !TEST_false(OSSL_ENCODER_CTX_add_encoder(ectx, NULL))
        || !TEST_false(OSSL_ENCODER_CTX_add_extra(NULL, testctx, NULL))
        || !TEST_false(OSSL_ENCODER_CTX_set_construct(NULL, enc_construct))
        || !TEST_false(OSSL_ENCODER_CTX_set_construct_data(NULL, NULL))
        || !TEST_false(OSSL_ENCODER_CTX_set_cleanup(NULL, enc_cleanup))
        || !TEST_int_eq(OSSL_ENCODER_CTX_get_num_encoders(NULL), 0)
        || !TEST_false(OSSL_ENCODER_to_data(ectx, &pdata, NULL)))
        goto end;

    if (!TEST_ptr_null(OSSL_ENCODER_INSTANCE_get_encoder(NULL))
        || !TEST_ptr_null(OSSL_ENCODER_INSTANCE_get_encoder_ctx(NULL))
        || !TEST_ptr_null(OSSL_ENCODER_INSTANCE_get_output_type(NULL))
        || !TEST_ptr_null(OSSL_ENCODER_INSTANCE_get_output_structure(NULL)))
        goto end;

    ok = 1;
end:
    OSSL_ENCODER_free(encoder);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

/* NULL argument checks on the decoder API */
static int test_decoder_null_args(void)
{
    OSSL_DECODER_CTX *dctx = NULL;
    OSSL_DECODER *decoder = NULL;
    const unsigned char *pdata = NULL;
    unsigned char buf[16];
    const unsigned char *pbuf = buf;
    size_t pdata_len = 0;
    int was_set = 0;
    int ok = 0;

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new())
        || !TEST_ptr(decoder = OSSL_DECODER_fetch(testctx, KEY_NAME, NULL)))
        goto end;

    if (!TEST_false(OSSL_DECODER_CTX_set_selection(NULL, TEST_SELECTION))
        || !TEST_false(OSSL_DECODER_CTX_set_input_type(NULL, PEM_NAME))
        || !TEST_false(OSSL_DECODER_CTX_set_input_structure(NULL, STRUCTURE_NAME))
        || !TEST_false(OSSL_DECODER_CTX_add_decoder(NULL, decoder))
        || !TEST_false(OSSL_DECODER_CTX_add_decoder(dctx, NULL))
        || !TEST_false(OSSL_DECODER_CTX_add_extra(NULL, testctx, NULL))
        || !TEST_false(OSSL_DECODER_CTX_set_construct(NULL, dec_construct))
        || !TEST_false(OSSL_DECODER_CTX_set_construct_data(NULL, NULL))
        || !TEST_false(OSSL_DECODER_CTX_set_cleanup(NULL, dec_cleanup))
        || !TEST_int_eq(OSSL_DECODER_CTX_get_num_decoders(NULL), 0)
        || !TEST_false(OSSL_DECODER_from_data(dctx, NULL, &pdata_len))
        || !TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdata_len))
        || !TEST_false(OSSL_DECODER_from_data(dctx, &pbuf, NULL))
        || !TEST_false(OSSL_DECODER_export(NULL, NULL, 0, NULL, NULL)))
        goto end;

    if (!TEST_true(OSSL_DECODER_CTX_get_construct(NULL) == NULL)
        || !TEST_ptr_null(OSSL_DECODER_CTX_get_construct_data(NULL))
        || !TEST_true(OSSL_DECODER_CTX_get_cleanup(NULL) == NULL)
        || !TEST_ptr_null(OSSL_DECODER_INSTANCE_get_decoder(NULL))
        || !TEST_ptr_null(OSSL_DECODER_INSTANCE_get_decoder_ctx(NULL))
        || !TEST_ptr_null(OSSL_DECODER_INSTANCE_get_input_type(NULL))
        || !TEST_ptr_null(OSSL_DECODER_INSTANCE_get_input_structure(NULL, &was_set)))
        goto end;

    ok = 1;
end:
    OSSL_DECODER_free(decoder);
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}

int setup_tests(void)
{
    if (!TEST_ptr(testctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(testctx, "apitest-prov",
            apitest_provider_init))
        || !TEST_ptr(testprov = OSSL_PROVIDER_load(testctx, "apitest-prov")))
        return 0;

    if (!TEST_ptr(nonseek_meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK,
                      "non-seekable source"))
        || !TEST_true(BIO_meth_set_read(nonseek_meth, nonseek_read))
        || !TEST_true(BIO_meth_set_ctrl(nonseek_meth, nonseek_ctrl)))
        return 0;

    ADD_TEST(test_chain_encode_to_bio);
    ADD_TEST(test_chain_encode_to_data);
    ADD_TEST(test_chain_decode_from_data);
#ifndef OPENSSL_NO_STDIO
    ADD_TEST(test_chain_roundtrip_fp);
#endif
    ADD_TEST(test_decode_non_seekable_bio);
    ADD_TEST(test_encode_failures);
    ADD_TEST(test_decode_garbage);
    ADD_TEST(test_encoder_null_args);
    ADD_TEST(test_decoder_null_args);
    return 1;
}

void cleanup_tests(void)
{
    BIO_meth_free(nonseek_meth);
    OSSL_PROVIDER_unload(testprov);
    OSSL_LIB_CTX_free(testctx);
}
