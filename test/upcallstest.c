/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/objects.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include "testutil.h"

static const OSSL_ALGORITHM *obj_query(void *provctx, int operation_id,
                                       int *no_cache)
{
    *no_cache = 0;
    return NULL;
}

static const OSSL_DISPATCH obj_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))obj_query },
    { 0, NULL }
};

static OSSL_FUNC_OBJ_add_sigid_fn *c_obj_add_sigid = NULL;
static OSSL_FUNC_OBJ_create_fn *c_obj_create = NULL;
static OSSL_FUNC_OBJ_txt2nid_fn *c_obj_txt2nid = NULL;
static OSSL_FUNC_OBJ_sn2nid_fn *c_obj_sn2nid = NULL;
static OSSL_FUNC_OBJ_ln2nid_fn *c_obj_ln2nid = NULL;

static int test_create_oid(const char *oid, const char *sn, const char *ln)
{
    int nid = c_obj_create(oid, sn, ln);

    if (nid == NID_undef
            || c_obj_txt2nid(oid) != nid
            || c_obj_sn2nid(sn) != nid
            || c_obj_ln2nid(ln) != nid)
        return NID_undef;

    return nid;
}

#define SIG_OID "1.3.6.1.4.1.16604.998877.1"
#define SIG_SN "my-sig"
#define SIG_LN "my-sig-long"
#define DIGEST_OID "1.3.6.1.4.1.16604.998877.2"
#define DIGEST_SN "my-digest"
#define DIGEST_LN "my-digest-long"
#define SIGALG_OID "1.3.6.1.4.1.16604.998877.3"
#define SIGALG_SN "my-sigalg"
#define SIGALG_LN "my-sigalg-long"

static int obj_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{

    int digestnid, signid, sigalgnid;

    *provctx = (void *)handle;
    *out = obj_dispatch_table;

   for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_OBJ_add_sigid(in);
            break;
        case OSSL_FUNC_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_OBJ_create(in);
            break;
        case OSSL_FUNC_OBJ_TXT2NID:
            c_obj_txt2nid = OSSL_FUNC_OBJ_txt2nid(in);
            break;
        case OSSL_FUNC_OBJ_SN2NID:
            c_obj_sn2nid = OSSL_FUNC_OBJ_sn2nid(in);
            break;
        case OSSL_FUNC_OBJ_LN2NID:
            c_obj_ln2nid = OSSL_FUNC_OBJ_ln2nid(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    digestnid = test_create_oid(DIGEST_OID, DIGEST_SN, DIGEST_LN);
    signid = test_create_oid(SIG_OID, SIG_SN, SIG_LN);
    sigalgnid = test_create_oid(SIGALG_OID, SIGALG_SN, SIGALG_LN);

    if (digestnid == NID_undef || signid == NID_undef)
        return 0;

    if (!c_obj_add_sigid(sigalgnid, digestnid, signid))
        return 0;

    return 1;
}

static int obj_create_test(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *objprov = NULL;
    int sigalgnid, digestnid, signid;
    int testresult = 0;

    if (!TEST_ptr(libctx))
        goto err;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "obj-prov",
                                             obj_provider_init))
            || !TEST_ptr(objprov = OSSL_PROVIDER_load(libctx, "obj-prov")))
        goto err;

    /* Check that the provider created the OIDs/NIDs we expected */
    sigalgnid = OBJ_txt2nid(SIGALG_OID);
    if (!TEST_int_ne(sigalgnid, NID_undef)
            || !TEST_true(OBJ_find_sigid_algs(sigalgnid, &digestnid, &signid))
            || !TEST_int_ne(digestnid, NID_undef)
            || !TEST_int_ne(signid, NID_undef)
            || !TEST_int_eq(digestnid, OBJ_sn2nid(DIGEST_SN))
            || !TEST_int_eq(signid, OBJ_ln2nid(SIG_LN)))
        goto err;

    testresult = 1;
 err:
    OSSL_PROVIDER_unload(objprov);
    OSSL_LIB_CTX_free(libctx);
    return testresult;
}

int setup_tests(void)
{

    ADD_TEST(obj_create_test);

    return 1;
}
