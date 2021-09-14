/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* The defines in core_dispatch.h are part of the public API and should not
 * change between versions.  A failure in this test indicates an attempt
 * to do this.
 */

#include <openssl/core_dispatch.h>
#include "testutil.h"

static int dispatch_core_function(void)
{
    return TEST_int_eq(OSSL_FUNC_CORE_GETTABLE_PARAMS,            1)
           && TEST_int_eq(OSSL_FUNC_CORE_GET_PARAMS,              2)
           && TEST_int_eq(OSSL_FUNC_CORE_THREAD_START,            3)
           && TEST_int_eq(OSSL_FUNC_CORE_GET_LIBCTX,              4)
           && TEST_int_eq(OSSL_FUNC_CORE_NEW_ERROR,               5)
           && TEST_int_eq(OSSL_FUNC_CORE_SET_ERROR_DEBUG,         6)
           && TEST_int_eq(OSSL_FUNC_CORE_VSET_ERROR,              7)
           && TEST_int_eq(OSSL_FUNC_CORE_SET_ERROR_MARK,          8)
           && TEST_int_eq(OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK,   9)
           && TEST_int_eq(OSSL_FUNC_CORE_POP_ERROR_TO_MARK,      10)
           && TEST_int_eq(OSSL_FUNC_CORE_OBJ_ADD_SIGID,          11)
           && TEST_int_eq(OSSL_FUNC_CORE_OBJ_CREATE,             12)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_MALLOC,               20)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_ZALLOC,               21)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_FREE,                 22)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_CLEAR_FREE,           23)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_REALLOC,              24)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_CLEAR_REALLOC,        25)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_SECURE_MALLOC,        26)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_SECURE_ZALLOC,        27)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_SECURE_FREE,          28)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE,    29)
           && TEST_int_eq(OSSL_FUNC_CRYPTO_SECURE_ALLOCATED,     30)
           && TEST_int_eq(OSSL_FUNC_OPENSSL_CLEANSE,             31)
           && TEST_int_eq(OSSL_FUNC_BIO_NEW_FILE,                40)
           && TEST_int_eq(OSSL_FUNC_BIO_NEW_MEMBUF,              41)
           && TEST_int_eq(OSSL_FUNC_BIO_READ_EX,                 42)
           && TEST_int_eq(OSSL_FUNC_BIO_WRITE_EX,                43)
           && TEST_int_eq(OSSL_FUNC_BIO_UP_REF,                  44)
           && TEST_int_eq(OSSL_FUNC_BIO_FREE,                    45)
           && TEST_int_eq(OSSL_FUNC_BIO_VPRINTF,                 46)
           && TEST_int_eq(OSSL_FUNC_BIO_VSNPRINTF,               47)
           && TEST_int_eq(OSSL_FUNC_BIO_PUTS,                    48)
           && TEST_int_eq(OSSL_FUNC_BIO_GETS,                    49)
           && TEST_int_eq(OSSL_FUNC_BIO_CTRL,                    50)
           && TEST_int_eq(OSSL_FUNC_SELF_TEST_CB,               100)
           && TEST_int_eq(OSSL_FUNC_GET_ENTROPY,                101)
           && TEST_int_eq(OSSL_FUNC_CLEANUP_ENTROPY,            102)
           && TEST_int_eq(OSSL_FUNC_GET_NONCE,                  103)
           && TEST_int_eq(OSSL_FUNC_CLEANUP_NONCE,              104)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB,   105)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB, 106)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_NAME,                107)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX,   108)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_GET0_DISPATCH,       109)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_UP_REF,              110)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_FREE,                111);
}

static int dispatch_provider_function(void)
{
    return TEST_int_eq(OSSL_FUNC_PROVIDER_TEARDOWN,              1024)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,    1025)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_GET_PARAMS,         1026)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_QUERY_OPERATION,    1027)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_UNQUERY_OPERATION,  1028)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, 1029)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_GET_CAPABILITIES,   1030)
           && TEST_int_eq(OSSL_FUNC_PROVIDER_SELF_TEST,          1031);
}

static int dispatch_operations(void)
{
    return TEST_int_eq(OSSL_OP_DIGEST,                            1)
           && TEST_int_eq(OSSL_OP_CIPHER,                         2)
           && TEST_int_eq(OSSL_OP_MAC,                            3)
           && TEST_int_eq(OSSL_OP_KDF,                            4)
           && TEST_int_eq(OSSL_OP_RAND,                           5)
           && TEST_int_eq(OSSL_OP_KEYMGMT,                       10)
           && TEST_int_eq(OSSL_OP_KEYEXCH,                       11)
           && TEST_int_eq(OSSL_OP_SIGNATURE,                     12)
           && TEST_int_eq(OSSL_OP_ASYM_CIPHER,                   13)
           && TEST_int_eq(OSSL_OP_KEM,                           14)
           && TEST_int_eq(OSSL_OP_ENCODER,                       20)
           && TEST_int_eq(OSSL_OP_DECODER,                       21)
           && TEST_int_eq(OSSL_OP_STORE,                         22)
           && TEST_int_eq(OSSL_OP__HIGHEST,                      22);
}

static int dispatch_digests(void)
{
    return TEST_int_eq(OSSL_FUNC_DIGEST_NEWCTX,                   1)
           && TEST_int_eq(OSSL_FUNC_DIGEST_INIT,                  2)
           && TEST_int_eq(OSSL_FUNC_DIGEST_UPDATE,                3)
           && TEST_int_eq(OSSL_FUNC_DIGEST_FINAL,                 4)
           && TEST_int_eq(OSSL_FUNC_DIGEST_DIGEST,                5)
           && TEST_int_eq(OSSL_FUNC_DIGEST_FREECTX,               6)
           && TEST_int_eq(OSSL_FUNC_DIGEST_DUPCTX,                7)
           && TEST_int_eq(OSSL_FUNC_DIGEST_GET_PARAMS,            8)
           && TEST_int_eq(OSSL_FUNC_DIGEST_SET_CTX_PARAMS,        9)
           && TEST_int_eq(OSSL_FUNC_DIGEST_GET_CTX_PARAMS,       10)
           && TEST_int_eq(OSSL_FUNC_DIGEST_GETTABLE_PARAMS,      11)
           && TEST_int_eq(OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,  12)
           && TEST_int_eq(OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,  13);
}

static int dispatch_ciphers(void)
{
    return TEST_int_eq(OSSL_FUNC_CIPHER_NEWCTX,                   1)
           && TEST_int_eq(OSSL_FUNC_CIPHER_ENCRYPT_INIT,          2)
           && TEST_int_eq(OSSL_FUNC_CIPHER_DECRYPT_INIT,          3)
           && TEST_int_eq(OSSL_FUNC_CIPHER_UPDATE,                4)
           && TEST_int_eq(OSSL_FUNC_CIPHER_FINAL,                 5)
           && TEST_int_eq(OSSL_FUNC_CIPHER_CIPHER,                6)
           && TEST_int_eq(OSSL_FUNC_CIPHER_FREECTX,               7)
           && TEST_int_eq(OSSL_FUNC_CIPHER_DUPCTX,                8)
           && TEST_int_eq(OSSL_FUNC_CIPHER_GET_PARAMS,            9)
           && TEST_int_eq(OSSL_FUNC_CIPHER_GET_CTX_PARAMS,       10)
           && TEST_int_eq(OSSL_FUNC_CIPHER_SET_CTX_PARAMS,       11)
           && TEST_int_eq(OSSL_FUNC_CIPHER_GETTABLE_PARAMS,      12)
           && TEST_int_eq(OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,  13)
           && TEST_int_eq(OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,  14);
}

static int dispatch_macs(void)
{
    return TEST_int_eq(OSSL_FUNC_MAC_NEWCTX,                      1)
           && TEST_int_eq(OSSL_FUNC_MAC_DUPCTX,                   2)
           && TEST_int_eq(OSSL_FUNC_MAC_FREECTX,                  3)
           && TEST_int_eq(OSSL_FUNC_MAC_INIT,                     4)
           && TEST_int_eq(OSSL_FUNC_MAC_UPDATE,                   5)
           && TEST_int_eq(OSSL_FUNC_MAC_FINAL,                    6)
           && TEST_int_eq(OSSL_FUNC_MAC_GET_PARAMS,               7)
           && TEST_int_eq(OSSL_FUNC_MAC_GET_CTX_PARAMS,           8)
           && TEST_int_eq(OSSL_FUNC_MAC_SET_CTX_PARAMS,           9)
           && TEST_int_eq(OSSL_FUNC_MAC_GETTABLE_PARAMS,         10)
           && TEST_int_eq(OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,     11)
           && TEST_int_eq(OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,     12);
}

static int dispatch_kdfs(void)
{
    return TEST_int_eq(OSSL_FUNC_KDF_NEWCTX,                      1)
           && TEST_int_eq(OSSL_FUNC_KDF_DUPCTX,                   2)
           && TEST_int_eq(OSSL_FUNC_KDF_FREECTX,                  3)
           && TEST_int_eq(OSSL_FUNC_KDF_RESET,                    4)
           && TEST_int_eq(OSSL_FUNC_KDF_DERIVE,                   5)
           && TEST_int_eq(OSSL_FUNC_KDF_GETTABLE_PARAMS,          6)
           && TEST_int_eq(OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,      7)
           && TEST_int_eq(OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,      8)
           && TEST_int_eq(OSSL_FUNC_KDF_GET_PARAMS,               9)
           && TEST_int_eq(OSSL_FUNC_KDF_GET_CTX_PARAMS,          10)
           && TEST_int_eq(OSSL_FUNC_KDF_SET_CTX_PARAMS,          11);
}

static int dispatch_rands(void)
{
    return TEST_int_eq(OSSL_FUNC_RAND_NEWCTX,                     1)
           && TEST_int_eq(OSSL_FUNC_RAND_FREECTX,                 2)
           && TEST_int_eq(OSSL_FUNC_RAND_INSTANTIATE,             3)
           && TEST_int_eq(OSSL_FUNC_RAND_UNINSTANTIATE,           4)
           && TEST_int_eq(OSSL_FUNC_RAND_GENERATE,                5)
           && TEST_int_eq(OSSL_FUNC_RAND_RESEED,                  6)
           && TEST_int_eq(OSSL_FUNC_RAND_NONCE,                   7)
           && TEST_int_eq(OSSL_FUNC_RAND_ENABLE_LOCKING,          8)
           && TEST_int_eq(OSSL_FUNC_RAND_LOCK,                    9)
           && TEST_int_eq(OSSL_FUNC_RAND_UNLOCK,                 10)
           && TEST_int_eq(OSSL_FUNC_RAND_GETTABLE_PARAMS,        11)
           && TEST_int_eq(OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,    12)
           && TEST_int_eq(OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,    13)
           && TEST_int_eq(OSSL_FUNC_RAND_GET_PARAMS,             14)
           && TEST_int_eq(OSSL_FUNC_RAND_GET_CTX_PARAMS,         15)
           && TEST_int_eq(OSSL_FUNC_RAND_SET_CTX_PARAMS,         16)
           && TEST_int_eq(OSSL_FUNC_RAND_VERIFY_ZEROIZATION,     17)
           && TEST_int_eq(OSSL_FUNC_RAND_GET_SEED,               18)
           && TEST_int_eq(OSSL_FUNC_RAND_CLEAR_SEED,             19);
}

static int dispatch_keymgmts(void)
{
    return TEST_int_eq(OSSL_FUNC_KEYMGMT_NEW,                      1)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GEN_INIT,              2)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,      3)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,        4)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,   5)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GEN,                   6)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GEN_CLEANUP,           7)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_LOAD,                  8)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_FREE,                 10)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GET_PARAMS,           11)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,      12)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_SET_PARAMS,           13)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,      14)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, 20)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_HAS,                  21)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_VALIDATE,             22)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_MATCH,                23)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_IMPORT,               40)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         41)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_EXPORT,               42)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         43)
           && TEST_int_eq(OSSL_FUNC_KEYMGMT_DUP,                  44);
}

static int dispatch_keyexchs(void)
{
    return TEST_int_eq(OSSL_FUNC_KEYEXCH_NEWCTX,                  1)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_INIT,                 2)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_DERIVE,               3)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_SET_PEER,             4)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_FREECTX,              5)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_DUPCTX,               6)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,       7)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,  8)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,       9)
           && TEST_int_eq(OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, 10);
}

static int dispatch_signatures(void)
{
    return TEST_int_eq(OSSL_FUNC_SIGNATURE_NEWCTX,                     1)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_SIGN_INIT,               2)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_SIGN,                    3)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_VERIFY_INIT,             4)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_VERIFY,                  5)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,     6)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,          7)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,        8)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,      9)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,      10)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_SIGN,            11)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,     12)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,   13)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,    14)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,          15)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_FREECTX,                16)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_DUPCTX,                 17)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,         18)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,    19)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,         20)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,    21)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,      22)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, 23)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,      24)
           && TEST_int_eq(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, 25);
}

static int dispatch_asym_ciphers(void)
{
    return TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_NEWCTX,                   1)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,          2)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_ENCRYPT,               3)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,          4)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_DECRYPT,               5)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_FREECTX,               6)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_DUPCTX,                7)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,        8)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,   9)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,       10)
           && TEST_int_eq(OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,  11);
}

static int dispatch_kems(void)
{
    return TEST_int_eq(OSSL_FUNC_KEM_NEWCTX,                      1)
           && TEST_int_eq(OSSL_FUNC_KEM_ENCAPSULATE_INIT,         2)
           && TEST_int_eq(OSSL_FUNC_KEM_ENCAPSULATE,              3)
           && TEST_int_eq(OSSL_FUNC_KEM_DECAPSULATE_INIT,         4)
           && TEST_int_eq(OSSL_FUNC_KEM_DECAPSULATE,              5)
           && TEST_int_eq(OSSL_FUNC_KEM_FREECTX,                  6)
           && TEST_int_eq(OSSL_FUNC_KEM_DUPCTX,                   7)
           && TEST_int_eq(OSSL_FUNC_KEM_GET_CTX_PARAMS,           8)
           && TEST_int_eq(OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,      9)
           && TEST_int_eq(OSSL_FUNC_KEM_SET_CTX_PARAMS,          10)
           && TEST_int_eq(OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,     11);
}

static int dispatch_encoders(void)
{
    return TEST_int_eq(OSSL_FUNC_ENCODER_NEWCTX,                  1)
           && TEST_int_eq(OSSL_FUNC_ENCODER_FREECTX,              2)
           && TEST_int_eq(OSSL_FUNC_ENCODER_GET_PARAMS,           3)
           && TEST_int_eq(OSSL_FUNC_ENCODER_GETTABLE_PARAMS,      4)
           && TEST_int_eq(OSSL_FUNC_ENCODER_SET_CTX_PARAMS,       5)
           && TEST_int_eq(OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,  6)
           && TEST_int_eq(OSSL_FUNC_ENCODER_DOES_SELECTION,      10)
           && TEST_int_eq(OSSL_FUNC_ENCODER_ENCODE,              11)
           && TEST_int_eq(OSSL_FUNC_ENCODER_IMPORT_OBJECT,       20)
           && TEST_int_eq(OSSL_FUNC_ENCODER_FREE_OBJECT,         21);
}

static int dispatch_decoders(void)
{
    return TEST_int_eq(OSSL_FUNC_DECODER_NEWCTX,                  1)
           && TEST_int_eq(OSSL_FUNC_DECODER_FREECTX,              2)
           && TEST_int_eq(OSSL_FUNC_DECODER_GET_PARAMS,           3)
           && TEST_int_eq(OSSL_FUNC_DECODER_GETTABLE_PARAMS,      4)
           && TEST_int_eq(OSSL_FUNC_DECODER_SET_CTX_PARAMS,       5)
           && TEST_int_eq(OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,  6)
           && TEST_int_eq(OSSL_FUNC_DECODER_DOES_SELECTION,      10)
           && TEST_int_eq(OSSL_FUNC_DECODER_DECODE,              11)
           && TEST_int_eq(OSSL_FUNC_DECODER_EXPORT_OBJECT,       20);
}

static int dispatch_stores(void)
{
    return TEST_int_eq(OSSL_FUNC_STORE_OPEN,                      1)
           && TEST_int_eq(OSSL_FUNC_STORE_ATTACH,                 2)
           && TEST_int_eq(OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,    3)
           && TEST_int_eq(OSSL_FUNC_STORE_SET_CTX_PARAMS,         4)
           && TEST_int_eq(OSSL_FUNC_STORE_LOAD,                   5)
           && TEST_int_eq(OSSL_FUNC_STORE_EOF,                    6)
           && TEST_int_eq(OSSL_FUNC_STORE_CLOSE,                  7)
           && TEST_int_eq(OSSL_FUNC_STORE_EXPORT_OBJECT,          8);
}

int setup_tests(void)
{
    ADD_TEST(dispatch_core_function);
    ADD_TEST(dispatch_provider_function);
    ADD_TEST(dispatch_operations);
    ADD_TEST(dispatch_digests);
    ADD_TEST(dispatch_ciphers);
    ADD_TEST(dispatch_macs);
    ADD_TEST(dispatch_kdfs);
    ADD_TEST(dispatch_rands);
    ADD_TEST(dispatch_keymgmts);
    ADD_TEST(dispatch_keyexchs);
    ADD_TEST(dispatch_signatures);
    ADD_TEST(dispatch_asym_ciphers);
    ADD_TEST(dispatch_kems);
    ADD_TEST(dispatch_encoders);
    ADD_TEST(dispatch_decoders);
    ADD_TEST(dispatch_stores);
    return 1;
}
