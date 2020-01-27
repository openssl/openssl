/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* TODO(3.0): Needed for dummy_evp_call(). To be removed */
#include <openssl/sha.h>
#include <openssl/rand_drbg.h>
#include <openssl/ec.h>
#include <openssl/fips_names.h>

#include "internal/cryptlib.h"
#include "internal/property.h"
#include "internal/nelem.h"
#include "internal/param_build.h"
#include "crypto/evp.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/provider_util.h"
#include "self_test.h"

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "fips=yes", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

extern OSSL_core_thread_start_fn *c_thread_start;

/*
 * TODO(3.0): Should these be stored in the provider side provctx? Could they
 * ever be different from one init to the next? Unfortunately we can't do this
 * at the moment because c_put_error/c_add_error_vdata do not provide
 * us with the OPENSSL_CTX as a parameter.
 */

static SELF_TEST_POST_PARAMS selftest_params;

/* Functions provided by the core */
static OSSL_core_gettable_params_fn *c_gettable_params;
static OSSL_core_get_params_fn *c_get_params;
OSSL_core_thread_start_fn *c_thread_start;
static OSSL_core_new_error_fn *c_new_error;
static OSSL_core_set_error_debug_fn *c_set_error_debug;
static OSSL_core_vset_error_fn *c_vset_error;
static OSSL_core_set_error_mark_fn *c_set_error_mark;
static OSSL_core_clear_last_error_mark_fn *c_clear_last_error_mark;
static OSSL_core_pop_error_to_mark_fn *c_pop_error_to_mark;
static OSSL_CRYPTO_malloc_fn *c_CRYPTO_malloc;
static OSSL_CRYPTO_zalloc_fn *c_CRYPTO_zalloc;
static OSSL_CRYPTO_free_fn *c_CRYPTO_free;
static OSSL_CRYPTO_clear_free_fn *c_CRYPTO_clear_free;
static OSSL_CRYPTO_realloc_fn *c_CRYPTO_realloc;
static OSSL_CRYPTO_clear_realloc_fn *c_CRYPTO_clear_realloc;
static OSSL_CRYPTO_secure_malloc_fn *c_CRYPTO_secure_malloc;
static OSSL_CRYPTO_secure_zalloc_fn *c_CRYPTO_secure_zalloc;
static OSSL_CRYPTO_secure_free_fn *c_CRYPTO_secure_free;
static OSSL_CRYPTO_secure_clear_free_fn *c_CRYPTO_secure_clear_free;
static OSSL_CRYPTO_secure_allocated_fn *c_CRYPTO_secure_allocated;

typedef struct fips_global_st {
    const OSSL_PROVIDER *prov;
} FIPS_GLOBAL;

static void *fips_prov_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    FIPS_GLOBAL *fgbl = OPENSSL_zalloc(sizeof(*fgbl));

    return fgbl;
}

static void fips_prov_ossl_ctx_free(void *fgbl)
{
    OPENSSL_free(fgbl);
}

static const OPENSSL_CTX_METHOD fips_prov_ossl_ctx_method = {
    fips_prov_ossl_ctx_new,
    fips_prov_ossl_ctx_free,
};


/* Parameters we provide to the core */
static const OSSL_PARAM fips_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

/*
 * Parameters to retrieve from the core provider - required for self testing.
 * NOTE: inside core_get_params() these will be loaded from config items
 * stored inside prov->parameters (except for OSSL_PROV_PARAM_MODULE_FILENAME).
 */
static OSSL_PARAM core_params[] =
{
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_MODULE_FILENAME,
                        selftest_params.module_filename,
                        sizeof(selftest_params.module_filename)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_MODULE_MAC,
                        selftest_params.module_checksum_data,
                        sizeof(selftest_params.module_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_MAC,
                        selftest_params.indicator_checksum_data,
                        sizeof(selftest_params.indicator_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
                        selftest_params.indicator_data,
                        sizeof(selftest_params.indicator_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
                        selftest_params.indicator_version,
                        sizeof(selftest_params.indicator_version)),
    OSSL_PARAM_END
};

/*
 * Convert a string into a bignumber.
 * The array of hex_data is used to get around compilers that dont like
 * strings longer than 509 bytes,
 */
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_DSA)
static int hextobn(const char *hex_data[], BIGNUM **bn)
{
    int ret = 0;
    int i, slen;
    char *str = NULL;

    /* Get the total length of the strings */
    for (slen = 0, i = 0; hex_data[i] != NULL; ++i)
        slen += strlen(hex_data[i]);

    /* Add 1 for the string terminator */
    str = OPENSSL_zalloc(slen + 1);
    if (str == NULL)
        return 0;

    /* join the strings together into 1 buffer */
    for (i = 0; hex_data[i] != NULL; ++i)
        strcat(str, hex_data[i]);

    if (BN_hex2bn(bn, str) <= 0)
        goto err;
    ret = 1;
err:
    OPENSSL_free(str);
    return ret;
}
#endif /* !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_DSA) */

#ifndef OPENSSL_NO_DH
static int hextobin(const char *hex_data[], unsigned char **out, size_t *len)
{
    int ret = 0, sz;
    BIGNUM *bn = NULL;
    unsigned char *buf = NULL;

    if (!hextobn(hex_data, &bn))
        return 0;
    sz = BN_num_bytes(bn);
    buf = OPENSSL_zalloc(sz);
    if (buf == NULL)
        goto err;
    if (BN_bn2binpad(bn, buf, sz) <= 0)
        goto err;

    *out = buf;
    *len = sz;
    buf = NULL; /* Set to NULL so it is not freed */
    ret = 1;
err:
    OPENSSL_free(buf);
    BN_free(bn);
    return ret;
}
#endif

#ifndef OPENSSL_NO_DSA
static int dsa_key_signature_test(OPENSSL_CTX *libctx)
{
    int ret = 0;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    BIGNUM *pub = NULL, *priv = NULL;
    OSSL_PARAM *params = NULL, *params_sig = NULL;
    OSSL_PARAM_BLD bld;
    EVP_PKEY_CTX *sctx = NULL, *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char sig[64];
    size_t siglen;

    static const unsigned char dgst[SHA256_DIGEST_LENGTH] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81,
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
    };
    /* dsa 2048 */
    static const char *dsa_p_hex[] = {
        "a29b8872ce8b8423b7d5d21d4b02f57e03e9e6b8a258dc16611ba098ab543415"
        "e415f156997a3ee236658fa093260de3ad422e05e046f9ec29161a375f0eb4ef"
        "fcef58285c5d39ed425d7a62ca12896c4a92cb1946f2952a48133f07da364d1b"
        "df6b0f7139983e693c80059b0eacd1479ba9f2857754ede75f112b07ebbf3534",
        "8bbf3e01e02f2d473de39453f99dd2367541caca3ba01166343d7b5b58a37bd1"
        "b7521db2f13b86707132fe09f4cd09dc1618fa3401ebf9cc7b19fa94aa472088"
        "133d6cb2d35c1179c8c8ff368758d507d9f9a17d46c110fe3144ce9b022b42e4"
        "19eb4f5388613bfc3e26241a432e8706bc58ef76117278deab6cf692618291b7",
         NULL
    };
    static const char *dsa_q_hex[] = {
        "a3bfd9ab7884794e383450d5891dc18b65157bdcfcdac51518902867",
        NULL
    };
    static const char *dsa_g_hex[] = {
        "6819278869c7fd3d2d7b77f77e8150d9ad433bea3ba85efc80415aa3545f78f7"
        "2296f06cb19ceda06c94b0551cfe6e6f863e31d1de6eed7dab8b0c9df231e084"
        "34d1184f91d033696bb382f8455e9888f5d31d4784ec40120246f4bea61794bb"
        "a5866f09746463bdf8e9e108cd9529c3d0f6df80316e2e70aaeb1b26cdb8ad97",
        "bc3d287e0b8d616c42e65b87db20deb7005bc416747a6470147a68a7820388eb"
        "f44d52e0628af9cf1b7166d03465f35acc31b6110c43dabc7c5d591e671eaf7c"
        "252c1c145336a1a4ddf13244d55e835680cab2533b82df2efe55ec18c1e6cd00"
        "7bb089758bb17c2cbe14441bd093ae66e5976d53733f4fa3269701d31d23d467",
        NULL
    };
    static const char *dsa_pub_hex[] = {
        "a012b3b170b307227957b7ca2061a816ac7a2b3d9ae995a5119c385b603bf6f6"
        "c5de4dc5ecb5dfa4a41c68662eb25b638b7e2620ba898d07da6c4991e76cc0ec"
        "d1ad3421077067e47c18f58a92a72ad43199ecb7bd84e7d3afb9019f0e9dd0fb"
        "aa487300b13081e33c902876436f7b03c345528481d362815e24fe59dac5ac34",
        "660d4c8a76cb99a7c7de93eb956cd6bc88e58d901034944a094b01803a43c672"
        "b9688c0e01d8f4fc91c62a3f88021f7bd6a651b1a88f43aa4ef27653d12bf8b7"
        "099fdf6b461082f8e939107bfd2f7210087d326c375200f1f51e7e74a3413190"
        "1bcd0863521ff8d676c48581868736c5e51b16a4e39215ea0b17c4735974c516",
        NULL
    };
    static const char *dsa_priv_hex[] = {
        "6ccaeef6d73b4e80f11c17b8e9627c036635bac39423505e407e5cb7",
        NULL
    };

    if (!hextobn(dsa_p_hex, &p)
        || !hextobn(dsa_q_hex, &q)
        || !hextobn(dsa_g_hex, &g)
        || !hextobn(dsa_pub_hex, &pub)
        || !hextobn(dsa_priv_hex, &priv))
        goto err;

    ossl_param_bld_init(&bld);
    if (!ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_P, p)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_Q, q)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_G, g)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_PUB_KEY, pub)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_PRIV_KEY, priv))
        goto err;
    params = ossl_param_bld_to_param(&bld);

    /* Create a EVP_PKEY_CTX to load the DSA key into */
    kctx = EVP_PKEY_CTX_new_from_name(libctx, SN_dsa, "");
    if (kctx == NULL || params == NULL)
        goto err;
    if (EVP_PKEY_key_fromdata_init(kctx) <= 0
        || EVP_PKEY_fromdata(kctx, &pkey, params) <= 0)
        goto err;

    /* Create a EVP_PKEY_CTX to use for the signing operation */
    sctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (sctx == NULL
        || EVP_PKEY_sign_init(sctx) <= 0)
        goto err;

    /* set signature parameters */
    ossl_param_bld_init(&bld);
    if (!ossl_param_bld_push_utf8_string(&bld, OSSL_SIGNATURE_PARAM_DIGEST,
                                         SN_sha256,strlen(SN_sha256) + 1))
        goto err;
    params_sig = ossl_param_bld_to_param(&bld);
    if (EVP_PKEY_CTX_set_params(sctx, params_sig) <= 0)
        goto err;

    if (EVP_PKEY_sign(sctx, sig, &siglen, dgst, sizeof(dgst)) <= 0
        || EVP_PKEY_verify_init(sctx) <= 0
        || EVP_PKEY_verify(sctx, sig, siglen, dgst, sizeof(dgst)) <= 0)
        goto err;
    ret = 1;
err:
    ossl_param_bld_free(params);
    ossl_param_bld_free(params_sig);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
    return ret;
}
#endif /* OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DH
static int dh_key_exchange_test(OPENSSL_CTX *libctx)
{
    int ret = 0;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    BIGNUM *pub = NULL, *priv = NULL, *pub_peer = NULL;
    unsigned char *kat_secret = NULL;
    EVP_PKEY_CTX *kactx = NULL, *dctx = NULL;
    EVP_PKEY *pkey = NULL, *peerkey = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM *params_peer = NULL;
    unsigned char secret[256];
    size_t secret_len, kat_secret_len = 0;
    OSSL_PARAM_BLD bld;

    /* DH KAT */
    static const char *dh_p_hex[] = {
        "dcca1511b2313225f52116e1542789e001f0425bccc7f366f7406407f1c9fa8b"
        "e610f1778bb170be39dbb76f85bf24ce6880adb7629f7c6d015e61d43fa3ee4d"
        "e185f2cfd041ffde9d418407e15138bb021daeb35f762d1782acc658d32bd4b0"
        "232c927dd38fa097b3d1859fa8acafb98f066608fc644ec7ddb6f08599f92ac1",
        "b59825da8432077def695646063c20823c9507ab6f0176d4730d990dbbe6361c"
        "d8b2b94d3d2f329b82099bd661f42950f403df3ede62a33188b02798ba823f44"
        "b946fe9df677a0c5a1238eaa97b70f80da8cac88e092b1127060ffbf45579994"
        "011dc2faa5e7f6c76245e1cc312231c17d1ca6b19007ef0db99f9cb60e1d5f69",
        NULL
    };
    static const char *dh_q_hex[] = {
        "898b226717ef039e603e82e5c7afe48374ac5f625c54f1ea11acb57d",
        NULL
    };
    static const char *dh_g_hex[] = {
        "5ef7b88f2df60139351dfbfe1266805fdf356cdfd13a4da0050c7ede"
        "246df59f6abf96ade5f2b28ffe88d6bce7f7894a3d535fc82126ddd4"
        "24872e16b838df8c51e9016f889c7c203e98a8b631f9c72563d38a49"
        "589a0753d358e783318cefd9677c7b2dbb77d6dce2a1963795ca64b9",
        "2d1c9aac6d0e8d431de5e50060dff78689c9eca1c1248c16ed09c7ad",
        "412a17406d2b525aa1cabb237b9734ec7b8ce3fae02f29c5efed30d6"
        "9187da109c2c9fe2aadbb0c22af54c616655000c431c6b4a379763b0"
        "a91658efc84e8b06358c8b4f213710fd10172cf39b830c2dd84a0c8a"
        "b82516ecab995fa4215e023e4ecf8074c39d6c88b70d1ee4e96fdc20",
        "ea115c32",
        NULL
    };
    static const char *dh_priv_hex[] = {
        "1433e0b5a917b60a3023f2f8aa2c2d70d2968aba9aeac81540b8fce6",
        NULL
    };
    static const char *dh_pub_hex[] = {
        "95dd338d29e5710492b918317b72a36936e1951a2ee5a5591699c048"
        "6d0d4f9bdd6d5a3f6b98890c62b37652d36e712111e68a7355372506"
        "99efe330537391fbc2c548bc5ac3e5b23386c3eef5eb43c099d70a52"
        "02687e83964248fca91f40908e8fb3319315f6d2606d7f7cd52cc6e7",
        "c5843afb22519cf0f0f9d3a0a4e8c88899efede7364351fb6a363ee7"
        "17e5445adab4c931a6483997b87dad83677e4d1d3a7775e0f6d00fdf"
        "73c7ad801e665a0e5a796d0a0380a19fa182efc8a04f5e4db90d1a86"
        "37f95db16436bdc8f3fc096c4ff7f234be8fef479ac4b0dc4b77263e",
        "07d9959de0f1bf3f0ae3d9d50e4b89c99e3ea1217343dd8c6581acc4"
        "959c91d3",
        NULL
    };
    static const char *dh_peer_pub_hex[] = {
        "1fc1da341d1a846a96b7be24340f877dd010aa0356d5ad58aae9c7b0"
        "8f749a32235110b5d88eb5dbfa978d27ecc530f02d3114005b64b1c0"
        "e024cb8ae21698bca9e60d42808622f181c56e1de7a96e6efee9d665"
        "67e91b977042c7e3d0448f05fb77f522b9bfc8d33cc3c31ed3b31f0f",
        "ecb6db4f6ea311e77afdbcd47aee1bb150f216873578fb96468e8f9f"
        "3de8efbfce75624b1df05322a34f1463e839e8984c4ad0a96e1ac842"
        "e5318cc23c062a8ca171b8d575980dde7fc56f1536523820d43192bf"
        "d51e8e228978aca5b94472f339caeb9931b42be301268bc99789c9b2",
        "5571c3c0e4cb3f007f1a511cbb53c8519cdd1302abca6c0f34f96739"
        "f17ff48b",
        NULL
    };
    static const char *dh_secret_exptd_hex[] = {
        "08ff33bb2ecff49a7d4a7912aeb1bb6ab511641b4a76770c8cc1bcc2"
        "33343dfe700d11813d2c9ed23b211ca9e8786921edca283c68b16153"
        "fa01e91ab82c90ddab4a95816770a98710e14c92ab83b6e46e1e426e"
        "e852430d6187daa3720a6bcd73235c6b0f941f3364f50420551a4bfe",
        "afe2bc438505a59a4a40daca7a895a73db575c74c13a23ad8832957d"
        "582d38f0a6165fb0d7e9b8799e42fd3220e332e98185a0c9429757b2"
        "d0d02c17dbaa1ff6ed93d7e73e241eaed90caf394d2bc6570f18c81f"
        "2be5d01a2ca99ff142b5d963f9f500325e7556f95849b3ffc7479486",
        "be1d4596a3106bd5cb4f61c57ec5f100fb7a0c82a10b82526a97d1d9"
        "7d98eaf6",
        NULL
    };

    if (!hextobn(dh_p_hex, &p)
        || !hextobn(dh_q_hex, &q)
        || !hextobn(dh_g_hex, &g)
        || !hextobn(dh_pub_hex, &pub)
        || !hextobn(dh_priv_hex, &priv)
        || !hextobn(dh_peer_pub_hex, &pub_peer)
        || !hextobin(dh_secret_exptd_hex, &kat_secret, &kat_secret_len))
        goto err;

    ossl_param_bld_init(&bld);
    if (!ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_P, p)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_Q, q)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_G, g)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_PUB_KEY, pub)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_PRIV_KEY, priv))
        goto err;
    params = ossl_param_bld_to_param(&bld);

    ossl_param_bld_init(&bld);
    if (!ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_P, p)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_Q, q)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_FFC_G, g)
        || !ossl_param_bld_push_BN(&bld, OSSL_PKEY_PARAM_PUB_KEY, pub_peer))
        goto err;

    params_peer = ossl_param_bld_to_param(&bld);
    if (params == NULL || params_peer == NULL)
        goto err;

    /* Create a EVP_PKEY_CTX to load the DH keys into */
    kactx = EVP_PKEY_CTX_new_from_name(libctx, "DH", "");
    if (kactx == NULL)
        goto err;
    if (EVP_PKEY_key_fromdata_init(kactx) <= 0
        || EVP_PKEY_fromdata(kactx, &pkey, params) <= 0)
        goto err;
    if (EVP_PKEY_key_fromdata_init(kactx) <= 0
        || EVP_PKEY_fromdata(kactx, &peerkey, params_peer) <= 0)
        goto err;

    /* Create a EVP_PKEY_CTX to perform key derivation */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (dctx == NULL)
        goto err;

    if (EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peerkey) <= 0
        || EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        goto err;

    if (secret_len != kat_secret_len
        || memcmp(secret, kat_secret, secret_len) != 0)
        goto err;
    ret = 1;
err:
    ossl_param_bld_free(params_peer);
    ossl_param_bld_free(params);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(pub);
    BN_free(priv);
    BN_free(pub_peer);
    OPENSSL_free(kat_secret);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(kactx);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}
#endif /* OPENSSL_NO_DH */

/* TODO(3.0): To be removed */
static int dummy_evp_call(void *provctx)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF2, NULL);
    unsigned char dgst[SHA256_DIGEST_LENGTH];
    unsigned int dgstlen;
    int ret = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *a = NULL, *b = NULL;
    unsigned char randbuf[128];
    RAND_DRBG *drbg = OPENSSL_CTX_get0_public_drbg(libctx);
#ifndef OPENSSL_NO_EC
    EC_KEY *key = NULL;
#endif

    static const char msg[] = "Hello World!";
    static const unsigned char exptd[] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81,
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
    };

    if (ctx == NULL || sha256 == NULL || drbg == NULL || kdf == NULL)
        goto err;

    if (!EVP_DigestInit_ex(ctx, sha256, NULL))
        goto err;
    if (!EVP_DigestUpdate(ctx, msg, sizeof(msg) - 1))
        goto err;
    if (!EVP_DigestFinal(ctx, dgst, &dgstlen))
        goto err;
    if (dgstlen != sizeof(exptd) || memcmp(dgst, exptd, sizeof(exptd)) != 0)
        goto err;

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;
    BN_CTX_start(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    if (b == NULL)
        goto err;
    BN_zero(a);
    if (!BN_one(b)
        || !BN_add(a, a, b)
        || BN_cmp(a, b) != 0)
        goto err;

    if (RAND_DRBG_bytes(drbg, randbuf, sizeof(randbuf)) <= 0)
        goto err;

    if (!BN_rand_ex(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, bnctx))
        goto err;

#ifndef OPENSSL_NO_EC
    /* Do some dummy EC calls */
    key = EC_KEY_new_by_curve_name_ex(libctx, NID_X9_62_prime256v1);
    if (key == NULL)
        goto err;

    if (!EC_KEY_generate_key(key))
        goto err;
#endif

#ifndef OPENSSL_NO_DSA
    if (!dsa_key_signature_test(libctx))
        goto err;
#endif

#ifndef OPENSSL_NO_DH
    if (!dh_key_exchange_test(libctx))
        goto err;
#endif /* OPENSSL_NO_DH */

    ret = 1;
 err:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);

    EVP_KDF_free(kdf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(sha256);

#ifndef OPENSSL_NO_EC
    EC_KEY_free(key);
#endif
    return ret;
}

static const OSSL_PARAM *fips_gettable_params(const OSSL_PROVIDER *prov)
{
    return fips_param_types;
}

static int fips_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL FIPS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

/* FIPS specific version of the function of the same name in provlib.c */
const char *ossl_prov_util_nid_to_name(int nid)
{
    /* We don't have OBJ_nid2n() in FIPS_MODE so we have an explicit list */

    switch (nid) {
    /* Digests */
    case NID_sha1:
        return "SHA1";
    case NID_sha224:
        return "SHA-224";
    case NID_sha256:
        return "SHA-256";
    case NID_sha384:
        return "SHA-384";
    case NID_sha512:
        return "SHA-512";
    case NID_sha512_224:
        return "SHA-512/224";
    case NID_sha512_256:
        return "SHA-512/256";
    case NID_sha3_224:
        return "SHA3-224";
    case NID_sha3_256:
        return "SHA3-256";
    case NID_sha3_384:
        return "SHA3-384";
    case NID_sha3_512:
        return "SHA3-512";

    /* Ciphers */
    case NID_aes_256_ecb:
        return "AES-256-ECB";
    case NID_aes_192_ecb:
        return "AES-192-ECB";
    case NID_aes_128_ecb:
        return "AES-128-ECB";
    case NID_aes_256_cbc:
        return "AES-256-CBC";
    case NID_aes_192_cbc:
        return "AES-192-CBC";
    case NID_aes_128_cbc:
        return "AES-128-CBC";
    case NID_aes_256_ctr:
        return "AES-256-CTR";
    case NID_aes_192_ctr:
        return "AES-192-CTR";
    case NID_aes_128_ctr:
        return "AES-128-CTR";
    case NID_aes_256_xts:
        return "AES-256-XTS";
    case NID_aes_128_xts:
        return "AES-128-XTS";
    case NID_aes_256_gcm:
        return "AES-256-GCM";
    case NID_aes_192_gcm:
        return "AES-192-GCM";
    case NID_aes_128_gcm:
        return "AES-128-GCM";
    case NID_aes_256_ccm:
        return "AES-256-CCM";
    case NID_aes_192_ccm:
        return "AES-192-CCM";
    case NID_aes_128_ccm:
        return "AES-128-CCM";
    case NID_id_aes256_wrap:
        return "AES-256-WRAP";
    case NID_id_aes192_wrap:
        return "AES-192-WRAP";
    case NID_id_aes128_wrap:
        return "AES-128-WRAP";
    case NID_id_aes256_wrap_pad:
        return "AES-256-WRAP-PAD";
    case NID_id_aes192_wrap_pad:
        return "AES-192-WRAP-PAD";
    case NID_id_aes128_wrap_pad:
        return "AES-128-WRAP-PAD";
    case NID_des_ede3_ecb:
        return "DES-EDE3";
    case NID_des_ede3_cbc:
        return "DES-EDE3-CBC";
    case NID_aes_256_cbc_hmac_sha256:
        return "AES-256-CBC-HMAC-SHA256";
    case NID_aes_128_cbc_hmac_sha256:
        return "AES-128-CBC-HMAC-SHA256";
    case NID_aes_256_cbc_hmac_sha1:
        return "AES-256-CBC-HMAC-SHA1";
    case NID_aes_128_cbc_hmac_sha1:
        return "AES-128-CBC-HMAC-SHA1";
    default:
        break;
    }

    return NULL;
}

/*
 * For the algorithm names, we use the following formula for our primary
 * names:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 *
 * We add diverse other names where applicable, such as the names that
 * NIST uses, or that are used for ASN.1 OBJECT IDENTIFIERs, or names
 * we have used historically.
 */
static const OSSL_ALGORITHM fips_digests[] = {
    /* Our primary name:NiST name[:our older names] */
    { "SHA1:SHA-1", "fips=yes", sha1_functions },
    { "SHA2-224:SHA-224:SHA224", "fips=yes", sha224_functions },
    { "SHA2-256:SHA-256:SHA256", "fips=yes", sha256_functions },
    { "SHA2-384:SHA-384:SHA384", "fips=yes", sha384_functions },
    { "SHA2-512:SHA-512:SHA512", "fips=yes", sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", "fips=yes",
      sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", "fips=yes",
      sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", "fips=yes", sha3_224_functions },
    { "SHA3-256", "fips=yes", sha3_256_functions },
    { "SHA3-384", "fips=yes", sha3_384_functions },
    { "SHA3-512", "fips=yes", sha3_512_functions },
    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * KMAC128 and KMAC256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", "fips=yes", keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", "fips=yes", keccak_kmac_256_functions },

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM_CAPABLE fips_ciphers[] = {
    /* Our primary name[:ASN.1 OID name][:our older names] */
    ALG("AES-256-ECB", aes256ecb_functions),
    ALG("AES-192-ECB", aes192ecb_functions),
    ALG("AES-128-ECB", aes128ecb_functions),
    ALG("AES-256-CBC", aes256cbc_functions),
    ALG("AES-192-CBC", aes192cbc_functions),
    ALG("AES-128-CBC", aes128cbc_functions),
    ALG("AES-256-CTR", aes256ctr_functions),
    ALG("AES-192-CTR", aes192ctr_functions),
    ALG("AES-128-CTR", aes128ctr_functions),
    ALG("AES-256-XTS", aes256xts_functions),
    ALG("AES-128-XTS", aes128xts_functions),
    ALG("AES-256-GCM:id-aes256-GCM", aes256gcm_functions),
    ALG("AES-192-GCM:id-aes192-GCM", aes192gcm_functions),
    ALG("AES-128-GCM:id-aes128-GCM", aes128gcm_functions),
    ALG("AES-256-CCM:id-aes256-CCM", aes256ccm_functions),
    ALG("AES-192-CCM:id-aes192-CCM", aes192ccm_functions),
    ALG("AES-128-CCM:id-aes128-CCM", aes128ccm_functions),
    ALG("AES-256-WRAP:id-aes256-wrap:AES256-WRAP", aes256wrap_functions),
    ALG("AES-192-WRAP:id-aes192-wrap:AES192-WRAP", aes192wrap_functions),
    ALG("AES-128-WRAP:id-aes128-wrap:AES128-WRAP", aes128wrap_functions),
    ALG("AES-256-WRAP-PAD:id-aes256-wrap-pad:AES256-WRAP-PAD",
        aes256wrappad_functions),
    ALG("AES-192-WRAP-PAD:id-aes192-wrap-pad:AES192-WRAP-PAD",
        aes192wrappad_functions),
    ALG("AES-128-WRAP-PAD:id-aes128-wrap-pad:AES128-WRAP-PAD",
        aes128wrappad_functions),
    ALGC("AES-128-CBC-HMAC-SHA1", aes128cbc_hmac_sha1_functions,
         cipher_capable_aes_cbc_hmac_sha1),
    ALGC("AES-256-CBC-HMAC-SHA1", aes256cbc_hmac_sha1_functions,
         cipher_capable_aes_cbc_hmac_sha1),
    ALGC("AES-128-CBC-HMAC-SHA256", aes128cbc_hmac_sha256_functions,
         cipher_capable_aes_cbc_hmac_sha256),
    ALGC("AES-256-CBC-HMAC-SHA256", aes256cbc_hmac_sha256_functions,
         cipher_capable_aes_cbc_hmac_sha256),
#ifndef OPENSSL_NO_DES
    ALG("DES-EDE3-ECB:DES-EDE3", tdes_ede3_ecb_functions),
    ALG("DES-EDE3-CBC:DES3", tdes_ede3_cbc_functions),
#endif  /* OPENSSL_NO_DES */
    { { NULL, NULL, NULL }, NULL }
};
static OSSL_ALGORITHM exported_fips_ciphers[OSSL_NELEM(fips_ciphers)];

static const OSSL_ALGORITHM fips_macs[] = {
#ifndef OPENSSL_NO_CMAC
    { "CMAC", "fips=yes", cmac_functions },
#endif
    { "GMAC", "fips=yes", gmac_functions },
    { "HMAC", "fips=yes", hmac_functions },
    { "KMAC-128:KMAC128", "fips=yes", kmac128_functions },
    { "KMAC-256:KMAC256", "fips=yes", kmac256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_kdfs[] = {
    { "HKDF", "fips=yes", kdf_hkdf_functions },
    { "SSKDF", "fips=yes", kdf_sskdf_functions },
    { "PBKDF2", "fips=yes", kdf_pbkdf2_functions },
    { "TLS1-PRF", "fips=yes", kdf_tls1_prf_functions },
    { "KBKDF", "fips=yes", kdf_kbkdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "fips=yes", dh_keyexch_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "fips=yes", dsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "fips=yes", dh_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { "DSA", "fips=yes", dsa_keymgmt_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fips_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return fips_digests;
    case OSSL_OP_CIPHER:
        ossl_prov_cache_exported_algorithms(fips_ciphers, exported_fips_ciphers);
        return exported_fips_ciphers;
    case OSSL_OP_MAC:
        return fips_macs;
    case OSSL_OP_KDF:
        return fips_kdfs;
    case OSSL_OP_KEYMGMT:
        return fips_keymgmt;
    case OSSL_OP_KEYEXCH:
        return fips_keyexch;
    case OSSL_OP_SIGNATURE:
        return fips_signature;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fips_dispatch_table[] = {
    /*
     * To release our resources we just need to free the OPENSSL_CTX so we just
     * use OPENSSL_CTX_free directly as our teardown function
     */
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OPENSSL_CTX_free },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))fips_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fips_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};

/* Functions we provide to ourself */
static const OSSL_DISPATCH intern_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};


int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    FIPS_GLOBAL *fgbl;
    OPENSSL_CTX *ctx;
    OSSL_self_test_cb_fn *stcbfn = NULL;
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_get_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            c_thread_start = OSSL_get_core_thread_start(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_get_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_get_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_get_core_vset_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_MARK:
            c_set_error_mark = OSSL_get_core_set_error_mark(in);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK:
            c_clear_last_error_mark = OSSL_get_core_clear_last_error_mark(in);
            break;
        case OSSL_FUNC_CORE_POP_ERROR_TO_MARK:
            c_pop_error_to_mark = OSSL_get_core_pop_error_to_mark(in);
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            c_CRYPTO_malloc = OSSL_get_CRYPTO_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            c_CRYPTO_zalloc = OSSL_get_CRYPTO_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            c_CRYPTO_free = OSSL_get_CRYPTO_free(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            c_CRYPTO_clear_free = OSSL_get_CRYPTO_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_REALLOC:
            c_CRYPTO_realloc = OSSL_get_CRYPTO_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_REALLOC:
            c_CRYPTO_clear_realloc = OSSL_get_CRYPTO_clear_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            c_CRYPTO_secure_malloc = OSSL_get_CRYPTO_secure_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            c_CRYPTO_secure_zalloc = OSSL_get_CRYPTO_secure_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_FREE:
            c_CRYPTO_secure_free = OSSL_get_CRYPTO_secure_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            c_CRYPTO_secure_clear_free = OSSL_get_CRYPTO_secure_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
            c_CRYPTO_secure_allocated = OSSL_get_CRYPTO_secure_allocated(in);
            break;
        case OSSL_FUNC_BIO_NEW_FILE:
            selftest_params.bio_new_file_cb = OSSL_get_BIO_new_file(in);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            selftest_params.bio_new_buffer_cb = OSSL_get_BIO_new_membuf(in);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            selftest_params.bio_read_ex_cb = OSSL_get_BIO_read_ex(in);
            break;
        case OSSL_FUNC_BIO_FREE:
            selftest_params.bio_free_cb = OSSL_get_BIO_free(in);
            break;
        case OSSL_FUNC_SELF_TEST_CB: {
            stcbfn = OSSL_get_self_test_cb(in);
            break;
        }
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (stcbfn != NULL && c_get_libctx != NULL) {
        stcbfn(c_get_libctx(provider), &selftest_params.event_cb,
               &selftest_params.event_cb_arg);
    }
    else {
        selftest_params.event_cb = NULL;
        selftest_params.event_cb_arg = NULL;
    }

    if (!c_get_params(provider, core_params))
        return 0;

    /*  Create a context. */
    if ((ctx = OPENSSL_CTX_new()) == NULL)
        return 0;
    if ((fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                     &fips_prov_ossl_ctx_method)) == NULL) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    fgbl->prov = provider;

    selftest_params.libctx = PROV_LIBRARY_CONTEXT_OF(ctx);
    if (!SELF_TEST_post(&selftest_params, 0)) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    /*
     * TODO(3.0): Remove me. This is just a dummy call to demonstrate making
     * EVP calls from within the FIPS module.
     */
    if (!dummy_evp_call(ctx)) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    *out = fips_dispatch_table;
    *provctx = ctx;

    return 1;
}

/*
 * The internal init function used when the FIPS module uses EVP to call
 * another algorithm also in the FIPS module. This is a recursive call that has
 * been made from within the FIPS module itself. To make this work, we populate
 * the provider context of this inner instance with the same library context
 * that was used in the EVP call that initiated this recursive call.
 */
OSSL_provider_init_fn fips_intern_provider_init;
int fips_intern_provider_init(const OSSL_PROVIDER *provider,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out,
                              void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *provctx = c_get_libctx(provider);

    /*
     * Safety measure...  we should get the library context that was
     * created up in OSSL_provider_init().
     */
    if (*provctx == NULL)
        return 0;

    *out = intern_dispatch_table;
    return 1;
}

void ERR_new(void)
{
    c_new_error(NULL);
}

void ERR_set_debug(const char *file, int line, const char *func)
{
    c_set_error_debug(NULL, file, line, func);
}

void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
    va_end(args);
}

void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
}

int ERR_set_mark(void)
{
    return c_set_error_mark(NULL);
}

int ERR_clear_last_mark(void)
{
    return c_clear_last_error_mark(NULL);
}

int ERR_pop_to_mark(void)
{
    return c_pop_error_to_mark(NULL);
}

const OSSL_PROVIDER *FIPS_get_provider(OPENSSL_CTX *ctx)
{
    FIPS_GLOBAL *fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                             &fips_prov_ossl_ctx_method);

    if (fgbl == NULL)
        return NULL;

    return fgbl->prov;
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_malloc(num, file, line);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_zalloc(num, file, line);
}

void CRYPTO_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_free(ptr, file, line);
}

void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_clear_free(ptr, num, file, line);
}

void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line)
{
    return c_CRYPTO_realloc(addr, num, file, line);
}

void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
                           const char *file, int line)
{
    return c_CRYPTO_clear_realloc(addr, old_num, num, file, line);
}

void *CRYPTO_secure_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_malloc(num, file, line);
}

void *CRYPTO_secure_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_zalloc(num, file, line);
}

void CRYPTO_secure_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_secure_free(ptr, file, line);
}

void CRYPTO_secure_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_secure_clear_free(ptr, num, file, line);
}

int CRYPTO_secure_allocated(const void *ptr)
{
    return c_CRYPTO_secure_allocated(ptr);
}
