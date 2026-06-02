/*
 * Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/hpke.h>
#include "testutil.h"
#include "hpke.inc"

/* a size to use for stack buffers */
#define OSSL_HPKE_TSTSIZE 512
#define OSSL_HPKE_TST_PUBSIZE 1665

static OSSL_LIB_CTX *testctx = NULL;
static OSSL_PROVIDER *nullprov = NULL;
static OSSL_PROVIDER *deflprov = NULL;
static int verbose = 0;

#if !defined(OPENSSL_NO_ML_KEM) || !defined(OPENSSL_NO_EC)
static char *testpropq = "provider=default";

/**
 * @brief Test that an EVP_PKEY encoded public key matches the supplied buffer
 * @param pkey is the EVP_PKEY we want to check
 * @param pub is the expected public key buffer
 * @param publen is the length of the above
 * @return 1 for good, 0 for bad
 */
static int cmpkey(const EVP_PKEY *pkey,
    const unsigned char *pub, size_t publen)
{
    unsigned char pubbuf[OSSL_HPKE_TST_PUBSIZE];
    size_t pubbuflen = 0;
    int erv = 0;

    if (!TEST_true(publen <= sizeof(pubbuf)))
        return 0;
    erv = EVP_PKEY_get_octet_string_param(pkey,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        pubbuf, sizeof(pubbuf), &pubbuflen);
    if (!TEST_true(erv))
        return 0;
    if (pub != NULL && !TEST_mem_eq(pubbuf, pubbuflen, pub, publen))
        return 0;
    return 1;
}

static int test_hpke_kats(int tstid)
{
    const TEST_HPKE_DATA *base = hpke_kat_tests + tstid;
    const TEST_HPKE_AEADDATA *aead = base->aead;
    const TEST_HPKE_EXPORTDATA *export = base->export;
    size_t aeadsz = base->aeadlen;
    size_t exportsz = base->exportlen;
    OSSL_LIB_CTX *libctx = testctx;
    const char *propq = testpropq;
    OSSL_HPKE_CTX *sealctx = NULL, *openctx = NULL;
    unsigned char ct[256];
    unsigned char enc[OSSL_HPKE_TST_PUBSIZE];
    unsigned char ptout[256];
    size_t ptoutlen = sizeof(ptout);
    size_t enclen = sizeof(enc);
    size_t ctlen = sizeof(ct);
    unsigned char pub[OSSL_HPKE_TST_PUBSIZE];
    size_t publen = sizeof(pub);
    EVP_PKEY *privE = NULL;
    unsigned char authpub[OSSL_HPKE_TST_PUBSIZE];
    size_t authpublen = sizeof(authpub);
    EVP_PKEY *authpriv = NULL;
    unsigned char rpub[OSSL_HPKE_TST_PUBSIZE];
    size_t rpublen = sizeof(rpub);
    EVP_PKEY *privR = NULL;
    int ret = 0;
    size_t i;
    uint64_t lastseq = 0;

    TEST_note("%s", base->desc);
    if (base->expected_pkEm != NULL) {
        if (!TEST_true(OSSL_HPKE_keygen(base->suite, pub, &publen, &privE,
                base->ikmE, base->ikmElen, libctx, propq)))
            goto end;
        if (!TEST_true(cmpkey(privE, base->expected_pkEm, base->expected_pkEmlen)))
            goto end;
    }
    if (!TEST_ptr(sealctx = OSSL_HPKE_CTX_new(base->mode, base->suite,
                      OSSL_HPKE_ROLE_SENDER,
                      libctx, propq)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set1_ikme(sealctx, base->ikmE, base->ikmElen)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_AUTH
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(base->ikmAuth != NULL && base->ikmAuthlen > 0))
            goto end;
        if (!TEST_true(OSSL_HPKE_keygen(base->suite,
                authpub, &authpublen, &authpriv,
                base->ikmAuth, base->ikmAuthlen,
                libctx, propq)))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(sealctx, authpriv)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_keygen(base->suite, rpub, &rpublen, &privR,
            base->ikmR, base->ikmRlen, libctx, propq)))
        goto end;
    if (!TEST_true(cmpkey(privR, base->expected_pkRm, base->expected_pkRmlen)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_PSK
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(sealctx, base->pskid,
                base->psk, base->psklen)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_encap(sealctx, enc, &enclen,
            rpub, rpublen,
            base->ksinfo, base->ksinfolen)))
        goto end;
    if (!TEST_mem_eq(enc, enclen, base->expected_enc, base->expected_enclen))
        goto end;
    if (privE != NULL && !TEST_true(cmpkey(privE, enc, enclen)))
        goto end;
    for (i = 0; i < aeadsz; ++i) {
        ctlen = sizeof(ct);
        memset(ct, 0, ctlen);
        if (!TEST_true(OSSL_HPKE_seal(sealctx, ct, &ctlen,
                aead[i].aad, aead[i].aadlen,
                aead[i].pt, aead[i].ptlen)))
            goto end;
        if (!TEST_mem_eq(ct, ctlen, aead[i].expected_ct,
                aead[i].expected_ctlen))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_get_seq(sealctx, &lastseq)))
            goto end;
        if (lastseq != (uint64_t)(i + 1))
            goto end;
    }
    if (!TEST_ptr(openctx = OSSL_HPKE_CTX_new(base->mode, base->suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      libctx, propq)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_PSK
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(base->pskid != NULL && base->psk != NULL
                && base->psklen > 0))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(openctx, base->pskid,
                base->psk, base->psklen)))
            goto end;
    }
    if (base->mode == OSSL_HPKE_MODE_AUTH
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(OSSL_HPKE_CTX_set1_authpub(openctx,
                authpub, authpublen)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_decap(openctx, enc, enclen, privR,
            base->ksinfo, base->ksinfolen)))
        goto end;
    for (i = 0; i < aeadsz; ++i) {
        ptoutlen = sizeof(ptout);
        memset(ptout, 0, ptoutlen);
        if (!TEST_true(OSSL_HPKE_open(openctx, ptout, &ptoutlen,
                aead[i].aad, aead[i].aadlen,
                aead[i].expected_ct,
                aead[i].expected_ctlen)))
            goto end;
        if (!TEST_mem_eq(aead[i].pt, aead[i].ptlen, ptout, ptoutlen))
            goto end;
        /* check the sequence is being incremented as expected */
        if (!TEST_true(OSSL_HPKE_CTX_get_seq(openctx, &lastseq)))
            goto end;
        if (lastseq != (uint64_t)(i + 1))
            goto end;
    }
    /* check exporters */
    for (i = 0; i < exportsz; ++i) {
        size_t len = export[i].expected_secretlen;
        unsigned char eval[OSSL_HPKE_TSTSIZE];

        if (len > sizeof(eval))
            goto end;
        /* export with too long label should fail */
        if (!TEST_false(OSSL_HPKE_export(sealctx, eval, len,
                export[i].context, -1)))
            goto end;
        /* good export call */
        if (!TEST_true(OSSL_HPKE_export(sealctx, eval, len,
                export[i].context,
                export[i].contextlen)))
            goto end;
        if (!TEST_mem_eq(eval, len, export[i].expected_secret,
                export[i].expected_secretlen))
            goto end;

        /* check seal fails if export only mode */
        if (aeadsz == 0) {
            if (!TEST_false(OSSL_HPKE_seal(sealctx, ct, &ctlen,
                    NULL, 0, ptout, ptoutlen)))
                goto end;
        }
    }
    ret = 1;
end:
    OSSL_HPKE_CTX_free(sealctx);
    OSSL_HPKE_CTX_free(openctx);
    EVP_PKEY_free(privE);
    EVP_PKEY_free(privR);
    EVP_PKEY_free(authpriv);
    return ret;
}
#endif /* !defined(OPENSSL_NO_ML_KEM) || !defined(OPENSSL_NO_EC) */

/*
 * Randomly toss a coin
 */
#define COIN_IS_HEADS (test_random() % 2)

/* tables of HPKE modes and suite values */
static int hpke_mode_list[] = {
    OSSL_HPKE_MODE_BASE,
    OSSL_HPKE_MODE_PSK,
    OSSL_HPKE_MODE_AUTH,
    OSSL_HPKE_MODE_PSKAUTH
};
static uint16_t hpke_kem_list[] = {
    OSSL_HPKE_KEM_ID_P256,
    OSSL_HPKE_KEM_ID_P384,
    OSSL_HPKE_KEM_ID_P521,
#ifndef OPENSSL_NO_ECX
    OSSL_HPKE_KEM_ID_X25519,
    OSSL_HPKE_KEM_ID_X448
#endif
};
static uint16_t hpke_kdf_list[] = {
    OSSL_HPKE_KDF_ID_HKDF_SHA256,
    OSSL_HPKE_KDF_ID_HKDF_SHA384,
    OSSL_HPKE_KDF_ID_HKDF_SHA512
};
static uint16_t hpke_aead_list[] = {
    OSSL_HPKE_AEAD_ID_AES_GCM_128,
    OSSL_HPKE_AEAD_ID_AES_GCM_256,
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    OSSL_HPKE_AEAD_ID_CHACHA_POLY1305
#endif
};

/*
 * Strings that can be used with names or IANA codepoints.
 * Note that the initial entries from these lists should
 * match the lists above, i.e. kem_str_list[0] and
 * hpke_kem_list[0] should refer to the same KEM. We use
 * that for verbose output via TEST_note() below.
 * Subsequent entries are only used for tests of
 * OSSL_HPKE_str2suite()
 */
static const char *mode_str_list[] = {
    "base", "psk", "auth", "pskauth"
};
static const char *kem_str_list[] = {
#ifndef OPENSSL_NO_ECX
    "P-256", "P-384", "P-521", "x25519", "x448",
    "0x10", "0x11", "0x12", "0x20", "0x21",
    "16", "17", "18", "32", "33"
#else
    "P-256", "P-384", "P-521",
    "0x10", "0x11", "0x12",
    "16", "17", "18"
#endif
};
static const char *kdf_str_list[] = {
    "hkdf-sha256", "hkdf-sha384", "hkdf-sha512",
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03",
    "1", "2", "3"
};
static const char *aead_str_list[] = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "exporter",
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03",
    "1", "2", "3",
    "0xff", "255"
};
/* table of bogus strings that better not work */
static const char *bogus_suite_strs[] = {
    "3,33,3",
    "bogus,bogus,bogus",
    "bogus,33,3,1,bogus",
    "bogus,33,3,1",
    "bogus,bogus",
    "bogus",
    /* one bad token */
    "0x10,0x01,bogus",
    "0x10,bogus,0x01",
    "bogus,0x02,0x01",
    /* in reverse order */
    "aes-256-gcm,hkdf-sha512,x25519",
    /* surplus separators */
    ",,0x10,0x01,0x02",
    "0x10,,0x01,0x02",
    "0x10,0x01,,0x02",
    /* embedded NUL chars */
    "0x10,\00x01,,0x02",
    "0x10,\0"
    "0x01,0x02",
    "0x10\0,0x01,0x02",
    "0x10,0x01\0,0x02",
    "0x10,0x01,\0"
    "0x02",
    /* embedded whitespace */
    " aes-256-gcm,hkdf-sha512,x25519",
    "aes-256-gcm, hkdf-sha512,x25519",
    "aes-256-gcm ,hkdf-sha512,x25519",
    "aes-256-gcm,hkdf-sha512, x25519",
    "aes-256-gcm,hkdf-sha512 ,x25519",
    "aes-256-gcm,hkdf-sha512,x25519 ",
    /* good value followed by extra stuff */
    "0x10,0x01,0x02,",
    "0x10,0x01,0x02,,,",
    "0x10,0x01,0x01,0x02",
    "0x10,0x01,0x01,blah",
    "0x10,0x01,0x01 0x02",
    /* too few but good tokens */
    "0x10,0x01",
    "0x10",
    /* empty things */
    NULL,
    "",
    ",",
    ",,"
};

/**
 * @brief round-trips, generating keys, encrypt and decrypt
 *
 * This iterates over all mode and ciphersuite options trying
 * a key gen, encrypt and decrypt for each. The aad, info, and
 * seq inputs are randomly set or omitted each time. EVP and
 * non-EVP key generation are randomly selected.
 *
 * @return 1 for success, other otherwise
 */
static int test_hpke_modes_suites(void)
{
    int overallresult = 1;
    size_t mind = 0; /* index into hpke_mode_list */
    size_t kemind = 0; /* index into hpke_kem_list */
    size_t kdfind = 0; /* index into hpke_kdf_list */
    size_t aeadind = 0; /* index into hpke_aead_list */

    /* iterate over the different modes */
    for (mind = 0; mind < OSSL_NELEM(hpke_mode_list); mind++) {
        int hpke_mode = hpke_mode_list[mind];
        size_t aadlen = OSSL_HPKE_TSTSIZE;
        unsigned char aad[OSSL_HPKE_TSTSIZE];
        unsigned char *aadp = NULL;
        size_t infolen = 32;
        unsigned char info[32];
        unsigned char *infop = NULL;
        unsigned char lpsk[32];
        unsigned char *pskp = NULL;
        char lpskid[32];
        size_t psklen = 32;
        char *pskidp = NULL;
        EVP_PKEY *privp = NULL;
        OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
        size_t plainlen = OSSL_HPKE_TSTSIZE;
        unsigned char plain[OSSL_HPKE_TSTSIZE];
        OSSL_HPKE_CTX *rctx = NULL;
        OSSL_HPKE_CTX *ctx = NULL;

        memset(plain, 0x00, OSSL_HPKE_TSTSIZE);
        strcpy((char *)plain, "a message not in a bottle");
        plainlen = strlen((char *)plain);
        /*
         * Randomly try with/without info, aad, seq. Given mode and suite
         * combos, and this being run even a few times, we'll exercise many
         * code paths fairly quickly. We don't really care what the values
         * are but it'll be easier to debug if they're known, so we set 'em.
         */
        if (COIN_IS_HEADS) {
            aadp = aad;
            memset(aad, 'a', aadlen);
        } else {
            aadlen = 0;
        }
        if (COIN_IS_HEADS) {
            infop = info;
            memset(info, 'i', infolen);
        } else {
            infolen = 0;
        }
        if (hpke_mode == OSSL_HPKE_MODE_PSK
            || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
            pskp = lpsk;
            memset(lpsk, 'P', psklen);
            pskidp = lpskid;
            memset(lpskid, 'I', psklen - 1);
            lpskid[psklen - 1] = '\0';
        } else {
            psklen = 0;
        }
        for (kemind = 0; /* iterate over the kems, kdfs and aeads */
            overallresult == 1 && kemind < OSSL_NELEM(hpke_kem_list);
            kemind++) {
            uint16_t kem_id = hpke_kem_list[kemind];
            size_t authpublen = OSSL_HPKE_TSTSIZE;
            unsigned char authpub[OSSL_HPKE_TSTSIZE];
            unsigned char *authpubp = NULL;
            EVP_PKEY *authpriv = NULL;

            hpke_suite.kem_id = kem_id;
            if (hpke_mode == OSSL_HPKE_MODE_AUTH
                || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                if (TEST_true(OSSL_HPKE_keygen(hpke_suite, authpub, &authpublen,
                        &authpriv, NULL, 0,
                        testctx, NULL))
                    != 1) {
                    overallresult = 0;
                }
                authpubp = authpub;
            } else {
                authpublen = 0;
            }
            for (kdfind = 0;
                overallresult == 1 && kdfind < OSSL_NELEM(hpke_kdf_list);
                kdfind++) {
                uint16_t kdf_id = hpke_kdf_list[kdfind];

                hpke_suite.kdf_id = kdf_id;
                for (aeadind = 0;
                    overallresult == 1
                    && aeadind < OSSL_NELEM(hpke_aead_list);
                    aeadind++) {
                    uint16_t aead_id = hpke_aead_list[aeadind];
                    size_t publen = OSSL_HPKE_TSTSIZE;
                    unsigned char pub[OSSL_HPKE_TSTSIZE];
                    size_t senderpublen = OSSL_HPKE_TSTSIZE;
                    unsigned char senderpub[OSSL_HPKE_TSTSIZE];
                    size_t cipherlen = OSSL_HPKE_TSTSIZE;
                    unsigned char cipher[OSSL_HPKE_TSTSIZE];
                    size_t clearlen = OSSL_HPKE_TSTSIZE;
                    unsigned char clear[OSSL_HPKE_TSTSIZE];

                    hpke_suite.aead_id = aead_id;
                    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite,
                            pub, &publen, &privp,
                            NULL, 0, testctx, NULL)))
                        overallresult = 0;
                    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                      OSSL_HPKE_ROLE_SENDER,
                                      testctx, NULL)))
                        overallresult = 0;
                    if (hpke_mode == OSSL_HPKE_MODE_PSK
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(ctx, pskidp,
                                pskp, psklen)))
                            overallresult = 0;
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_AUTH
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(ctx,
                                authpriv)))
                            overallresult = 0;
                    }
                    if (!TEST_true(OSSL_HPKE_encap(ctx, senderpub,
                            &senderpublen,
                            pub, publen,
                            infop, infolen)))
                        overallresult = 0;
                    /* throw in a call with a too-short cipherlen */
                    cipherlen = 15;
                    if (!TEST_false(OSSL_HPKE_seal(ctx, cipher, &cipherlen,
                            aadp, aadlen,
                            plain, plainlen)))
                        overallresult = 0;
                    /* fix back real cipherlen */
                    cipherlen = OSSL_HPKE_TSTSIZE;
                    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen,
                            aadp, aadlen,
                            plain, plainlen)))
                        overallresult = 0;
                    OSSL_HPKE_CTX_free(ctx);
                    memset(clear, 0, clearlen);
                    rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                        OSSL_HPKE_ROLE_RECEIVER,
                        testctx, NULL);
                    if (!TEST_ptr(rctx))
                        overallresult = 0;
                    if (hpke_mode == OSSL_HPKE_MODE_PSK
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(rctx, pskidp,
                                pskp, psklen)))
                            overallresult = 0;
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_AUTH
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        /* check a borked p256 key */
                        if (hpke_suite.kem_id == OSSL_HPKE_KEM_ID_P256) {
                            /* set to fail decode of authpub this time */
                            if (!TEST_false(OSSL_HPKE_CTX_set1_authpub(rctx,
                                    authpub,
                                    10)))
                                overallresult = 0;
                        }
                        if (!TEST_true(OSSL_HPKE_CTX_set1_authpub(rctx,
                                authpubp,
                                authpublen)))
                            overallresult = 0;
                    }
                    if (!TEST_true(OSSL_HPKE_decap(rctx, senderpub,
                            senderpublen, privp,
                            infop, infolen)))
                        overallresult = 0;
                    /* throw in a call with a too-short clearlen */
                    clearlen = 15;
                    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen,
                            aadp, aadlen, cipher,
                            cipherlen)))
                        overallresult = 0;
                    /* fix up real clearlen again */
                    clearlen = OSSL_HPKE_TSTSIZE;
                    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen,
                            aadp, aadlen, cipher,
                            cipherlen)))
                        overallresult = 0;
                    OSSL_HPKE_CTX_free(rctx);
                    EVP_PKEY_free(privp);
                    privp = NULL;
                    /* check output */
                    if (!TEST_mem_eq(clear, clearlen, plain, plainlen)) {
                        overallresult = 0;
                    }
                    if (verbose || overallresult != 1) {
                        const char *res = NULL;

                        res = (overallresult == 1 ? "worked" : "failed");
                        TEST_note("HPKE %s for mode: %s/0x%02x, "
                                  "kem: %s/0x%02x, kdf: %s/0x%02x, "
                                  "aead: %s/0x%02x",
                            res,
                            mode_str_list[mind], (int)mind,
                            kem_str_list[kemind], kem_id,
                            kdf_str_list[kdfind], kdf_id,
                            aead_str_list[aeadind], aead_id);
                    }
                }
            }
            EVP_PKEY_free(authpriv);
        }
    }
    return overallresult;
}

/**
 * @brief check roundtrip for export
 * @return 1 for success, other otherwise
 */
static int test_hpke_export(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub);
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char exp[32];
    unsigned char exp2[32];
    unsigned char rexp[32];
    unsigned char rexp2[32];
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TSTSIZE];
    size_t enclen = sizeof(enc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);
    char *estr = "foo";

    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* a few error cases 1st */
    if (!TEST_false(OSSL_HPKE_export(NULL, exp, sizeof(exp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    /* ctx before encap should fail too */
    if (!TEST_false(OSSL_HPKE_export(ctx, exp, sizeof(exp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;
    /* now for real */
    if (!TEST_true(OSSL_HPKE_export(ctx, exp, sizeof(exp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    /* check a 2nd call with same input gives same output */
    if (!TEST_true(OSSL_HPKE_export(ctx, exp2, sizeof(exp2),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    if (!TEST_mem_eq(exp, sizeof(exp), exp2, sizeof(exp2)))
        goto end;
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    if (!TEST_true(OSSL_HPKE_export(rctx, rexp, sizeof(rexp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    /* check a 2nd call with same input gives same output */
    if (!TEST_true(OSSL_HPKE_export(rctx, rexp2, sizeof(rexp2),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    if (!TEST_mem_eq(rexp, sizeof(rexp), rexp2, sizeof(rexp2)))
        goto end;
    if (!TEST_mem_eq(exp, sizeof(exp), rexp, sizeof(rexp)))
        goto end;
    erv = 1;
end:
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(privp);
    return erv;
}

/**
 * @brief Check mapping from strings to HPKE suites
 * @return 1 for success, other otherwise
 */
static int test_hpke_suite_strs(void)
{
    int overallresult = 1;
    int kemind = 0;
    int kdfind = 0;
    int aeadind = 0;
    int sind = 0;
    char sstr[128];
    OSSL_HPKE_SUITE stirred;
    char giant[2048];

    for (kemind = 0; kemind != OSSL_NELEM(kem_str_list); kemind++) {
        for (kdfind = 0; kdfind != OSSL_NELEM(kdf_str_list); kdfind++) {
            for (aeadind = 0; aeadind != OSSL_NELEM(aead_str_list); aeadind++) {
                BIO_snprintf(sstr, 128, "%s,%s,%s", kem_str_list[kemind],
                    kdf_str_list[kdfind], aead_str_list[aeadind]);
                if (TEST_true(OSSL_HPKE_str2suite(sstr, &stirred)) != 1) {
                    if (verbose)
                        TEST_note("Unexpected str2suite fail for :%s",
                            bogus_suite_strs[sind]);
                    overallresult = 0;
                }
            }
        }
    }
    for (sind = 0; sind != OSSL_NELEM(bogus_suite_strs); sind++) {
        if (TEST_false(OSSL_HPKE_str2suite(bogus_suite_strs[sind],
                &stirred))
            != 1) {
            if (verbose)
                TEST_note("OSSL_HPKE_str2suite didn't fail for bogus[%d]:%s",
                    sind, bogus_suite_strs[sind]);
            overallresult = 0;
        }
    }
    /* check a few errors */
    if (!TEST_false(OSSL_HPKE_str2suite("", &stirred)))
        overallresult = 0;
    if (!TEST_false(OSSL_HPKE_str2suite(NULL, &stirred)))
        overallresult = 0;
    if (!TEST_false(OSSL_HPKE_str2suite("", NULL)))
        overallresult = 0;
    memset(giant, 'A', sizeof(giant) - 1);
    giant[sizeof(giant) - 1] = '\0';
    if (!TEST_false(OSSL_HPKE_str2suite(giant, &stirred)))
        overallresult = 0;

    return overallresult;
}

/**
 * @brief try the various GREASEy APIs
 * @return 1 for success, other otherwise
 */
static int test_hpke_grease(void)
{
    int overallresult = 1;
    OSSL_HPKE_SUITE g_suite;
    unsigned char g_pub[OSSL_HPKE_TST_PUBSIZE];
    size_t g_pub_len = 0;
    unsigned char g_cipher[OSSL_HPKE_TSTSIZE];
    size_t g_cipher_len = 266;
    size_t clearlen = 128;
    size_t expanded = 0;
    size_t enclen = 0;

    memset(&g_suite, 0, sizeof(OSSL_HPKE_SUITE));
    /* GREASEing */
    /* check too short for public value */
    g_pub_len = 10;
    if (TEST_false(OSSL_HPKE_get_grease_value(NULL, &g_suite,
            g_pub, &g_pub_len,
            g_cipher, g_cipher_len,
            testctx, NULL))
        != 1) {
        overallresult = 0;
    }
    /* reset to work */
    g_pub_len = sizeof(g_pub);
    if (TEST_true(OSSL_HPKE_get_grease_value(NULL, &g_suite,
            g_pub, &g_pub_len,
            g_cipher, g_cipher_len,
            testctx, NULL))
        != 1) {
        overallresult = 0;
    }
    /* expansion */
    expanded = OSSL_HPKE_get_ciphertext_size(g_suite, clearlen);
    if (!TEST_size_t_gt(expanded, clearlen)) {
        overallresult = 0;
    }
    enclen = OSSL_HPKE_get_public_encap_size(g_suite);
    if (!TEST_size_t_ne(enclen, 0))
        overallresult = 0;

    return overallresult;
}

/*
 * Make a set of calls with odd parameters
 */
static int test_hpke_oddcalls(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TST_PUBSIZE];
    size_t publen = sizeof(pub);
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    int bad_mode = 0xbad;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE bad_suite = { 0xbad, 0xbad, 0xbad };
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TST_PUBSIZE], smallenc[10];
    size_t enclen = sizeof(enc), smallenclen = sizeof(smallenc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);
    unsigned char fake_ikm[OSSL_HPKE_TSTSIZE];
    char *badpropq = "yeah, this won't work";
    uint64_t lseq = 0;
    char giant_pskid[OSSL_HPKE_MAX_PARMLEN + 10];
    unsigned char info[OSSL_HPKE_TSTSIZE];

    /* many of the calls below are designed to get better test coverage */

    /* NULL ctx calls */
    OSSL_HPKE_CTX_free(NULL);
    if (!TEST_false(OSSL_HPKE_CTX_set_seq(NULL, 1)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_get_seq(NULL, &lseq)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpub(NULL, pub, publen)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpriv(NULL, privp)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_ikme(NULL, NULL, 0)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(NULL, NULL, NULL, 0)))
        goto end;

    /* bad suite calls */
    hpke_suite.aead_id = 0xbad;
    if (!TEST_false(OSSL_HPKE_suite_check(hpke_suite)))
        goto end;
    hpke_suite.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_128;
    if (!TEST_false(OSSL_HPKE_suite_check(bad_suite)))
        goto end;
    if (!TEST_false(OSSL_HPKE_get_recommended_ikmelen(bad_suite)))
        goto end;
    if (!TEST_false(OSSL_HPKE_get_public_encap_size(bad_suite)))
        goto end;
    if (!TEST_false(OSSL_HPKE_get_ciphertext_size(bad_suite, 0)))
        goto end;
    if (!TEST_false(OSSL_HPKE_keygen(bad_suite, pub, &publen, &privp,
            NULL, 0, testctx, badpropq)))
        goto end;
    if (!TEST_false(OSSL_HPKE_keygen(bad_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;

    /* dodgy keygen calls */
    /* no pub */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, NULL, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    /* ikmlen but NULL ikm */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 80, testctx, NULL)))
        goto end;
    /* zero ikmlen but ikm */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            fake_ikm, 0, testctx, NULL)))
        goto end;
    /* GIANT ikmlen */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            fake_ikm, -1, testctx, NULL)))
        goto end;
    /* short publen */
    publen = 10;
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    publen = sizeof(pub);

    /* encap/decap with NULLs */
    if (!TEST_false(OSSL_HPKE_encap(NULL, NULL, NULL, NULL, 0, NULL, 0)))
        goto end;
    if (!TEST_false(OSSL_HPKE_decap(NULL, NULL, 0, NULL, NULL, 0)))
        goto end;

    /*
     * run through a sender/recipient set of calls but with
     * failing calls interspersed whenever possible
     */
    /* good keygen */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;

    /* a psk context with no psk => encap fail */
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSK, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* set bad length psk */
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(ctx, "foo",
            (unsigned char *)"bar", -1)))
        goto end;
    /* set bad length pskid */
    memset(giant_pskid, 'A', sizeof(giant_pskid) - 1);
    giant_pskid[sizeof(giant_pskid) - 1] = '\0';
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(ctx, giant_pskid,
            (unsigned char *)"bar", 3)))
        goto end;
    /* still no psk really set so encap fails */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    OSSL_HPKE_CTX_free(ctx);

    /* bad suite */
    if (!TEST_ptr_null(ctx = OSSL_HPKE_CTX_new(hpke_mode, bad_suite,
                           OSSL_HPKE_ROLE_SENDER,
                           testctx, NULL)))
        goto end;
    /* bad mode */
    if (!TEST_ptr_null(ctx = OSSL_HPKE_CTX_new(bad_mode, hpke_suite,
                           OSSL_HPKE_ROLE_SENDER,
                           testctx, NULL)))
        goto end;
    /* make good ctx */
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* too long ikm */
    if (!TEST_false(OSSL_HPKE_CTX_set1_ikme(ctx, fake_ikm, -1)))
        goto end;
    /* zero length ikm */
    if (!TEST_false(OSSL_HPKE_CTX_set1_ikme(ctx, fake_ikm, 0)))
        goto end;
    /* NULL authpub */
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpub(ctx, NULL, 0)))
        goto end;
    /* NULL auth priv */
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpriv(ctx, NULL)))
        goto end;
    /* priv good, but mode is bad */
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpriv(ctx, privp)))
        goto end;
    /* bad mode for psk */
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(ctx, "foo",
            (unsigned char *)"bar", 3)))
        goto end;
    /* seal before encap */
    if (!TEST_false(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;
    /* encap with dodgy public */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, NULL, 0)))
        goto end;
    /* encap with too big info */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, info, -1)))
        goto end;
    /* encap with NULL info & non-zero infolen */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, NULL, 1)))
        goto end;
    /* encap with non-NULL info & zero infolen */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, info, 0)))
        goto end;
    /* encap with too small enc */
    if (!TEST_false(OSSL_HPKE_encap(ctx, smallenc, &smallenclen, pub, 1, NULL, 0)))
        goto end;
    /* good encap */
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    /* second encap fail */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    plainlen = 0;
    /* should fail for no plaintext */
    if (!TEST_false(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;
    plainlen = sizeof(plain);
    /* working seal */
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;

    /* receiver side */
    /* decap fail with psk mode but no psk set */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSK, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    if (!TEST_false(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* done with PSK mode */
    OSSL_HPKE_CTX_free(rctx);

    /* back good calls for base mode  */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    /* open before decap */
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    /* decap with info too long */
    if (!TEST_false(OSSL_HPKE_decap(rctx, enc, enclen, privp, info, -1)))
        goto end;
    /* good decap */
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* second decap fail */
    if (!TEST_false(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* no space for recovered clear */
    clearlen = 0;
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    clearlen = OSSL_HPKE_TSTSIZE;
    /* seq wrap around test */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, -1)))
        goto end;
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    if (!TEST_mem_eq(plain, plainlen, clear, clearlen))
        goto end;
    erv = 1;
end:
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(privp);
    return erv;
}

static int test_hpke_random_suites(void)
{
    OSSL_HPKE_SUITE def_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE suite2 = { 0xff01, 0xff02, 0xff03 };
    unsigned char enc[OSSL_HPKE_TST_PUBSIZE];
    size_t enclen = sizeof(enc);
    unsigned char ct[500];
    size_t ctlen = sizeof(ct);

    /* test with NULL/0 inputs */
    if (!TEST_false(OSSL_HPKE_get_grease_value(NULL, NULL,
            NULL, NULL, NULL, 0,
            testctx, NULL)))
        return 0;
    enclen = 10;
    if (!TEST_false(OSSL_HPKE_get_grease_value(&def_suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;

    enclen = sizeof(enc); /* reset, 'cause get_grease() will have set */
    /* test with a should-be-good suite */
    if (!TEST_true(OSSL_HPKE_get_grease_value(&def_suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    /* no suggested suite */
    enclen = sizeof(enc); /* reset, 'cause get_grease() will have set */
    if (!TEST_true(OSSL_HPKE_get_grease_value(NULL, &suite2,
            enc, &enclen,
            ct, ctlen,
            testctx, NULL)))
        return 0;
    /* suggested suite with P-521, just to be sure we hit long values */
    enclen = sizeof(enc); /* reset, 'cause get_grease() will have set */
    suite.kem_id = OSSL_HPKE_KEM_ID_P521;
    if (!TEST_true(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    enclen = sizeof(enc);
    ctlen = 2; /* too-short cttext (can't fit an aead tag) */
    if (!TEST_false(OSSL_HPKE_get_grease_value(NULL, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;

    ctlen = sizeof(ct);
    enclen = sizeof(enc);

    suite.kem_id = OSSL_HPKE_KEM_ID_X25519; /* back to default */
    suite.aead_id = 0x1234; /* bad aead */
    if (!TEST_false(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    enclen = sizeof(enc);
    suite.aead_id = def_suite.aead_id; /* good aead */
    suite.kdf_id = 0x3451; /* bad kdf */
    if (!TEST_false(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    enclen = sizeof(enc);
    suite.kdf_id = def_suite.kdf_id; /* good kdf */
    suite.kem_id = 0x4517; /* bad kem */
    if (!TEST_false(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    return 1;
}

#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_ECX)
/*
 * @brief generate a key pair from initial key material (ikm) and check public
 * @param kem_id the KEM to use (RFC9180 code point)
 * @ikm is the initial key material buffer
 * @ikmlen is the length of ikm
 * @pub is the public key buffer
 * @publen is the length of the public key
 * @return 1 for good, other otherwise
 *
 * This calls OSSL_HPKE_keygen specifying only the IKM, then
 * compares the key pair values with the already-known values
 * that were input.
 */
static int test_hpke_one_ikm_gen(uint16_t kem_id,
    const unsigned char *ikm, size_t ikmlen,
    const unsigned char *pub, size_t publen)
{
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char lpub[OSSL_HPKE_TST_PUBSIZE];
    size_t lpublen = sizeof(lpub);
    EVP_PKEY *sk = NULL;

    hpke_suite.kem_id = kem_id;
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, lpub, &lpublen, &sk,
            ikm, ikmlen, testctx, NULL)))
        return 0;
    if (!TEST_ptr(sk))
        return 0;
    EVP_PKEY_free(sk);
    if (!TEST_mem_eq(pub, publen, lpub, lpublen))
        return 0;
    return 1;
}
#endif

/*
 * @brief test some uses of IKM produce the expected public keys
 */
static int test_hpke_ikms(void)
{
    int res = 1;

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_ECX
    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_X25519,
        ikm25519, sizeof(ikm25519),
        pub25519, sizeof(pub25519));
    if (res != 1)
        return res;
#endif
    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_P521,
        ikmp521, sizeof(ikmp521),
        pubp521, sizeof(pubp521));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_P256,
        ikmp256, sizeof(ikmp256),
        pubp256, sizeof(pubp256));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_P256,
        ikmiter, sizeof(ikmiter),
        pubiter, sizeof(pubiter));
    if (res != 1)
        return res;
#endif
    return res;
}

/*
 * Test that use of a compressed format auth public key works
 * We'll do a typical round-trip for auth mode but provide the
 * auth public key in compressed form. That should work.
 */
static int test_hpke_compressed(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TST_PUBSIZE];
    size_t publen = sizeof(pub);
    EVP_PKEY *authpriv = NULL;
    unsigned char authpub[OSSL_HPKE_TST_PUBSIZE];
    size_t authpublen = sizeof(authpub);
    int hpke_mode = OSSL_HPKE_MODE_AUTH;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TST_PUBSIZE];
    size_t enclen = sizeof(enc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);

    hpke_suite.kem_id = OSSL_HPKE_KEM_ID_P256;

    /* generate auth key pair */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, authpub, &authpublen, &authpriv,
            NULL, 0, testctx, NULL)))
        goto end;
    /* now get the compressed form public key */
    if (!TEST_true(EVP_PKEY_set_utf8_string_param(authpriv,
            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
            OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED)))
        goto end;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(authpriv,
            OSSL_PKEY_PARAM_PUB_KEY,
            authpub,
            sizeof(authpub),
            &authpublen)))
        goto end;

    /* sender side as usual */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(ctx, authpriv)))
        goto end;
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;

    /* receiver side providing compressed form of auth public */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set1_authpub(rctx, authpub, authpublen)))
        goto end;
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    erv = 1;

end:
    EVP_PKEY_free(privp);
    EVP_PKEY_free(authpriv);
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    return erv;
}

/*
 * Test that nonce reuse calls are prevented as we expect
 */
static int test_hpke_noncereuse(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TST_PUBSIZE];
    size_t publen = sizeof(pub);
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TST_PUBSIZE];
    size_t enclen = sizeof(enc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);
    uint64_t seq = 0xbad1dea;

    /* sender side is not allowed set seq once some crypto done */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* set seq will fail before any crypto done */
    if (!TEST_false(OSSL_HPKE_CTX_set_seq(ctx, seq)))
        goto end;
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    /* set seq will also fail after some crypto done */
    if (!TEST_false(OSSL_HPKE_CTX_set_seq(ctx, seq + 1)))
        goto end;
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;

    /* receiver side is allowed control seq */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    /* set seq will work before any crypto done */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, seq)))
        goto end;
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* set seq will work for receivers even after crypto done */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, seq)))
        goto end;
    /* but that value isn't good so decap will fail */
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    /* reset seq to correct value and _open() should work */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    erv = 1;

end:
    EVP_PKEY_free(privp);
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    return erv;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run HPKE tests\n" },
        { NULL }
    };
    return test_options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1; /* Print progress dots */
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    if (!test_get_libctx(&testctx, &nullprov, NULL, &deflprov, "default"))
        return 0;
#if !defined(OPENSSL_NO_ML_KEM) || !defined(OPENSSL_NO_EC)
    ADD_ALL_TESTS(test_hpke_kats, OSSL_NELEM(hpke_kat_tests));
#endif
    ADD_TEST(test_hpke_export);
    ADD_TEST(test_hpke_modes_suites);
    ADD_TEST(test_hpke_suite_strs);
    ADD_TEST(test_hpke_grease);
    ADD_TEST(test_hpke_ikms);
    ADD_TEST(test_hpke_random_suites);
    ADD_TEST(test_hpke_oddcalls);
    ADD_TEST(test_hpke_compressed);
    ADD_TEST(test_hpke_noncereuse);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(deflprov);
    OSSL_PROVIDER_unload(nullprov);
    OSSL_LIB_CTX_free(testctx);
}
