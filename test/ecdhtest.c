/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../e_os.h"

#include <openssl/opensslconf.h> /* for OPENSSL_NO_EC */
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#ifdef OPENSSL_NO_EC
int main(int argc, char *argv[])
{
    printf("No ECDH support\n");
    return (0);
}
#else
# include <openssl/ec.h>

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

/* Given private value and NID, create EC_KEY structure */

static EC_KEY *mk_eckey(int nid, const char *str)
{
    int ok = 0;
    EC_KEY *k = NULL;
    BIGNUM *priv = NULL;
    EC_POINT *pub = NULL;
    const EC_GROUP *grp;
    k = EC_KEY_new_by_curve_name(nid);
    if (!k)
        goto err;
    if(!BN_hex2bn(&priv, str))
        goto err;
    if (!priv)
        goto err;
    if (!EC_KEY_set_private_key(k, priv))
        goto err;
    grp = EC_KEY_get0_group(k);
    pub = EC_POINT_new(grp);
    if (!pub)
        goto err;
    if (!EC_POINT_mul(grp, pub, priv, NULL, NULL, NULL))
        goto err;
    if (!EC_KEY_set_public_key(k, pub))
        goto err;
    ok = 1;
 err:
    BN_clear_free(priv);
    EC_POINT_free(pub);
    if (ok)
        return k;
    EC_KEY_free(k);
    return NULL;
}

#include "ecdhtest_cavs.h"

/*
 * NIST SP800-56A co-factor ECDH tests.
 * KATs taken from NIST documents with parameters:
 *
 * - (QCAVSx,QCAVSy) is the public key for CAVS.
 * - dIUT is the private key for IUT.
 * - (QIUTx,QIUTy) is the public key for IUT.
 * - ZIUT is the shared secret KAT.
 *
 * CAVS: Cryptographic Algorithm Validation System
 * IUT: Implementation Under Test
 *
 * This function tests two things:
 *
 * 1. dIUT * G = (QIUTx,QIUTy)
 *    i.e. public key for IUT computes correctly.
 * 2. x-coord of cofactor * dIUT * (QCAVSx,QCAVSy) = ZIUT
 *    i.e. co-factor ECDH key computes correctly.
 *
 * returns zero on failure or unsupported curve. One otherwise.
 */
static int ecdh_cavs_kat(BIO *out, const ecdh_cavs_kat_t *kat)
{
    int rv = 0, is_char_two = 0;
    EC_KEY *key1 = NULL;
    EC_POINT *pub = NULL;
    const EC_GROUP *group = NULL;
    BIGNUM *bnz = NULL, *x = NULL, *y = NULL;
    unsigned char *Ztmp = NULL, *Z = NULL;
    size_t Ztmplen, Zlen;
    BIO_puts(out, "Testing ECC CDH Primitive SP800-56A with ");
    BIO_puts(out, OBJ_nid2sn(kat->nid));

    /* dIUT is IUT's private key */
    if ((key1 = mk_eckey(kat->nid, kat->dIUT)) == NULL)
        goto err;
    /* these are cofactor ECDH KATs */
    EC_KEY_set_flags(key1, EC_FLAG_COFACTOR_ECDH);

    if ((group = EC_KEY_get0_group(key1)) == NULL)
        goto err;
    if ((pub = EC_POINT_new(group)) == NULL)
        goto err;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_characteristic_two_field)
        is_char_two = 1;

    /* (QIUTx, QIUTy) is IUT's public key */
    if(!BN_hex2bn(&x, kat->QIUTx))
        goto err;
    if(!BN_hex2bn(&y, kat->QIUTy))
        goto err;
    if (is_char_two) {
#ifdef OPENSSL_NO_EC2M
        goto err;
#else
        if (!EC_POINT_set_affine_coordinates_GF2m(group, pub, x, y, NULL))
            goto err;
#endif
    }
    else {
        if (!EC_POINT_set_affine_coordinates_GFp(group, pub, x, y, NULL))
            goto err;
    }
    /* dIUT * G = (QIUTx, QIUTy) should hold */
    if (EC_POINT_cmp(group, EC_KEY_get0_public_key(key1), pub, NULL))
        goto err;

    /* (QCAVSx, QCAVSy) is CAVS's public key */
    if(!BN_hex2bn(&x, kat->QCAVSx))
        goto err;
    if(!BN_hex2bn(&y, kat->QCAVSy))
        goto err;
    if (is_char_two) {
#ifdef OPENSSL_NO_EC2M
        goto err;
#else
        if (!EC_POINT_set_affine_coordinates_GF2m(group, pub, x, y, NULL))
            goto err;
#endif
    }
    else {
        if (!EC_POINT_set_affine_coordinates_GFp(group, pub, x, y, NULL))
            goto err;
    }

    /* ZIUT is the shared secret */
    if(!BN_hex2bn(&bnz, kat->ZIUT))
        goto err;
    Ztmplen = (EC_GROUP_get_degree(EC_KEY_get0_group(key1)) + 7) / 8;
    Zlen = BN_num_bytes(bnz);
    if (Zlen > Ztmplen)
        goto err;
    if((Ztmp = OPENSSL_zalloc(Ztmplen)) == NULL)
        goto err;
    if((Z = OPENSSL_zalloc(Ztmplen)) == NULL)
        goto err;
    if(!BN_bn2binpad(bnz, Z, Ztmplen))
        goto err;
    if (!ECDH_compute_key(Ztmp, Ztmplen, pub, key1, 0))
        goto err;
    /* shared secrets should be identical */
    if (memcmp(Ztmp, Z, Ztmplen))
        goto err;
    rv = 1;
 err:
    EC_KEY_free(key1);
    EC_POINT_free(pub);
    BN_free(bnz);
    BN_free(x);
    BN_free(y);
    OPENSSL_free(Ztmp);
    OPENSSL_free(Z);
    if (rv) {
        BIO_puts(out, " ok\n");
    }
    else {
        fprintf(stderr, "Error in ECC CDH routines\n");
        ERR_print_errors_fp(stderr);
    }
    return rv;
}

int main(int argc, char *argv[])
{
    int ret = 1;
    size_t n = 0;
    BIO *out;

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed);

    out = BIO_new(BIO_s_file());
    if (out == NULL)
        EXIT(1);
    BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    /* NAMED CURVES TESTS: moved to evptests.txt */

    /* KATs: moved to evptests.txt  */

    /* NIST SP800-56A co-factor ECDH KATs */
    for (n = 0; n < (sizeof(ecdh_cavs_kats)/sizeof(ecdh_cavs_kat_t)); n++) {
        if (!ecdh_cavs_kat(out, &ecdh_cavs_kats[n]))
            goto err;
    }

    ret = 0;

 err:
    ERR_print_errors_fp(stderr);
    BIO_free(out);

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks_fp(stderr) <= 0)
        ret = 1;
#endif
    EXIT(ret);
}
#endif
