/* crypto/ec/ec_kmeth.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <openssl/ec.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include "ec_lcl.h"


static const EC_KEY_METHOD openssl_ec_key_method = {
    "OpenSSL EC_KEY method",
    0,
    0,0,0,0,0,0,
    ossl_ec_key_gen,
    ossl_ecdh_compute_key
};

const EC_KEY_METHOD *default_ec_key_meth = &openssl_ec_key_method;

const EC_KEY_METHOD *EC_KEY_OpenSSL(void)
{
    return &openssl_ec_key_method;
}

const EC_KEY_METHOD *EC_KEY_get_default_method(void)
{
    return default_ec_key_meth;
}

void EC_KEY_set_default_method(const EC_KEY_METHOD *meth)
{
    if (meth == NULL)
        default_ec_key_meth = &openssl_ec_key_method;
    else
        default_ec_key_meth = meth;
}

EC_KEY *EC_KEY_new_method(ENGINE *engine)
{
    EC_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        ECerr(EC_F_EC_KEY_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->meth = EC_KEY_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            ECerr(EC_F_EC_KEY_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_EC_KEY();
    if (ret->engine) {
        ret->meth = ENGINE_get_EC_KEY(ret->engine);
        if (!ret->meth) {
            ECerr(EC_F_EC_KEY_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
        }
    }
#endif

    ret->version = 1;
    ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;
    ret->references = 1;
    if (ret->meth->init && ret->meth->init(ret) == 0) {
        EC_KEY_free(ret);
        return NULL;
    }
    return ret;
}

int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                     EC_KEY *eckey,
                     void *(*KDF) (const void *in, size_t inlen, void *out,
                                   size_t *outlen))
{
    if (eckey->meth->compute_key)
        return eckey->meth->compute_key(out, outlen, pub_key, eckey, KDF);
    ECerr(EC_F_ECDH_COMPUTE_KEY, EC_R_OPERATION_NOT_SUPPORTED);
    return 0;
}
