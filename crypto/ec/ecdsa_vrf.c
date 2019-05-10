/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ec.h>
#include "ec_lcl.h"
#include <openssl/err.h>

#ifndef OPENSSL_NO_CNSM

int sm2_verify(const unsigned char *dgst, int dgstlen, const unsigned char *sig, int sig_len, EC_KEY *eckey);

#endif

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey)
{
    if (eckey->meth->verify_sig != NULL)
        return eckey->meth->verify_sig(dgst, dgst_len, sig, eckey);
    ECerr(EC_F_ECDSA_DO_VERIFY, EC_R_OPERATION_NOT_SUPPORTED);
    return 0;
}

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_verify(int type, const unsigned char *dgst, int dgst_len,
                 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    #ifndef OPENSSL_NO_CNSM
    if (EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)) == NID_sm2)
        return sm2_verify(dgst, dgst_len, sigbuf, sig_len, eckey);
    #endif   
    if (eckey->meth->verify != NULL)
        return eckey->meth->verify(type, dgst, dgst_len, sigbuf, sig_len,
                                   eckey);
    ECerr(EC_F_ECDSA_VERIFY, EC_R_OPERATION_NOT_SUPPORTED);
    return 0;
}
