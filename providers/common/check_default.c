/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <openssl/rsa.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include "prov/check.h"
#include "internal/nelem.h"

int rsa_check_key(ossl_unused const RSA *rsa, ossl_unused int protect)
{
    return 1;
}

#ifndef OPENSSL_NO_EC
int ec_check_key(ossl_unused const EC_KEY *ec, ossl_unused int protect)
{
    return 1;
}
#endif

#ifndef OPENSSL_NO_DSA
int dsa_check_key(ossl_unused const DSA *dsa, ossl_unused int sign)
{
    return 1;
}
#endif

#ifndef OPENSSL_NO_DH
int dh_check_key(const DH *dh)
{
    return 1;
}
#endif

int digest_is_allowed(ossl_unused const EVP_MD *md)
{
    return 1;
}

int digest_get_approved_nid_with_sha1(const EVP_MD *md,
                                      ossl_unused int sha1_allowed)
{
    return digest_get_approved_nid(md);
}

int digest_rsa_sign_get_md_nid(const EVP_MD *md, ossl_unused int sha1_allowed)
{
    int mdnid;

    static const OSSL_ITEM name_to_nid[] = {
        { NID_md5,       OSSL_DIGEST_NAME_MD5       },
        { NID_md5_sha1,  OSSL_DIGEST_NAME_MD5_SHA1  },
        { NID_md2,       OSSL_DIGEST_NAME_MD2       },
        { NID_md4,       OSSL_DIGEST_NAME_MD4       },
        { NID_mdc2,      OSSL_DIGEST_NAME_MDC2      },
        { NID_ripemd160, OSSL_DIGEST_NAME_RIPEMD160 },
    };
    if (md == NULL)
        return NID_undef;

    mdnid = digest_get_approved_nid_with_sha1(md, 1);
    if (mdnid == NID_undef)
        mdnid = digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
    return mdnid;
}
