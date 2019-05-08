/*
 * Copyright 2013-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"

#ifndef OPENSSL_NO_CMS
# include <string.h>
# include <openssl/dh.h>
# include <openssl/evp.h>
# include <openssl/asn1.h>
# include <openssl/kdf.h>

int DH_KDF_X9_42(unsigned char *out, size_t outlen,
                 const unsigned char *Z, size_t Zlen,
                 ASN1_OBJECT *key_oid,
                 const unsigned char *ukm, size_t ukmlen, const EVP_MD *md)
{
    int ret = 0, nid;
    EVP_KDF_CTX *kctx = NULL;
    const EVP_KDF *kdf = NULL;
    const char *oid_sn;

    nid = OBJ_obj2nid(key_oid);
    if (nid == NID_undef)
        return 0;
    oid_sn = OBJ_nid2sn(nid);
    if (oid_sn == NULL)
        return 0;

    kdf = EVP_get_kdfbyname(SN_x942kdf);
    if (kdf == NULL)
        goto err;
    kctx = EVP_KDF_CTX_new(kdf);
    ret =
        kctx != NULL
        && EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, md) > 0
        && EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, Z, Zlen) > 0
        && (ukm == NULL
            || EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_UKM, ukm, ukmlen) > 0)
        && EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_CEK_ALG, oid_sn) > 0
        && EVP_KDF_derive(kctx, out, outlen) > 0;
err:
    EVP_KDF_CTX_free(kctx);
    return ret;
}
#endif /* OPENSSL_NO_CMS */
