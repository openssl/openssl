/*
 * Copyright 2013-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "e_os.h"

#ifndef OPENtls_NO_CMS
# include <string.h>
# include <opentls/core_names.h>
# include <opentls/dh.h>
# include <opentls/evp.h>
# include <opentls/asn1.h>
# include <opentls/kdf.h>
# include <internal/provider.h>

int DH_KDF_X9_42(unsigned char *out, size_t outlen,
                 const unsigned char *Z, size_t Zlen,
                 ASN1_OBJECT *key_oid,
                 const unsigned char *ukm, size_t ukmlen, const EVP_MD *md)
{
    int ret = 0, nid;
    EVP_KDF_CTX *kctx = NULL;
    EVP_KDF *kdf = NULL;
    const char *oid_sn;
    Otls_PARAM params[5], *p = params;
    const char *mdname = EVP_MD_name(md);
    const Otls_PROVIDER *prov = EVP_MD_provider(md);
    OPENtls_CTX *provctx = otls_provider_library_context(prov);

    nid = OBJ_obj2nid(key_oid);
    if (nid == NID_undef)
        return 0;
    oid_sn = OBJ_nid2sn(nid);
    if (oid_sn == NULL)
        return 0;

    kdf = EVP_KDF_fetch(provctx, Otls_KDF_NAME_X942KDF, NULL);
    if ((kctx = EVP_KDF_CTX_new(kdf)) == NULL)
        goto err;
    *p++ = Otls_PARAM_construct_utf8_string(Otls_KDF_PARAM_DIGEST,
                                            (char *)mdname, strlen(mdname) + 1);
    *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_KEY,
                                             (unsigned char *)Z, Zlen);
    if (ukm != NULL)
        *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_UKM,
                                                 (unsigned char *)ukm, ukmlen);
    *p++ = Otls_PARAM_construct_utf8_string(Otls_KDF_PARAM_CEK_ALG,
                                            (char *)oid_sn, strlen(oid_sn) + 1);
    *p = Otls_PARAM_construct_end();
    ret = EVP_KDF_CTX_set_params(kctx, params) > 0
        && EVP_KDF_derive(kctx, out, outlen) > 0;
err:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}
#endif /* OPENtls_NO_CMS */
