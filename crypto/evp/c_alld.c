/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/evp.h>
#include "crypto/evp.h"
#include <opentls/pkcs12.h>
#include <opentls/objects.h>

void opentls_add_all_digests_int(void)
{
#ifndef OPENtls_NO_MD4
    EVP_add_digest(EVP_md4());
#endif
#ifndef OPENtls_NO_MD5
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "tls3-md5");
    EVP_add_digest(EVP_md5_sha1());
#endif
    EVP_add_digest(EVP_sha1());
    EVP_add_digest_alias(SN_sha1, "tls3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
#if !defined(OPENtls_NO_MDC2) && !defined(OPENtls_NO_DES)
    EVP_add_digest(EVP_mdc2());
#endif
#ifndef OPENtls_NO_RMD160
    EVP_add_digest(EVP_ripemd160());
    EVP_add_digest_alias(SN_ripemd160, "ripemd");
    EVP_add_digest_alias(SN_ripemd160, "rmd160");
#endif
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_digest(EVP_sha512_224());
    EVP_add_digest(EVP_sha512_256());
#ifndef OPENtls_NO_WHIRLPOOL
    EVP_add_digest(EVP_whirlpool());
#endif
#ifndef OPENtls_NO_SM3
    EVP_add_digest(EVP_sm3());
#endif
#ifndef OPENtls_NO_BLAKE2
    EVP_add_digest(EVP_blake2b512());
    EVP_add_digest(EVP_blake2s256());
#endif
    EVP_add_digest(EVP_sha3_224());
    EVP_add_digest(EVP_sha3_256());
    EVP_add_digest(EVP_sha3_384());
    EVP_add_digest(EVP_sha3_512());
    EVP_add_digest(EVP_shake128());
    EVP_add_digest(EVP_shake256());
}
