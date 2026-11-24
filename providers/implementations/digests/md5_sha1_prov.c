/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * MD5 and SHA-1 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include "prov/md5_sha1.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"

/* ossl_md5_sha1_functions */
IMPLEMENT_digest_functions(
    md5_sha1, MD5_SHA1_CTX, MD5_SHA1_CBLOCK, MD5_SHA1_DIGEST_LENGTH, 0,
    ossl_md5_sha1_init, ossl_md5_sha1_update, ossl_md5_sha1_final)
