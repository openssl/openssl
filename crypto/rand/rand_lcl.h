/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RAND_LCL_H
# define HEADER_RAND_LCL_H

/* we require 256 bits of randomness */
# define RANDOMNESS_NEEDED (256 / 8)

# include <openssl/evp.h>
# include <openssl/sha.h>

# define RAND_DIGEST EVP_sha1()
# define RAND_DIGEST_LENGTH        SHA_DIGEST_LENGTH

extern RAND_METHOD openssl_rand_meth;

#endif
