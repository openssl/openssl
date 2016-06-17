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

# define ENTROPY_NEEDED 32      /* require 256 bits = 32 bytes of randomness */

# if !defined(USE_SHA256_RAND) && !defined(OPENSSL_NO_SHA256)
#  define USE_SHA256_RAND
# elif !defined(USE_SHA1_RAND)
#  define USE_SHA1_RAND
# endif

# include <openssl/evp.h>
# define MD_Update(a,b,c)        EVP_DigestUpdate(a,b,c)
# define MD_Final(a,b)           EVP_DigestFinal_ex(a,b,NULL)
# if defined(USE_SHA256_RAND)
#  include <openssl/sha.h>
#  define MD_DIGEST_LENGTH        SHA_DIGEST_LENGTH
#  define MD_Init(a)              EVP_DigestInit_ex(a,EVP_sha256(), NULL)
#  define MD(a,b,c)               EVP_Digest(a,b,c,NULL,EVP_sha256(), NULL)
# elif defined(USE_SHA1_RAND)
#  include <openssl/sha.h>
#  define MD_DIGEST_LENGTH        SHA_DIGEST_LENGTH
#  define MD_Init(a)              EVP_DigestInit_ex(a,EVP_sha1(), NULL)
#  define MD(a,b,c)               EVP_Digest(a,b,c,NULL,EVP_sha1(), NULL)
# endif

void rand_hw_xor(unsigned char *buf, size_t num);

#endif
