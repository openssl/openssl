/*
 * Copyright 2000-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef HEADER_OCSP_RESPST_H
# define HEADER_OCSP_RESPST_H

# ifndef OPENSSL_NO_OCSP

#  include <openssl/ocsp.h>
#  include <openssl/safestack.h>
#  include <openssl/ocsperr.h>

#ifdef  __cplusplus
extern "C" {
#endif

DEFINE_STACK_OF(OCSP_RESPONSE)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPONSE)

#  ifdef  __cplusplus
}
#  endif
# endif
#endif

