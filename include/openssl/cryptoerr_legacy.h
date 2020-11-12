/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This header file preserves symbols from pre-3.0 OpenSSL.
 * It should never be included directly, as it's already included
 * by the public {lib}err.h headers, and since it will go away some
 * time in the future.
 */

#ifndef OPENSSL_CRYPTOERR_LEGACY_H
# define OPENSSL_CRYPTOERR_LEGACY_H
# pragma once

# include <openssl/macros.h>
# include <openssl/symhacks.h>

# ifdef  __cplusplus
extern "C" {
# endif

# ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0 int ERR_load_ASN1_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_ASYNC_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_BIO_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_BN_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_BUF_strings(void);
#  ifndef OPENSSL_NO_CMS
OSSL_DEPRECATEDIN_3_0 int ERR_load_CMS_strings(void);
#  endif
#  ifndef OPENSSL_NO_COMP
OSSL_DEPRECATEDIN_3_0 int ERR_load_COMP_strings(void);
#  endif
OSSL_DEPRECATEDIN_3_0 int ERR_load_CONF_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_CRYPTO_strings(void);
#  ifndef OPENSSL_NO_CT
OSSL_DEPRECATEDIN_3_0 int ERR_load_CT_strings(void);
#  endif
#  ifndef OPENSSL_NO_DH
OSSL_DEPRECATEDIN_3_0 int ERR_load_DH_strings(void);
#  endif
#  ifndef OPENSSL_NO_DSA
OSSL_DEPRECATEDIN_3_0 int ERR_load_DSA_strings(void);
#  endif
#  ifndef OPENSSL_NO_EC
OSSL_DEPRECATEDIN_3_0 int ERR_load_EC_strings(void);
#  endif
#  ifndef OPENSSL_NO_ENGINE
OSSL_DEPRECATEDIN_3_0 int ERR_load_ENGINE_strings(void);
#  endif
OSSL_DEPRECATEDIN_3_0 int ERR_load_ERR_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_EVP_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_KDF_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_OBJ_strings(void);
#  ifndef OPENSSL_NO_OCSP
OSSL_DEPRECATEDIN_3_0 int ERR_load_OCSP_strings(void);
#  endif
OSSL_DEPRECATEDIN_3_0 int ERR_load_PEM_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_PKCS12_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_PKCS7_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_RAND_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_RSA_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_OSSL_STORE_strings(void);
#  ifndef OPENSSL_NO_TS
OSSL_DEPRECATEDIN_3_0 int ERR_load_TS_strings(void);
#  endif
OSSL_DEPRECATEDIN_3_0 int ERR_load_UI_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_X509_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_X509V3_strings(void);
# endif

# ifdef  __cplusplus
}
# endif
#endif
