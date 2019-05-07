/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/evp_int.h"

void openssl_add_all_kdfs_int(void)
{
    EVP_add_kdf(&pbkdf2_kdf_meth);
#ifndef OPENSSL_NO_SCRYPT
    EVP_add_kdf(&scrypt_kdf_meth);
#endif
    EVP_add_kdf(&tls1_prf_kdf_meth);
    EVP_add_kdf(&hkdf_kdf_meth);
    EVP_add_kdf(&sshkdf_kdf_meth);
    EVP_add_kdf(&ss_kdf_meth);
    EVP_add_kdf(&x963_kdf_meth);
}
