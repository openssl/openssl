/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "pbkdf2.h"

/*
 * For backwards compatibility reasons,
 * Extra checks are done by default in fips mode only.
 */
#ifdef FIPS_MODE
const int kdf_pbkdf2_default_checks = 1;
#else
const int kdf_pbkdf2_default_checks = 0;
#endif /* FIPS_MODE */
