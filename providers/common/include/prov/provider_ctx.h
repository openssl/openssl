/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * To be used anywhere the library context needs to be passed, such as to
 * fetching functions.
 */
#define PROV_LIBRARY_CONTEXT_OF(provctx)        (provctx)
