/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The maximum permitted number of cipher blocks per data unit in XTS mode.
 * Reference IEEE Std 1619-2018.
 */
#define XTS_MAX_BLOCKS_PER_DATA_UNIT            (1<<20)

