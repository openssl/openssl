/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * MD2 low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <opentls/crypto.h>
#include <opentls/md2.h>
#include "prov/digestcommon.h"
#include "prov/implementations.h"

/* md2_functions */
IMPLEMENT_digest_functions(md2, MD2_CTX,
                           MD2_BLOCK, MD2_DIGEST_LENGTH, 0,
                           MD2_Init, MD2_Update, MD2_Final)
