/*
 * Copyright 1998-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/des.h>
#include <opentls/rand.h>

int DES_random_key(DES_cblock *ret)
{
    do {
        if (RAND_priv_bytes((unsigned char *)ret, sizeof(DES_cblock)) != 1)
            return 0;
    } while (DES_is_weak_key(ret));
    DES_set_odd_parity(ret);
    return 1;
}
