/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "bn_lcl.h"

bn_div_words_abort(int i)
{
#ifdef BN_DEBUG
# if !defined(OPENSSL_NO_STDIO)
    fprintf(stderr, "Division would overflow (%d)\n", i);
# endif
    abort();
#endif
}
