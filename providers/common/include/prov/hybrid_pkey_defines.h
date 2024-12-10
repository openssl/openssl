/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(NAME_1) || !defined(NAME_2)
# error Must define NAME_1 and NAME_2
#endif  /* !NAME_1 || ! NAME_2 */

#if !defined(NUM_ALGS)
# define NUM_ALGS 2
#endif  /* !NUM_ALGS */

#include "prov/hybrid_pkey.h"

#if NUM_ALGS > MAX_HYBRID_ALGS
# error Too many algorithms
#endif  /* NUM_ALGS > MAX_HYBRID_ALGS */

/* Need to work around C's lack of macro expansion in some macro expansions */
#define NAME_CONCAT3(n1, n2, n3, name) \
    n1 ## _ ## n2 ## _ ## n3 ## _ ## name
#define NAME_CONCAT4(n1, n2, n3, n4, name) \
    n1 ## _ ## n2 ## _ ## n3 ## _ ## n4 ## _ ## name

#define NAME_CREATE3(n1, n2, n3, name)      NAME_CONCAT3(n1, n2, n3, name)
#define NAME_CREATE4(n1, n2, n3, n4, name)  NAME_CONCAT4(n1, n2, n3, n4, name)

#define NAME(name)          NAME_CREATE3(NAME_1, NAME_2, PREFIX, name)
#define OSSL_NAME(name)     NAME_CREATE4(ossl, NAME_1, NAME_2, PREFIX, name)
#define COMMON_NAME(name)   NAME_CREATE3(ossl, NAME_1, NAME_2, name)

#define STRINGIFY_ARG(a) #a
#define STRINGIFY(a) STRINGIFY_ARG(a)

extern const HYBRID_ALG_INFO COMMON_NAME(info);
