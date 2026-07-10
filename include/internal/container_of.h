/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_CONTAINER_OF_H
#define OSSL_INTERNAL_CONTAINER_OF_H
#pragma once

#include <stddef.h>

/*
 * Recover the containing struct from a pointer to one of its embedded
 * fields.
 *
 *     struct foo {
 *         int        bar;
 *         struct lnk link;
 *     };
 *     struct lnk *n = ...;
 *     struct foo *p = CONTAINER_OF(n, struct foo, link);
 *
 *
 * Const-correctness: a const ptr yields a non-const struct pointer.
 * Use CONTAINER_OF_CONST if you need const preserved.
 */
#define CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define CONTAINER_OF_CONST(ptr, type, member) \
    (const type *)CONTAINER_OF(ptr, type, member)

#endif
