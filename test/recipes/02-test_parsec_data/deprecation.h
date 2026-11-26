/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* clang-format off */

/*
 * Fixture for test_parsec: deprecation guards and attributes.
 *
 * Three distinct spellings meet in this area and must not be confused:
 *
 *   OPENSSL_NO_DEPRECATED_x_y   the feature-disable guard macro
 *   OSSL_DEPRECATEDIN_x_y       the compiler attribute on a declaration
 *   DEPRECATED_x_y              the condition name recorded in util/*.num
 *
 * ParseC records the first spelling as it stands; the third is produced
 * downstream by OpenSSL::Ordinals, which strips the OPENSSL_NO_ prefix.
 * The dep_guard_and* cases below place the guard in one term of a
 * compound condition, which is where the rewrite ParseC used to perform
 * discarded the sibling terms.  See the assertions in 02-test_parsec.t.
 *
 * This file is parser input, not compilable source.
 */

#ifndef OPENSSL_NO_DEPRECATED_3_0
int dep_guard_ifndef(int x);
#endif

#if !defined(OPENSSL_NO_DEPRECATED_3_0)
int dep_guard_modern(int x);
#endif

#if !defined(OPENSSL_NO_TS) && !defined(OPENSSL_NO_DEPRECATED_3_0)
int dep_guard_and(int x);
#endif

#if !defined(OPENSSL_NO_DEPRECATED_3_0) && !defined(OPENSSL_NO_TS)
int dep_guard_and_reversed(int x);
#endif

#ifndef OPENSSL_NO_TS
# ifndef OPENSSL_NO_DEPRECATED_3_0
int dep_guard_nested(int x);
# endif
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0 int dep_attr_leading(int x);
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
int OSSL_DEPRECATEDIN_3_0 dep_attr_middle(int x);
#endif

#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0_FOR("use something else") int dep_attr_for(int x);
#endif

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
int dep_guard_older(int x);
#endif
