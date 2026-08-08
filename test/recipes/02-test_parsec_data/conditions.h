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
 * Fixture for test_parsec: preprocessor condition tracking.
 *
 * OPENSSL_NO_TS, OPENSSL_NO_EC and OPENSSL_NO_DH are used throughout as
 * generic representatives of a feature-disable guard, chosen only because
 * they are well populated in util/libcrypto.num and read unambiguously.
 * Nothing here depends on what those features are, and any other
 * OPENSSL_NO_ name would serve.  Condition spellings that ARE handled
 * specially -- bare ZLIB/BROTLI/ZSTD and the OPENSSL_USE_ prefix, all of
 * which OpenSSL::Ordinals::_parse_features treats differently from
 * OPENSSL_NO_ -- live in polarity.h instead.
 *
 * This file is parser input, not compilable source.  Its exact layout is
 * the thing under test, so the formatter is turned off above and stays
 * off for the rest of the file, comments included.
 */

int cond_none(int x);

#ifndef OPENSSL_NO_TS
int cond_ifndef(int x);
#endif

#if !defined(OPENSSL_NO_TS)
int cond_if_not_defined(int x);
#endif

#ifdef OPENSSL_NO_TS
int cond_ifdef(int x);
#endif

#if defined(OPENSSL_NO_TS)
int cond_if_defined(int x);
#endif

#if !defined(OPENSSL_NO_TS) && !defined(OPENSSL_NO_EC)
int cond_and(int x);
#endif

#if defined(OPENSSL_NO_TS) || defined(OPENSSL_NO_EC)
int cond_or(int x);
#endif

#ifndef OPENSSL_NO_TS
# ifndef OPENSSL_NO_EC
int cond_nested(int x);
# endif
#endif

#ifndef OPENSSL_NO_TS
int cond_else_then(int x);
#else
int cond_else_otherwise(int x);
#endif

#if !defined(OPENSSL_NO_TS) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_DH)
int cond_and3(int x);
#endif

#ifndef OPENSSL_NO_TS
# if !defined(OPENSSL_NO_EC)
int cond_mixed_nesting(int x);
# endif
#endif
