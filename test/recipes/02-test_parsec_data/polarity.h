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
 * Fixture for test_parsec: condition spelling, polarity and mixing.
 *
 * Unlike conditions.h, the names here are NOT interchangeable.
 * OpenSSL::Ordinals::_parse_features gives four of them special
 * treatment, so the set is chosen deliberately:
 *
 *   OPENSSL_NO_x     recorded negated
 *   OPENSSL_USE_x    recorded positive
 *   ZLIB             recorded positive, matched as a bare name
 *   BROTLI, ZSTD     as ZLIB
 *
 * ParseC's #if handler reads the whole expression, so the mixed-polarity
 * cases below keep every term they are written with, and none of them
 * warns.  A warning belongs to an expression carrying a term the parser
 * cannot represent, a numeric comparison say; conditions.h holds those.
 * util/mknum.pl is invoked from the build with --no-warnings, so warnings
 * are not seen in practice, which is why the transcript records them.
 *
 * This file is parser input, not compilable source.
 */

/* Uniform polarity: both shapes the handler accepts. */

#if !defined(OPENSSL_NO_TS) && !defined(OPENSSL_NO_EC)
int uniform_and_negated(int x);
#endif

#if defined(OPENSSL_NO_TS) || defined(OPENSSL_NO_EC)
int uniform_or_positive(int x);
#endif

/* Bare names given special treatment downstream. */

#ifndef ZLIB
int bare_zlib_ifndef(int x);
#endif

#ifdef ZLIB
int bare_zlib_ifdef(int x);
#endif

#if defined(ZLIB)
int bare_zlib_if_defined(int x);
#endif

#if defined(ZLIB) || defined(BROTLI) || defined(ZSTD)
int bare_compression_or(int x);
#endif

/* The OPENSSL_USE_ prefix, recorded with positive polarity. */

#ifdef OPENSSL_USE_NODELETE
int use_prefix_ifdef(int x);
#endif

/* Mixed polarity within one expression. */

#if defined(ZLIB) && !defined(OPENSSL_NO_COMP)
int mixed_positive_first(int x);
#endif

#if !defined(OPENSSL_NO_COMP) && defined(OPENSSL_USE_NODELETE)
int mixed_negative_first(int x);
#endif

#if !defined(OPENSSL_NO_TS) && defined(OPENSSL_NO_EC)
int mixed_no_prefix_only(int x);
#endif

/*
 * The example given in STYLE.md's "Preprocessor directives" section, which
 * mixes polarity and nests a disjunction inside a conjunction.
 */

#if defined(OPENSSL_LINUX) && (!defined(OPENSSL_NO_HOOBLA) || !defined(OPENSSL_BULA))
int style_md_worked_example(int x);
#endif
