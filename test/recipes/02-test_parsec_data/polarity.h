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
 * ParseC's #if handler accepts exactly two shapes: a chain of
 * defined(...) joined by ||, or a chain of !defined(...) joined by &&.
 * Any other expression keeps only the leading term and emits a
 * "complicated #if expression" warning.  That warning is the parser
 * reporting that it has discarded information, and util/mknum.pl is
 * invoked from the build with --no-warnings, so it is not seen in
 * practice.  The transcript records these warnings deliberately.
 *
 * Note that the mixed-polarity cases below are not asserted as bugs:
 * the limitation is deliberate and announced.  What is recorded here is
 * which shapes trip it, so that a change to the handler is visible.
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

/* Mixed polarity within one expression: only the leading term survives. */

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
