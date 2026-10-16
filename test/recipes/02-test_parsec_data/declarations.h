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
 * Fixture for test_parsec: declaration shapes.
 *
 * Entry types recorded by ParseC are F (function), V (variable),
 * T (typedef) and M (macro).  util/mknum.pl keeps only F and V, drops
 * anything whose return type matches /\b(?:ossl_)inline/, and takes M
 * only from the symbol hacking file.
 *
 * Note the extern cases: none of them are recorded at all.  That has no
 * live consequence today, as neither util/libcrypto.num nor
 * util/libssl.num contains a VARIABLE entry, but it means the V path is
 * reachable only from a non-extern declaration, which a public header
 * would not use.
 *
 * This file is parser input, not compilable source.
 */

int decl_plain(int x);

void decl_void(void);

char *decl_returns_pointer(int x);

const char *decl_returns_const_pointer(int x);

int decl_multiline(int a,
                   int b,
                   int c);

int decl_fn_ptr_param(int (*cb)(int, void *), void *arg);

typedef int (*decl_cb_type)(int, void *);

int decl_stack_param(STACK_OF(X509) *sk);

STACK_OF(X509) *decl_stack_return(int x);

int decl_plain_var;

extern int decl_extern_var;

extern const char *decl_extern_ptr;

extern int decl_extern_array[];

static ossl_inline int decl_inline(int x) { return x; }

#define DECL_MACRO(x) ((x) + 1)

#define DECL_MACRO_VALUE 42

struct decl_struct_st;

typedef struct decl_struct_st DECL_STRUCT;

int decl_after_typedef(DECL_STRUCT *p);
