/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * These are test cases where check-format.pl should not report issues.
 * There are some known false positives, though, which are marked below.
 */

int f(void)
{
#if X
    if (1) /* bad style: just part of control structure depends on #if */
#else
    if (2) /*@ resulting false positive */
#endif
        c; /*@ resulting false positive */

    if (1)
        if (2)
            c;
        else /* TODO correct false positive: indent = 8 != 4 for stmt/decl */
            e; /* TODO correct false: indent = 12 != 8 for hanging stmt/expr */
    else
        f;
    do
        do
            2;
        while (1); /* TODO correct false posititive */
    while (2);

    if (1)
        f(a, b);
    do
        1; while (2);
    if (1)
        f(a, b);
    else
        do
            1;
        while (2); /* TODO correct false posititive */
    if (1)
        f(a, b);
    else do /*@ (non-brace) code before 'do' just to construct case */
             1; /* TODO correct false posititive */
        while (2); /* TODO correct false posititive */
    if (1)
        f(a,
          b); do /*@ (non-brace) code before 'do' just to construct case */
                  1; /* TODO correct false po: indent = 18 != 4 for stmt/decl */
    while (2);

    if (1)
        f(a, b);
    else
        return;
    if (1)
        f(a,
          b); else /*@ (non-brace) code before 'else' just to construct case */
        do
            1;
        while (2); /* TODO correct false pos: indent = 8 != 4 for stmt/decl */

    if (1)
        {
            c;
        }
    /* this comment is wrongly indented if it refers to the block before */
    d;

    if (1) {
        2;
    } else
        3;
    do {
    } while (x);
    if (1) {
        2;
    } else {
        3;
    }
    if (4)
        5;
    else
        6;
}
typedef * d(int)
    x;
typedef (int)
x;
typedef (int)*()
    x;
typedef *int *
x;
typedef OSSL_CMP_MSG *(*cmp_srv_process_cb_t)
    (OSSL_CMP_SRV_CTX *ctx, OSSL_CMP_MSG *msg)
    xx;
int f()
{
    c;
    if (1) {
        c;
    }
    c;
    if (1)
        if (2)
            {
                c;
            }
    e;
    const usign = {
                   0xDF,
                   {
                    dd
                   },
                   dd
    };
    const unsign = {
                    0xDF, {
                           dd
                    },
                    dd
    };
}
const unsigned char trans_id[OSSL_CMP_TRANSACTIONID_LENGTH] = {
                                                               0xDF,
};
const unsigned char trans_id[OSSL_CMP_TRANSACTIONID_LENGTH] =
    {
     0xDF,
    };
typedef
int
a;

typedef
struct
{
    int a;
} b;
typedef enum {
              w = 0
} e_type;
typedef struct {
    enum {
          w = 0
    } e_type;
    enum {
          w = 0
    } e_type;
} e;
struct {
    enum {
          w = 0
    } e_type;
} e;
struct
{
    enum {
          w = 0
    } e_type;
} e;
enum {
      enum {
            w = 0
      } e_type;
} e;
struct
{
    enum {
          w = 0
    } e_type;
} e;

#define X  1          + 1
#define Y  /* .. */ 2 + 2
#define Z  3          + 3
