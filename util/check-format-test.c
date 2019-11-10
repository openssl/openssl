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

/* this demonstrates/tests cases where check-format.pl should complain */

/* for each of the following set of lines the tool should complain */
/* tab character: 	 */
/* cr character:  */
/* non-printable ASCII character:  */
/* non-ascii character: ä */
/* whitespace at EOL: */ 
/* comment start: /* inside intra-line comment */
/* multi-line comment with text on first line
 * comment start: /* inside multi-line comment
  * indent off by 1 in multi-line comment
 multi-line comment with text on last line */
*/ /* comment end outside comment */
/* over-loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong line */
 #define X      /* '#' of preprocessor directive not at first column */
# define X      /* indent off by 1 in preprocessor directive */
fun() {         /* opening brace at end of function definition header */
    if(cond)) { /* too many closing parens */
        stmt;   /* single-line statement in braces */
}}}             /* too many closing braces */
#endif          /* too many #endif */
 int f(int a,   /* normal indent off by 1 */
      int b,    /* hanging indent off by -1, flagged unless sloppy_expr */
        int c)  /* hanging indent off by 1 */
{ int x;        /* text after opening brace */
   g(a,         /* normal indent off by -1 */
    b,          /* hanging indent off by -1, flagged unless sloppy_expr */
# define M(X) X /* macro indent off by 1, does not disturb surrounding C code */
      c,        /* hanging indent off by 1 */
   d);          /* hanging indent off by -2 */
    if(e        /* just whitespace at EOL */ 
        && 1)   /* indent off by 1 */
       cmd;     /* indent off by -1 */
    while(e2)   /* just whitespace at EOL */ 
         cmd2;  /* indent off by 1 */
    switch(e) { /* just whitespace at EOL */ 
   case 1:      /* case indent off by -1 */
     default:  /* default indent off by 1 */
    }           /* just whitespace at EOL */ 
  label:        /* label indent off by 1*/
x; }            /* text before closing brace */
/* here the tool should stop complaining apart from those three issues at EOF */


{ /* unclosed brace */
#if /* unclosed #if */
/* empty line follows just before EOF: */

