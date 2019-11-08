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
# define X      /* indent of by 1 in preprocessor directive */
fun() {         /* opening brace at end of function definition header */
    if(cond)) { /* too many closing parens */
        stmt;   /* single-line statement in braces */
}}}             /* too many closing braces */
#endif          /* too many #endif */

{ /* unclosed brace */
#if /* unclosed #if */
/* empty line just before EOF: */

