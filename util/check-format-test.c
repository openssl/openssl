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

/* This demonstrates/tests cases where check-format.pl should complain */

/* For each of the following set of lines the tool should complain */
/*@ tab character: 	 */
/*@ cr character:  */
/*@ non-printable ASCII character:  */
/*@ non-ascii character: ä */
/*@ space at EOL: */ 
// /*@ end-of-line comment style not allowed for C90 */
/*@ comment start: /* inside intra-line comment */
/*@ multi-line comment with text on first line
 *@ comment start: /* inside multi-line comment
  *@ indent off by 1 in multi-line comment
 *@ multi-line comment with text on last line */
*/ /*@ comment end outside comment */
/*@ line is 1 column tooooooooooooooooooooooooooooooooooooooooooooooooooo wide */
 #define X          /*@ indent of '#' (preprocessor directive) off by 1 */
# define X          /*@ indent off by 1 in preprocessor directive */
typedef struct s  { /*@ double space, flagged unless sloppy_space */
     enum {         /*@ indent off by 1 */
          x = 1,    /*@ hanging indent off by 1 (or else -1 for sloppy expr) */
           y,z      /*@ no space after first comma */
    } type ;        /*@ space before ; */
   union {          /*@ indent off by -1 */
        struct{ T m; } n; /*@ no space before { */
    }p;             /*@ no space after } */
    };              /*@ indent off by 4 */
fun() {             /*@ opening brace at end of function definition header */
    if (cond)) {    /*@ too many closing parens */
        stmt;       /*@ single-line statement in braces */
}}}                 /*@ too many closing braces */
#endif              /*@ unexpected #endif */
 int f(int a,       /*@ normal indent off by 1 */
      int b,        /*@ hanging indent off by -1, flagged unless sloppy_expr */
        int c)      /*@ hanging indent off by 1 */
{ int               /*@ text after opening brace */
    x = 0);         /*@ 1 too many closing paren */
   g(a,             /*@ normal indent off by -1 */
    b,              /*@ hanging indent off by -1, flagged unless sloppy_expr */
# define M(X) X     /*@ macro indent off by 1 */
      c ? 1         /*@ hanging indent off by 1 (or else -2 for sloppy expr) */
         : 2,       /*@ hanging indent further off by 1 (or else -5 f sl. e.)  */
   d);              /*@ hanging indent off by -2 (or else -1 for sloppy expr)  */
    if (e+          /*@ no space before + */
        g*= 2       /*@ no space before *= */
        h %2        /*@ no space after % */
         && 1)      /*@ hanging indent off by 1 or -3 */
       cmd;         /*@ indent off by -1 */
    while ( e2)     /*@ space after ( */
         cmd2;      /*@ indent off by 1 */
    do{ c3; }       /*@ again no space before { */
    while(e3);      /*@ no space after 'while' */
    switch (e ) {   /*@ space before ) */
   case 1:          /*@ case indent off by -1 */
     default:       /*@ default indent off by 1 */
}                   /*@ indent off by -4 */
  label:            /*@ label indent off by 1*/
x; }                /*@ text before closing brace */
/* Here the tool should stop complaining apart from the below issues at EOF */

{                   /*@ unclosed brace */
#if                 /*@ unclosed #if */
                    /*@ space/empty line follows just before EOF: */

