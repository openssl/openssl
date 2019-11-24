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
 * This demonstrates/tests cases where check-format.pl should report issues.
 * Some of the reports are due to sanity checks for proper nesting of comment
 * delimiters and parenthesis-like symbols, e.g., on unexpected/unclosed braces.
 */

/*
 * The '@'s after '*' are used for self-tests: they mark lines containing
 * a single flaw that should be reported. Normally it should be reported
 * while handling the given line, but in case of delayed checks there is a
 * following digit indicating the number of reports expected for this line.
 */

/* For each of the following set of lines the tool should complain once */
/*@ tab character: 	 */
/*@ intra-line carriage return character:  */
/*@ non-printable ASCII character:  */
/*@ non-ASCII character: ä */
/*@ space at EOL: */ 
// /*@ end-of-line comment style not allowed for C90 */
/*X */ /*@ no space after comment start, reported unless sloppy-spc */
/* X*/ /*@ no space before comment end , reported unless sloppy-spc */
/*@ comment starting delimiter: /* inside intra-line comment */
 /*@ normal comment indent off by 1, reported unless sloppy-cmt */
 /*@
  *@ above multi-line comment start indent off by 1, reported unless sloppy-cmt; this comment line is too long
   *@ multi-line comment further off by 1 relative to comment start
*/ /*@ multi-line comment end indent off by -2 relative to comment start */
/*@ multi-line comment starting with text on first line
 *@ comment starting delimiter: /* inside multi-line comment
*@ multi-line comment indent off by -1
 *X*@ no spc after leading'*' in multi-line comment, reported unless sloppy-spc
 *@0 more than double space after '.'   in comment, reported unless sloppy-spc
 *@2 multi-line comment ending with text on last line */
*/ /*@ unexpected comment end symbol outside comment */
/*@ comment line is 4 columns tooooooooooooooooo wide, reported unless sloppy-len */
/*@ comment line is 5 columns toooooooooooooooooooooooooooooooooooooooooooooo wide */
 #define X          /*@ indent of preprocessor directive off by 1 (must be 0) */
# define Y          /*@ nesting of preprocessor directive off by 1  */
typedef struct s  { /*@0 double space, reported unless sloppy-spc */
    enum {          /*@2  double space in comment, reported unless sloppy-spc */
           w = 0    /*@ expression indent inside type decl off by 1 or 3 */
            && 1,   /*@ expr indent off off by 2 or 4, no exception for '&&' */
         x = 1,     /*@ expr indent off by -1 or 1 */
          y,z       /*@ no space after ',', reported unless sloppy-spc */
    } e_type ;      /*@ space before ';', reported unless sloppy-spc */
   union {          /*@ statement/type declaration indent off by -1 */
        struct{} s; /*@ no space before '{', reported unless sloppy-spc */
    }u_type;        /*@ no space after '}', reported unless sloppy-spc */
    };              /*@ statement/type declaration indent off by 4 */
void fun(int a) {   /*@ opening brace at end of function definition header */
    if (a)) {       /*@ unexpected closing parenthesis outside expression */
        return;     /*@0 (1-line) single statement in braces */
}}}                 /*@2 unexpected closing brace (too many '}') outside expr */
#endif              /*@ unexpected #endif */
 int f(int a,       /*@ stmt/function definition indent off by 1 */
      int b,        /*@ expr/function definition indent off by -1 */
        int c)      /*@ expr/function definition indent off by 1 */
{ int               /*@ code after '{' opening block */
    x = 1) +        /*@ unexpected closing parenthesis */
        2] -        /*@ unexpected closing bracket */
        3} *        /*@ unexpected closing brace within expression */
        4:;         /*@ unexpected ':' (without preceding '?') within expr */
    s = {           /*@0 unclosed brace within initializer/enum expression */
         (          /*@0 unclosed parenthesis */
          a[x       /*@0 unclosed bracket */
            ?;      /*@4 unclosed '? (conditional expression) */
   ggggfunc(a,      /*@ statement indent off by -1 */
           aligned to /*@ expr indent off by -1 accepted if sloppy-hang */ right
          b1,       /*@ expr indent off by -2 */
          b2,       /*@ expr indent again off -2, accepted if sloppy-hang */
        b3, /*@ expr indent off -4 but @ extra indent accepted if sloppy-hang */
   again aligned to /*@ expr indent off by -9 (left of stmt indent, .. */ right,
            c1 == /*@ .. so reported also with sloppy-hang; this line is too long */ c2
# define M(X) X     /*@ nesting indent of preprocessor directive off by 1 */
             ? 1    /*@ expr indent off by 1 */
              : 2); /*@ expr indent off by 2, or off by 1 for leading ':' */
    if(a            /*@ no space after 'if', reported unless sloppy-spc */
         || b ==    /*@ expr indent of leading '||' off by 2 or -2 */
       (c*= 2) +    /*@ no space before '*=', reported unless sloppy-spc */
       ( 0) -       /*@ space after '(', reported unless sloppy-spc */
       g (1) *      /*@ space before '(', reported unless sloppy-spc */
       a %2 /       /*@ no space after '%', reported unless sloppy-spc */
       1 +/* */     /*@ no space before comment, reported unless sloppy-spc */
       /* */b)      /*@ no space after comment, reported unless sloppy-spc */
         x = a + b  /*@ extra single-statement indent off by 1 */
               + c; /*@ double extra single-statement indent off by 3 */
    do{ x = 3; }    /*@ no space before '{', reported unless sloppy-spc */
    while (a+ 0);   /*@ no space before '+', reported unless sloppy-spc */
    switch (b ) {   /*@ space before ')', reported unless sloppy-spc */
   case 1:          /*@ 'case' special statement indent off by -1 */
     default:       /*@ 'default' special statement indent off by 1 */
}                   /*@ statement indent off by -4 */
  label:            /*@ label special statement indent off by 1 */
    return x; }     /*@ code before '}' closing block */
}                   /*@ unexpected closing brace, at outermost block level */
/* Here the tool should stop complaining apart from the below issues at EOF */

{                   /*@0 unclosed brace at block level, outside stmt/exp/decl */
    (               /*@0 unclosed parenthesis */
#if                 /*@0 unclosed #if */
     0              /*@0 empty line follows just before EOF: */

