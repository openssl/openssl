# OpenSSL Style Guide

## How to use this guide.

A brief metaphor to serve as a guide both for reviewers and
contributors.

This guide is intended to be applied like Electrical Wiring rules for
a house.

OpenSSL is a large codebase with a long history. Just as a house may
be older than the latest technology and standards for residential
electrical installations, OpenSSL is older than many current
language standards and best practices.

Electrical Wiring rules typically do not require that you rip open
your house with every revision of the rules, and change everything in
your house to the most modern standard of compliance. They do require
that changes need to be made reasonably, to ensure safety and improved
compliance, which can include bringing an area up to date if
significant changes are made to it and it could impact other
areas. Similarly, that is that the intention of the application of
the rules in this guide.

All code in OpenSSL does not conform to this document. This document
is meant to establish the standards required for new code, and for
significant refactors of existing code. For example, if your household
kitchen has old knob and tube wiring, that is correctly installed and
safe and working, you are not required to open up your walls and
rewire your entire kitchen to fix one broken electrical outlet.

However, if you did choose to replace your kitchen wiring for a
renovation, but then hack together something to feed the knob and tube
wiring that contines to the bedroom, You will be asked by the
electrical inspector to bring the bedroom up to date as well.

It is the desire that new contributions meet this standard, and
contributions that significantly change existing areas should bring
them up to this standard where possible and reasonable to do so.

## Webkit style

OpenSSL follows the
[Webkit coding style for C code](https://webkit.org/code-style-guidelines/)
The rest of this document describes differences and clarifications on
top of the base guide.

## Whitespace Indenting and Formatting

The basic style for indenting and whitespace is as per the WebKit
C coding style. This style is enforced by clang-format using the
.clang-format file in this directory. Your changes should be formatted
with clang-format and whatever indentation and line wrapping
clang-format does to them should be deemed correct.

In rare situations it may be necessary to disable clang-format
on a piece of code. This may be done by the comments:

```
/* clang-format off */
I am doing something nasty here.
Reviewers should be triggered.
/* clang-format on */
```
This should be used sparingly, and should not be used if
there is any other way to do what you are doing.

The use of clang-format is intended to ensure basic consistency
and to ease review. Nevertheless, clang-format can not enforce
other necessary aspects of style, and these are documented here.

## Language

The majority of the project is in C, so C++ specific rules in the
aforementioned coding standards do not apply.

To maximise portability the version of C defined in ISO/IEC 9899:1999
should be used. This is more commonly referred to as C99. More modern
version of the C language are not yet supported on some platforms that
OpenSSL is used on and therefore should be avoided.

## Naming

C is a Spartan language, and so should your naming be.

Local variable names should be short, and to the point. If you have
some random integer loop counter, it should probably be called i or j.

Avoid single-letter names when they can be visually confusing, such as
I and O. Avoid other single-letter names unless they are telling in
the given context. For instance, m for modulus and s for SSL pointers
are fine.

Use simple variable names like tmp and name as long as they are
non-ambiguous in the given context.

If you are afraid that someone might mix up your local variable names,
perhaps the function is too long; see the chapter on functions.

Global variables (to be used only if you REALLY need them) need to
have descriptive names, as do global functions. If you have a function
that counts the number of active users, you should call that
count_active_users() or similar, you should NOT call it cntusr().

For getter functions returning a pointer and functions setting a
pointer given as a parameter, use names containing get0_ or get1_
(rather than get_) or set0_ or set1_ (rather than set_) or push0_ or
push1_ (rather than push_) to indicate whether the structure referred
to by the pointer remains as it is or it is duplicated/up-ref’ed such
that an additional free() will be needed.

Use lowercase prefix like ossl_ for internal symbols unless they are
static (i.e., local to the source file).

Use uppercase prefix like EVP_ or OSSL_CMP_ for public (API) symbols.

Do not encode the type into a name (so-called Hungarian notation,
e.g., int iAge).

Align names to terms and wording used in standards and RFCs.

Avoid mixed-case unless needed by other rules. Especially never use
FirstCharacterUpperCase. For instance, use EVP_PKEY_do_something
rather than EVP_DigestDoSomething.

Make sure that names do not contain spelling errors.

## Comments

Use the classic /* ... */ comment markers. Don’t use // ... markers.
Place comments above or to the right of the code they refer to.
Comments are good, but there is also a danger of over-commenting. NEVER try to
explain HOW your code works in a comment. It is much better to write the code
so that it is obvious, and it’s a waste of time to explain badly written code.
You want your comments to tell WHAT your code does, not HOW.
The preferred style for long (multi-line) comments is:

```
/*-
 * This is the preferred style for multi-line
 * comments in the OpenSSL source code.
 * Please use it consistently.
 *
 * Description:  A column of asterisks on the left side,
 * with beginning and ending almost-blank lines.
 */
```

Note the initial hyphen to prevent indent and clang-format from
modifying the comment block. Use this if the comment has particular
formatting that must be preserved.

It’s also important to comment data, whether they are basic types or derived
types. To this end, use just one data declaration per line (no commas for
multiple data declarations). This leaves you room for a small comment on each
item, explaining its use.

In an effort to better translate our source code into documentation that is
more easily understandable to future developers, please also consider adding
Doxygen style comments to any function/data structures/macros/etc that you
alter or create in the development of patches for OpenSSL. The intent is to
provide a more robust set of documentation for our entire code base (with
particular focus on our internal functions and data structures). Please use the
following sample code as a guideline:

```
/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file doxysample.c
 * This is a brief file description that you may add
 * Subsequent lines contain more detailed information about what you will
 * find defined in this file.  It is not currently required that you add a file
 * description, but it's available if you like.
 */

 /**
  * @def MAX(x, y)
  * document a macro that returns the maximum of two inputs.
  * @param x integer input value
  * @param y integer input value
  * @returns the maximum of x and y
  */
  #define MAX(x, y) (x > y ? x : y)

/**
 * @struct foo_st
 * @brief description of the foo_st struct.
 * Optional more detailed description here.
 */
typedef foo_st {
    int a; /**< Describe the a field here */
    char b; /**< Describe the b field here */
} FOO;


/**
 * \brief Describe the function add briefly.
 * Add a more detailed description here, like sums two inputs and returns the
 * results.
 * \param a - input integer to add
 * \param b - input integer to add
 * \returns the sum of a and b
 */
int add(int a, int b)
{
    return a + b;
}
```

## Typedefs

OpenSSL uses typedef’s extensively. For structures, they are all
uppercase and are usually declared like this:

typedef struct name_st NAME;

For examples, look in <openssl/types.h>, but note that there are many
exceptions such as BN_CTX. Typedef’d enum is used much less often and
there is no convention, so consider not using a typedef. When doing
that, the enum name should be lowercase and the values (mostly)
uppercase. Note that enum arguments to public functions are not
permitted.

The ASN.1 structures are an exception to this. The rationale is that
if a structure (and its fields) is already defined in a standard it’s
more convenient to use a similar name. For example, in the CMS code, a
CMS_ prefix is used so ContentInfo becomes CMS_ContentInfo,
RecipientInfo becomes CMS_RecipientInfo etc. Some older code uses an
all uppercase name instead. For example, RecipientInfo for the PKCS#7
code uses PKCS7_RECIP_INFO.

Be careful about common names which might cause conflicts. For
example, Windows headers use X509 and X590_NAME. Consider using a
prefix, as with CMS_ContentInfo, if the name is common or generic. Of
course, you often don’t find out until the code is ported to other
platforms.

A final word on struct’s. OpenSSL has historically made all struct
definitions public; this has caused problems with maintaining binary
compatibility and adding features. Our stated direction is to have
struct’s be opaque and only expose pointers in the API. The actual
struct definition should be defined in a local header file that is not
exported.

## Integers

*When not constrained by legacy code*:

Prefer using explicitly-sized integers where appropriate rather than
generic C ones. For instance, to represent a byte, use `uint8_t`, not
`unsigned char`. Likewise, represent a two-byte field as `uint16_t`, not
`unsigned short`.

Sizes should be represented as `size_t`. When converting to/from an
`int` for legacy purposes ensure to account for overflow/underflow
conditions.

Within structs that are retained across the lifetime of a connection,
for new integer values whose size are known and it's easy to do, use a
smaller integer type like `uint8_t`. This is a "free" connection
footprint optimization for servers. Don't make code significantly more
complex for it, and do still check the bounds when passing in and out
of the struct. This narrowing should not propagate to local variables
and function parameters which should use more conventional integer
types in order to not add complexity for the users of such
functions. Do not retroactively apply this rule to existing integer
values in structures as this could cause ABI breakage.

When doing arithmetic, account for overflow conditions.

Except in platform specific code, do not use `ssize_t`. MSVC lacks it,
and prefer out-of-band error signaling for `size_t` (see Return
Values).

## Preprocessor Directives

Prefer #if defined(FOO) and #if !defined(FOO) to #ifdef and
#ifndef. This allows you to use logical operations when conditional
compilation is dependant on more than one variable instead of nesting
multiple blocks.

All #endif blocks must have a comment matching their #if.

```
#if defined(OPENSSL_LINUX) && (!defined(OPENSSL_NO_HOOBLA) || !defined(OPENSSL_BULA)
...
...
#endif /* defined(OPENSSL_LINUX) && (!defined(OPENSSL_NO_HOOBLA) || !defined(OPENSSL_BULA) */
```

Always prefer to isolate conditional compilation in one place, or use
separate files.  If you need to do "stuff" in many places that can be
done many different ways.  It is very undesirable to have:

```
#if defined(OPENSSL_OS_FOO) || defined (OPENSSL_OS_BAR)
stuff the way foo or bar does it;
#elif defined(OPENSSL_OS_BLAH) || defined (OPENSSL_WOOF)
stuff the way blah or woof does it;
#elif
...
...
...
#endif /* defined(OPENSSL_OS_BLAH) || defined (OPENSSL_WOOF) */
#endif /* defined(OPENSSL_OS_FOO) || defined (OPENSSL_OS_BAR) */
```

in many places.

If you need this you should consider making one function that contains
the os dependent "stuff" with the conditional compilation directives
only in that function, or if this is large, make separate files
(stuff_foo.c stuff_blah.c) which implement the same function and
choose the implementation to include in the build process. The latter
method is friendlier to non mainstream platforms as os dependent
implementations can be maintained in separate files rather than
intrusive code patches.

## Macros and Enums
OpenSSL has historically made extensive use of macros in C, and the C
preprocessor. This was normal practice in older C codebases, when C
compilers were simple things and unable to avoid significant function
call overhead. This is no longer the case, so it is desirable to
reduce this and avoid it in new code.

Macros and labels in enums should be named in
ALL_CAPS_WITH_UNDERSCORES. This convention helps distinguish macros
from functions and variables.

```
#define OPENSSL_MAGIC_FOO 0x12345
```

Enums are preferred when defining several related constants. Note,
however, that enum arguments to public functions are not permitted.

### Avoid Complex Macros

Generally, avoid overly complex or "clever" macros that are difficult
to read, debug, or maintain. Nesting of macros calling other macros
should be avoided. Prioritize clarity and simplicity.

### Avoid Function-like Macros

Functions should be preferred to function-like macros. New code or
refactors should be with functions. Do not 'pre-optimize' for the
overhead of a function call without first implementing with a function
and obtaining measurements to indicate function call overhead is a
significant problem. Only at this point you can consider inlining the
function in preference to a function-like macro, if you can then
measure a significant performance from inlining that does not generate
an undesirable code size increase.

### Macro Parenthesizetion

Always parenthesize arguments in function-like macros to prevent
operator precedence issues during expansion.

Enclose the entire macro definition in parentheses if it expands to an
expression to ensure correct evaluation when used within larger
expressions. For example:

```
#define BOB(blah) ((blah) + 42 - 23 / (blah))
```

### Multi Statement Macros

Enclose multi statement macros in a do {} while(0) loop. Do not
include a semicolon at the end of macros. Do not enclose macros in
braces. This ensures they can be used without problems. For example:

```
/* This is bad */
#define KERMIT(x) muppet((x)); frog((x)); green((x))
if (soemthing)
   KERMIT(bob);
else /* This now breaks */

/* This is also bad, because now you have to omit the semicolon. */
#define KERMIT(x) { muppet((x)); frog((x)); green((x)) }
if (something)
    KERMIT(bob)  /* No semicolon */
else

/* This does not break */
#define KERMIT(x) do { muppet((x)); frog((x)); green((x)) } while (0)
/* Now this works sensibly */
if (something)
    KERMIT(bob);
else

/*
 * But just use a function - Note we now know that x is an
 * integer that has something to do with froggieness and we
 * gain some type safety.
 */
static void kermit(int frogginess)
{
     muppet(froggieness);
     frog(froggieness);
     green(froggieness);
}
if (something)
   kermit(bob);
else
```

### Do not include files as multi-line macros

Do not put code in a file and include it inline

```
	...
	printf "Yolo\n";
#include "./abagfullofcode.inc"
	printf "That was fun\n";
	...
```

Either make a function out of the code and call it or just put the
code in place.

### Avoid Macros With Side Effects:

Be extremely cautious with arguments that may have side effects. as they might be
evaluated multiple times in the macro expansion, leading to unexpected
behavior. Do not make macros that depend upon modifiying a particular
magic name:

```
#define FOO(val) bar(index, (val))
```

It is confusing to the reader and is prone to breakage from seemingly innocent
changes.

Do not write macros that are l-values:

```
FOO(x) = y
```

## Functions

Ideally, functions should be short and sweet, and do just
one thing. A rule of thumb is that they should fit on one or two
screenfuls of text (25 lines as we all know), and do one thing and do
that well.

The maximum length of a function is often inversely proportional to
the complexity and indentation level of that function. So, if you have
a conceptually simple function that is just one long (but simple)
switch statement, where you have to do lots of small things for a lot
of different cases, it’s okay to have a longer function.

If you have a complex function, however, consider using helper
functions with descriptive names. You can ask the compiler to in-line
them if you think it’s performance-critical, and it will probably do a
better job of it than you would have done.

Another measure of complexity is the number of local variables. If
there are more than five to 10, consider splitting it into smaller
pieces. A human brain can generally easily keep track of about seven
different things; anything more and it gets confused. Often things
which are simple and clear now are much less obvious two weeks from
now, or to someone else. An exception to this is the command-line
applications which support many options.

In source files, separate functions with one blank line.  In function
prototypes, include parameter names with their data types. Although
this is not required by the C language, it is preferred in OpenSSL
because it is a simple way to add valuable information for the
reader. The name in the prototype declaration should match the name in
the function definition.

### Checking function arguments

A public function should verify that its arguments are sensible. This
includes, but is not limited to, verifying that:

* Non-optional pointer arguments are not NULL and,
* numeric arguments are within expected ranges.

Where an argument is not sensible, an error should be returned.

### Extending existing functions

From time to time it is necessary to extend an existing function. Typically
this will mean adding additional arguments, but it may also include removal of
some.

Where an extended function should be added the original function should be kept
and a new version created with the same name and an _ex suffix. For example,
the RAND_bytes function has an extended form called RAND_bytes_ex.

Where an extended version of a function already exists and a second extended
version needs to be created then it should have an _ex2 suffix, and so on for
further extensions.

When an extended version of a function is created the order of existing
parameters from the original function should be retained. However new
parameters may be inserted at any point (they do not have to be at the end),
and no longer required parameters may be removed.

### Centralized exiting of functions

The goto statement comes in handy when a function exits from multiple locations
and some common work such as cleanup has to be done. If there is no cleanup
needed then just return directly. The rationale for this is as follows:

* Unconditional statements are easier to understand and follow
* It can reduce excessive control structures and nesting
* It avoids errors caused by failing to update multiple exit points when
  the code is modified
* It saves the compiler work to optimize redundant code away ;)

For example:
```
int fun(int a)
{
    int result = 0;
    char *buffer = OPENSSL_malloc(SIZE);

    if (buffer == NULL)
        return -1;

    if (condition1) {
        while (loop1) {
            ...
        }
        result = 1;
        goto out;
    }
    ...
out:
    OPENSSL_free(buffer);
    return result;
}
```
## Return Values

### Return values in legacy code
Historically, functions in OpenSSL can return values of many different
kinds, and one of the most common is a value indicating whether the
function succeeded or failed. Usually this is:

* 1: success
* 0: failure

Sometimes an additional value is used:

* -1: something bad (e.g., internal error or memory allocation failure)

Other APIs use the following pattern:

* \>= 1: success, with value returning additional information
* <= 0: failure with return value indicating why things failed

Sometimes a return value of -1 can mean “should retry” (e.g., BIO,
SSL, et al).  Functions whose return value is the actual result of a
computation, rather than an indication of whether the computation
succeeded, are not subject to these rules.

When constrained by legacy code, you should follow the existing API's
convention for return values. Be certain you are aware of what this is
when modifying such code.

### Return values in new code

For new code, functions should return `int` with one on
success and zero on error. Do not overload the return value to both
signal success/failure and output an integer. For example:

```
    /**
     * \brief ossl_snuffle_thingamabob snuffles a thingamabob from bytes of input.
     * If a valid thingamabob is snuffled, the result is stored in
     * |*out_thingamabob|. On failure a snuffling error code is stored
     * in |*out_err|.
     * \param input - pointer to the bytes to snuffle
     * \param input_len - the number of bytes available to snuffle from |input|.
     * \param out_err - pointer to a integer to store an error code.
     * \param out_thingamabob - pointer to a thingamabob to store the output.
     * \returns 1 if a thingamabob was snuffled and stored, 0 otherwise.
     */
    int ossl_snuffle_thingamabob(uint8_t *input, size_t input_len,
        int *out_err, thingamabob *out_thingamabob);
```

If a function outputs a pointer to an object on success and there are *no
other outputs*, and you are certain there never would be other outputs,
return the pointer directly and `NULL` on error.

## Allocating memory
OpenSSL provides many general purpose memory utilities, including, but not
limited to: OPENSSL_malloc(), OPENSSL_zalloc(), OPENSSL_realloc(), OPENSSL_
memdup(), OPENSSL_strdup() and OPENSSL_free(). Please refer to the API
documentation for further information about them.

OpenSSL provides special purpose allocators for arrays, including
OPENSSL_malloc_array() and OPENSSL_realloc_array() which take
arguments of the element size and number of elements desired. Always
use these for array allocation, as these functions check for integer
overflow conditions safely when computing the size of the allocation.

If you design an API that requires internal memory allocations before use,
ensure you provide both an initialization API to do the allocation before
using it, and a completion API to de-allocate the memory that consumers
of your API can call when finished.

## Processor-specific code
In OpenSSL’s case the only reason to resort to processor-specific code is for
performance. As it still exists in a general platform-independent algorithm
context, it always has to be backed up by a neutral pure C one. This implies
certain limitations.

The most common way to resolve this conflict is to opt for
short inline assembly function-like snippets, customarily implemented as
macros, so that they can be easily interchanged with other platform-specific or
neutral code. As with any macro, try to implement it as single expression.
You may need to mark your asm statement as volatile, to prevent GCC from
removing it if GCC doesn’t notice any side effects. You don’t always need to do
so, though, and doing so unnecessarily can limit optimization.

When writing a single inline assembly statement containing multiple
instructions, put each instruction on a separate line in a separate quoted
string, and end each string except the last with \n\t to properly indent the
next instruction in the assembly output:

```
asm ("magic %reg1, #42\n\t"
     "more_magic %reg2, %reg3"
     : /* outputs */ : /* inputs */ : /* clobbers */);
```

Large, non-trivial assembly functions go in pure assembly modules, with
corresponding C prototypes defined in C. The preferred way to implement this is
so-called “perlasm”: instead of writing real .s file, you write a perl script
that generates one. This allows use symbolic names for variables (register as
well as locals allocated on stack) that are independent on specific assembler.
It simplifies implementation of recurring instruction sequences with regular
permutation of inputs. By adhering to specific coding rules, perlasm is also
used to support multiple ABIs and assemblers, see crypto/perlasm/x86_64-
xlate.pl for an example.

Another option for processor-specific (primarily SIMD) capabilities is called
compiler intrinsics. We avoid this, because it’s not very much less complicated
than coding pure assembly, and it doesn’t provide the same performance
guarantee across different micro-architecture. Nor is it portable enough to
meet our multi-platform support goals.

##  Asserts
We have 3 kind of asserts. The behaviour depends on being a debug or release
build:
```
Function       failure release failure debug success release success debug
assert         not evaluated   abort         not evaluated   nothing
ossl_assert    returns 0       abort         returns 1       returns 1
OPENSSL_assert abort           abort         nothing         nothing
```

Use OPENSSL_assert() only in the following cases:

* In the libraries when the global state of the software is corrupted and
  there is no way to recover it
* In applications, test programs and fuzzers

Use ossl_assert() in the libraries when the state can be recovered and an error
can be returned. Example code:

```
if (!ossl_assert(!should_not_happen)) {
    /* push internal error onto error stack */
    return BAD;
}
```

Use assert() in libraries when no error can be returned, and what you are checking
is not a run-time dependent condition (such as failure to allocate resources or open
a file) but a programmer error.
