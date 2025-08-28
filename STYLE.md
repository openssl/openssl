# OpenSSL Style Guide

OpenSSL usually follows the
[Linux kernel coding style](https://www.kernel.org/doc/html/next/process/coding-style.html#codingstyle)
The rest of this document describes differences and clarifications on
top of the base guide.

## Whitespace Indenting and Formatting

The basic style for indenting and whitespace is as per the Linux
kernel coding style. This style is enforced by clang-format using the
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

### In code only for OpenSSL 3.6 and later

To maximise portability the version of C defined in ISO/IEC 9899:1999
should be used. This is more commonly referred to as C99. More modern
version of the C language are not yet supported on some platforms that
OpenSSL is used on and therefore should be avoided.

### In code used prior to OpenSSL 3.6

To maximise portability the version of C defined in ISO/IEC 9899:1990
should be used. This is more commonly referred to as C90. ISO/IEC
9899:1999 (also known as C99) is not yet supported on some platforms
that OpenSSL is used on and therefore should be avoided. This includes
C99 style initializers, and variable declarations in the middle of a
block or inside a `for` loop. Do not mix local variable declarations
and statements.

Separate variable declarations at the start of a block from subsequent
statements with an empty line.

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

Note the initial hyphen to prevent indent from modifying the comment block. Use this
if the comment has particular formatting that must be preserved.

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

    * non-optional pointer arguments are not NULL and
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
    * >= 1: success, with value returning additional information
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
     * \brief SNUFFLE_thingamabob snuffles a thingamabob from bytes of input.
     * If a valid thingamabob is snuffled, the result is stored in
     * |*out_thingamabob|.
     * \param input - pointer to the bytes to snuffle
     * \param input_len - the number of bytes available to snuffle from |input|.
     * \param out_thingamabob - pointer to a thingamabob to store the output.
     * \returns 1 if a thingamabob was snuffled and stored, 0 otherwise.
     */
    int SNUFFLE_thingamabob(uint8_t *input, size_t input_len,
         thingamabob *out_thingamabob);
```

Try hard to avoid needing more than a true/false result code. If you
must, define an enum rather than arbitrarily assigning meaning to int
values.

If a function outputs a pointer to an object on success and there are *no
other outputs*, return the pointer directly and `NULL` on error.

## Macros and Enums
Names of macros defining constants and labels in enums are in uppercase:

```
#define CONSTANT 0x12345
```

Enums are preferred when defining several related constants. Note, however,
that enum arguments to public functions are not permitted.
Macro names should be in uppercase, but macros resembling functions may be
written in lower case. Generally, inline functions are preferable to macros
resembling functions.
Macros with multiple statements should be enclosed in a do - while block:

```
#define macrofun(a, b, c)   \
    do {                    \
        if (a == 5)         \
            do_this(b, c);  \
    } while (0)
Do not write macros that affect control flow:
#define FOO(x)                 \
    do {                       \
        if (blah(x) < 0)       \
            return -EBUGGERED; \
    } while(0)
```

Do not write macros that depend on having a local variable with a magic name:

```
#define FOO(val) bar(index, val)
```

It is confusing to the reader and is prone to breakage from seemingly innocent
changes.

Do not write macros that are l-values:

```
FOO(x) = y
```

This will cause problems if, e.g., FOO becomes an inline function.
Be careful of precedence. Macros defining an expression must enclose the
expression in parentheses unless the expression is a literal or a function
application:

```
#define SOME_LITERAL 0x4000
#define CONSTEXP (SOME_LITERAL | 3)
#define CONSTFUN foo(0, CONSTEXP)
```

Beware of similar issues with macros using parameters. Put parentheses around
uses of macro arguments unless they are passed on as-is to a further macro or
function. For example,

```
#define MACRO(a,b) ((a) * func(a, b))
```

## Allocating memory
OpenSSL provides many general purpose memory utilities, including, but not
limited to: OPENSSL_malloc(), OPENSSL_zalloc(), OPENSSL_realloc(), OPENSSL_
memdup(), OPENSSL_strdup() and OPENSSL_free(). Please refer to the API
documentation for further information about them.

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

## Header Files

### Headers should be self-contained

Header files should be self contained. This means that they themselves
include their prerequisites, and that they should compile all on their own.

This ensures that users and refactoring tools do not need to adhere to
special conditions to use the header.

There are rare cases when a file is designed to be included and is not
self-contained. These are typically intended to be included at unusual
locations such as in the middle of another file. They might not use
header guards and might not be self contained. Name such files with the
.inc extension, and encase them in a block disabling clang-format.
```
/* clang-format off */
/*
 * I am using the preprocessor to insert code here for a very special
 * reason.
 */
#include "hoobla.c.inc"
#include "porkrind.c.inc"
/* clang-format on */
```
Use them sparingly and always prefer self contained headers wherever possible.

### Headers should have a #define guard

All header files should have #define guards to prevent multiple inclusion.

The format of the guard name should be OSSL_<PATH>_<FILE>_H.

To guarantee uniqueness, they should be based on the full path in the
openssl source tree. For example, the file openssl/crypto/thingamabob/snuffle.h
should have it's entire contents after the copyright notice enclosed
in:

```
#if !defined(OSSL_CRYPTO_THINGAMABOB_SNUFFLE_H)
#define OSSL_CRYPTO_THINGAMABOB_SNUFFLE_H)

...

#endif  /* !defined(OSSL_CRYPTO_THINGAMABOB_SNUFFLE_H) */
```

### Include What You Use

If a source or header file refers to a symbol defined elsewhere, the
file should directly include a header file which properly intends to
provide a declaration or definition of that symbol. It should not
include header files for any other reason.

Do not rely on transitive inclusions. This allows people to remove
no-longer-needed #include statements from their headers without
breaking things. This also applies to related headers - foo.c should
include bar.h if it uses a symbol from it even if it includes a foo.h
which also includes bar.h.

### Forward Declarations

Avoid using forward declarations where possible. Instead, include the headers you need.

### Names and Order of Include Files

Include file blocks and ordering within the blocks is enforced by
clang-format. For the file "foo.c" this will correspond to:

* "internal/deprecated.h" if needed.
* "foo.h" corresponding to what is provided in foo.c
* C standard library, POSIX, Linux, and Windows system headers.
* <openssl/*.h> openssl public include headers
* "internal/*.h" internal include headers
* "crypto/*.h" private crypto headers
* "foo_local.h" and other local include files from the current directory.

Each of these groups will be sorted alphabetically with a blank line
in between them.

Prefer to include files from the current directory, or relative to
openssl/include, and avoid the use of "." and ".." when possible.

### System specific includes

Sometime system-specific code needs conditional includes. Such code
can put in conditional includes after other includes as necessary as
long as such conditional code is kept small and localized.
