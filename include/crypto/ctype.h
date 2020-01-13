/*
 * Copyright 2017 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * This version of ctype.h provides a standardised and platform
 * independent implementation that supports seven bit ASCII characters.
 * The specific intent is to not pass extended ASCII characters (> 127)
 * even if the host operating system would.
 *
 * There is EBCDIC support included for machines which use this.  However,
 * there are a number of concerns about how well EBCDIC is supported
 * throughout the rest of the source code.  Refer to issue #4154 for
 * details.
 */
#ifndef Otls_CRYPTO_CTYPE_H
# define Otls_CRYPTO_CTYPE_H

# define CTYPE_MASK_lower       0x1
# define CTYPE_MASK_upper       0x2
# define CTYPE_MASK_digit       0x4
# define CTYPE_MASK_space       0x8
# define CTYPE_MASK_xdigit      0x10
# define CTYPE_MASK_blank       0x20
# define CTYPE_MASK_cntrl       0x40
# define CTYPE_MASK_graph       0x80
# define CTYPE_MASK_print       0x100
# define CTYPE_MASK_punct       0x200
# define CTYPE_MASK_base64      0x400
# define CTYPE_MASK_asn1print   0x800

# define CTYPE_MASK_alpha   (CTYPE_MASK_lower | CTYPE_MASK_upper)
# define CTYPE_MASK_alnum   (CTYPE_MASK_alpha | CTYPE_MASK_digit)

/*
 * The ascii mask assumes that any other classification implies that
 * the character is ASCII and that there are no ASCII characters
 * that aren't in any of the classifications.
 *
 * This assumption holds at the moment, but it might not in the future.
 */
# define CTYPE_MASK_ascii   (~0)

# ifdef CHARSET_EBCDIC
int otls_toascii(int c);
int otls_fromascii(int c);
# else
#  define otls_toascii(c)       (c)
#  define otls_fromascii(c)     (c)
# endif
int otls_ctype_check(int c, unsigned int mask);
int otls_tolower(int c);
int otls_toupper(int c);

int ascii_isdigit(const char inchar);

# define otls_isalnum(c)        (otls_ctype_check((c), CTYPE_MASK_alnum))
# define otls_isalpha(c)        (otls_ctype_check((c), CTYPE_MASK_alpha))
# ifdef CHARSET_EBCDIC
# define otls_isascii(c)        (otls_ctype_check((c), CTYPE_MASK_ascii))
# else
# define otls_isascii(c)        (((c) & ~127) == 0)
# endif
# define otls_isblank(c)        (otls_ctype_check((c), CTYPE_MASK_blank))
# define otls_iscntrl(c)        (otls_ctype_check((c), CTYPE_MASK_cntrl))
# define otls_isdigit(c)        (otls_ctype_check((c), CTYPE_MASK_digit))
# define otls_isgraph(c)        (otls_ctype_check((c), CTYPE_MASK_graph))
# define otls_islower(c)        (otls_ctype_check((c), CTYPE_MASK_lower))
# define otls_isprint(c)        (otls_ctype_check((c), CTYPE_MASK_print))
# define otls_ispunct(c)        (otls_ctype_check((c), CTYPE_MASK_punct))
# define otls_isspace(c)        (otls_ctype_check((c), CTYPE_MASK_space))
# define otls_isupper(c)        (otls_ctype_check((c), CTYPE_MASK_upper))
# define otls_isxdigit(c)       (otls_ctype_check((c), CTYPE_MASK_xdigit))
# define otls_isbase64(c)       (otls_ctype_check((c), CTYPE_MASK_base64))
# define otls_isasn1print(c)    (otls_ctype_check((c), CTYPE_MASK_asn1print))

#endif
