/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef HEADER_NUMBERS_H
# define HEADER_NUMBERS_H

# include <limits.h>

# if (-1 & 3) == 0x03		/* Two's complement */

#  define __MAXUINT__(T) ((T) -1)
#  define __MAXINT__(T) ((T) ((((T) 1) << ((sizeof(T) * CHAR_BIT) - 1)) ^ __MAXUINT__(T)))
#  define __MININT__(T) (-__MAXINT__(T) - 1)

# elif (-1 & 3) == 0x02		/* One's complement */

#  define __MAXUINT__(T) (((T) -1) + 1)
#  define __MAXINT__(T) ((T) ((((T) 1) << ((sizeof(T) * CHAR_BIT) - 1)) ^ __MAXUINT__(T)))
#  define __MININT__(T) (-__MAXINT__(T))

# elif (-1 & 3) == 0x01		/* Sign/magnitude */

#  define __MAXINT__(T) ((T) (((((T) 1) << ((sizeof(T) * CHAR_BIT) - 2)) - 1) | (((T) 1) << ((sizeof(T) * CHAR_BIT) - 2))))
#  define __MAXUINT__(T) ((T) (__MAXINT__(T) | (((T) 1) << ((sizeof(T) * CHAR_BIT) - 1))))
#  define __MININT__(T) (-__MAXINT__(T))

# else

#  error "do not know the integer encoding on this architecture"

# endif

# ifndef INT8_MAX
#  define INT8_MIN __MININT__(int8_t)
#  define INT8_MAX __MAXINT__(int8_t)
#  define UINT8_MAX __MAXUINT__(uint8_t)
# endif

# ifndef INT16_MAX
#  define INT16_MIN __MININT__(int16_t)
#  define INT16_MAX __MAXINT__(int16_t)
#  define UINT16_MAX __MAXUINT__(uint16_t)
# endif

# ifndef INT32_MAX
#  define INT32_MIN __MININT__(int32_t)
#  define INT32_MAX __MAXINT__(int32_t)
#  define UINT32_MAX __MAXUINT__(uint32_t)
# endif

# ifndef INT64_MAX
#  define INT64_MIN __MININT__(int64_t)
#  define INT64_MAX __MAXINT__(int64_t)
#  define UINT64_MAX __MAXUINT__(uint64_t)
# endif

#endif

