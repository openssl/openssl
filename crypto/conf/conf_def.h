/* crypto/conf/conf_def.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* THIS FILE WAS AUTOMAGICALLY GENERATED!
   Please modify and use keysets.pl to regenerate it. */

#define CONF_NUMBER		1
#define CONF_UPPER		2
#define CONF_LOWER		4
#define CONF_UNDER		256
#define CONF_PUNCTUATION	512
#define CONF_WS			16
#define CONF_ESC		32
#define CONF_QUOTE		64
#define CONF_DQUOTE		1024
#define CONF_COMMENT		128
#define CONF_FCOMMENT		2048
#define CONF_EOF		8
#define CONF_ALPHA		(CONF_UPPER|CONF_LOWER)
#define CONF_ALPHA_NUMERIC	(CONF_ALPHA|CONF_NUMBER|CONF_UNDER)
#define CONF_ALPHA_NUMERIC_PUNCT (CONF_ALPHA|CONF_NUMBER|CONF_UNDER| \
					CONF_PUNCTUATION)

#define KEYTYPES(c)		((unsigned short *)((c)->meth_data))
#ifndef CHARSET_EBCDIC
#define IS_COMMENT(c,a)		(KEYTYPES(c)[(a)&0x7f]&CONF_COMMENT)
#define IS_FCOMMENT(c,a)	(KEYTYPES(c)[(a)&0x7f]&CONF_FCOMMENT)
#define IS_EOF(c,a)		(KEYTYPES(c)[(a)&0x7f]&CONF_EOF)
#define IS_ESC(c,a)		(KEYTYPES(c)[(a)&0x7f]&CONF_ESC)
#define IS_NUMBER(c,a)		(KEYTYPES(c)[(a)&0x7f]&CONF_NUMBER)
#define IS_WS(c,a)		(KEYTYPES(c)[(a)&0x7f]&CONF_WS)
#define IS_ALPHA_NUMERIC(c,a)	(KEYTYPES(c)[(a)&0x7f]&CONF_ALPHA_NUMERIC)
#define IS_ALPHA_NUMERIC_PUNCT(c,a) \
				(KEYTYPES(c)[(a)&0x7f]&CONF_ALPHA_NUMERIC_PUNCT)
#define IS_QUOTE(c,a)		(KEYTYPES(c)[(a)&0x7f]&CONF_QUOTE)
#define IS_DQUOTE(c,a)		(KEYTYPES(c)[(a)&0x7f]&CONF_DQUOTE)

#else /*CHARSET_EBCDIC*/

#define IS_COMMENT(c,a)		(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_COMMENT)
#define IS_FCOMMENT(c,a)	(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_FCOMMENT)
#define IS_EOF(c,a)		(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_EOF)
#define IS_ESC(c,a)		(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_ESC)
#define IS_NUMBER(c,a)		(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_NUMBER)
#define IS_WS(c,a)		(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_WS)
#define IS_ALPHA_NUMERIC(c,a)	(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_ALPHA_NUMERIC)
#define IS_ALPHA_NUMERIC_PUNCT(c,a) \
				(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_ALPHA_NUMERIC_PUNCT)
#define IS_QUOTE(c,a)		(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_QUOTE)
#define IS_DQUOTE(c,a)		(KEYTYPES(c)[os_toascii[a]&0x7f]&CONF_DQUOTE)
#endif /*CHARSET_EBCDIC*/

static unsigned short CONF_type_default[128]={
	0x008,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
	0x000,0x010,0x010,0x000,0x000,0x010,0x000,0x000,
	0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
	0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
	0x010,0x200,0x040,0x080,0x000,0x200,0x200,0x040,
	0x000,0x000,0x200,0x200,0x200,0x200,0x200,0x200,
	0x001,0x001,0x001,0x001,0x001,0x001,0x001,0x001,
	0x001,0x001,0x000,0x200,0x000,0x000,0x000,0x200,
	0x200,0x002,0x002,0x002,0x002,0x002,0x002,0x002,
	0x002,0x002,0x002,0x002,0x002,0x002,0x002,0x002,
	0x002,0x002,0x002,0x002,0x002,0x002,0x002,0x002,
	0x002,0x002,0x002,0x000,0x020,0x000,0x200,0x100,
	0x040,0x004,0x004,0x004,0x004,0x004,0x004,0x004,
	0x004,0x004,0x004,0x004,0x004,0x004,0x004,0x004,
	0x004,0x004,0x004,0x004,0x004,0x004,0x004,0x004,
	0x004,0x004,0x004,0x000,0x200,0x000,0x200,0x000,
	};

static unsigned short CONF_type_win32[128]={
	0x008,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
	0x000,0x010,0x010,0x000,0x000,0x010,0x000,0x000,
	0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
	0x000,0x000,0x000,0x000,0x000,0x000,0x000,0x000,
	0x010,0x200,0x400,0x000,0x000,0x200,0x200,0x000,
	0x000,0x000,0x200,0x200,0x200,0x200,0x200,0x200,
	0x001,0x001,0x001,0x001,0x001,0x001,0x001,0x001,
	0x001,0x001,0x000,0xA00,0x000,0x000,0x000,0x200,
	0x200,0x002,0x002,0x002,0x002,0x002,0x002,0x002,
	0x002,0x002,0x002,0x002,0x002,0x002,0x002,0x002,
	0x002,0x002,0x002,0x002,0x002,0x002,0x002,0x002,
	0x002,0x002,0x002,0x000,0x000,0x000,0x200,0x100,
	0x000,0x004,0x004,0x004,0x004,0x004,0x004,0x004,
	0x004,0x004,0x004,0x004,0x004,0x004,0x004,0x004,
	0x004,0x004,0x004,0x004,0x004,0x004,0x004,0x004,
	0x004,0x004,0x004,0x000,0x200,0x000,0x200,0x000,
	};

