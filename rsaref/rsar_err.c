/* lib/rsaref/rsaref_err.c */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
#include <stdio.h>
#include "err.h"
#include "rsaref.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA RSAREF_str_functs[]=
	{
{ERR_PACK(0,RSAREF_F_BN_REF_MOD_EXP,0),	"BN_REF_MOD_EXP"},
{ERR_PACK(0,RSAREF_F_RSAREF_BN2BIN,0),	"RSAREF_BN2BIN"},
{ERR_PACK(0,RSAREF_F_RSA_BN2BIN,0),	"RSA_BN2BIN"},
{ERR_PACK(0,RSAREF_F_RSA_PRIVATE_DECRYPT,0),	"RSA_PRIVATE_DECRYPT"},
{ERR_PACK(0,RSAREF_F_RSA_PRIVATE_ENCRYPT,0),	"RSA_PRIVATE_ENCRYPT"},
{ERR_PACK(0,RSAREF_F_RSA_PUBLIC_DECRYPT,0),	"RSA_PUBLIC_DECRYPT"},
{ERR_PACK(0,RSAREF_F_RSA_PUBLIC_ENCRYPT,0),	"RSA_PUBLIC_ENCRYPT"},
{ERR_PACK(0,RSAREF_F_RSA_REF_BN2BIN,0),	"RSA_REF_BN2BIN"},
{ERR_PACK(0,RSAREF_F_RSA_REF_MOD_EXP,0),	"RSA_REF_MOD_EXP"},
{ERR_PACK(0,RSAREF_F_RSA_REF_PRIVATE_DECRYPT,0),	"RSA_REF_PRIVATE_DECRYPT"},
{ERR_PACK(0,RSAREF_F_RSA_REF_PRIVATE_ENCRYPT,0),	"RSA_REF_PRIVATE_ENCRYPT"},
{ERR_PACK(0,RSAREF_F_RSA_REF_PUBLIC_DECRYPT,0),	"RSA_REF_PUBLIC_DECRYPT"},
{ERR_PACK(0,RSAREF_F_RSA_REF_PUBLIC_ENCRYPT,0),	"RSA_REF_PUBLIC_ENCRYPT"},
{0,NULL},
	};

static ERR_STRING_DATA RSAREF_str_reasons[]=
	{
{RE_CONTENT_ENCODING                     ,"content encoding"},
{RE_DATA                                 ,"data"},
{RE_DIGEST_ALGORITHM                     ,"digest algorithm"},
{RE_ENCODING                             ,"encoding"},
{RE_KEY                                  ,"key"},
{RE_KEY_ENCODING                         ,"key encoding"},
{RE_LEN                                  ,"len"},
{RE_MODULUS_LEN                          ,"modulus len"},
{RE_NEED_RANDOM                          ,"need random"},
{RE_PRIVATE_KEY                          ,"private key"},
{RE_PUBLIC_KEY                           ,"public key"},
{RE_SIGNATURE                            ,"signature"},
{RE_SIGNATURE_ENCODING                   ,"signature encoding"},
{RE_ENCRYPTION_ALGORITHM                 ,"encryption algorithm"},
{RSAREF_R_CONTENT_ENCODING               ,"content encoding"},
{RSAREF_R_DATA                           ,"data"},
{RSAREF_R_DIGEST_ALGORITHM               ,"digest algorithm"},
{RSAREF_R_ENCODING                       ,"encoding"},
{RSAREF_R_ENCRYPTION_ALGORITHM           ,"encryption algorithm"},
{RSAREF_R_KEY                            ,"key"},
{RSAREF_R_KEY_ENCODING                   ,"key encoding"},
{RSAREF_R_LEN                            ,"len"},
{RSAREF_R_MODULUS_LEN                    ,"modulus len"},
{RSAREF_R_NEED_RANDOM                    ,"need random"},
{RSAREF_R_PRIVATE_KEY                    ,"private key"},
{RSAREF_R_PUBLIC_KEY                     ,"public key"},
{RSAREF_R_SIGNATURE                      ,"signature"},
{RSAREF_R_SIGNATURE_ENCODING             ,"signature encoding"},
{0,NULL},
	};

#endif

void ERR_load_RSAREF_strings()
	{
	static int init=1;

	if (init)
		{
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_RSAREF,RSAREF_str_functs);
		ERR_load_strings(ERR_LIB_RSAREF,RSAREF_str_reasons);
#endif

		}
	}
