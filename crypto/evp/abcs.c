/* lib/evp/evp_err.c */
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
#include "evp.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA EVP_str_functs[]=
	{
{ERR_PACK(0,EVP_F_D2I_PKEY,0),	"D2I_PKEY"},
{ERR_PACK(0,EVP_F_EVP_DECRYPTFINAL,0),	"EVP_DecryptFinal"},
{ERR_PACK(0,EVP_F_EVP_OPENINIT,0),	"EVP_OpenInit"},
{ERR_PACK(0,EVP_F_EVP_PKEY_COPY_PARAMETERS,0),	"EVP_PKEY_copy_parameters"},
{ERR_PACK(0,EVP_F_EVP_PKEY_DECRYPT,0),	"EVP_PKEY_decrypt"},
{ERR_PACK(0,EVP_F_EVP_PKEY_ENCRYPT,0),	"EVP_PKEY_encrypt"},
{ERR_PACK(0,EVP_F_EVP_PKEY_NEW,0),	"EVP_PKEY_new"},
{ERR_PACK(0,EVP_F_EVP_SIGNFINAL,0),	"EVP_SignFinal"},
{ERR_PACK(0,EVP_F_EVP_VERIFYFINAL,0),	"EVP_VerifyFinal"},
{0,NULL},
	};

static ERR_STRING_DATA EVP_str_reasons[]=
	{
{EVP_R_BAD_DECRYPT                       ,"bad decrypt"},
{EVP_R_DIFFERENT_KEY_TYPES               ,"different key types"},
{EVP_R_IV_TOO_LARGE                      ,"iv too large"},
{EVP_R_MISSING_PARMATERS                 ,"missing parmaters"},
{EVP_R_NO_SIGN_FUNCTION_CONFIGURED       ,"no sign function configured"},
{EVP_R_NO_VERIFY_FUNCTION_CONFIGURED     ,"no verify function configured"},
{EVP_R_PUBLIC_KEY_NOT_RSA                ,"public key not rsa"},
{EVP_R_UNSUPPORTED_CIPHER                ,"unsupported cipher"},
{EVP_R_WRONG_FINAL_BLOCK_LENGTH          ,"wrong final block length"},
{EVP_R_WRONG_PUBLIC_KEY_TYPE             ,"wrong public key type"},
{0,NULL},
	};

#endif

void ERR_load_EVP_strings()
	{
	static int init=1;

	if (init);
		{;
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_EVP,EVP_str_functs);
		ERR_load_strings(ERR_LIB_EVP,EVP_str_reasons);
#endif

		}
	}
