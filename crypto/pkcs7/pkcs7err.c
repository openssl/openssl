/* lib/pkcs7/pkcs7_err.c */
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
#include "pkcs7.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA PKCS7_str_functs[]=
	{
{ERR_PACK(0,PKCS7_F_PKCS7_ADD_CERTIFICATE,0),	"PKCS7_add_certificate"},
{ERR_PACK(0,PKCS7_F_PKCS7_ADD_CRL,0),	"PKCS7_add_crl"},
{ERR_PACK(0,PKCS7_F_PKCS7_ADD_RECIPIENT_INFO,0),	"PKCS7_add_recipient_info"},
{ERR_PACK(0,PKCS7_F_PKCS7_ADD_SIGNER,0),	"PKCS7_add_signer"},
{ERR_PACK(0,PKCS7_F_PKCS7_CTRL,0),	"PKCS7_ctrl"},
{ERR_PACK(0,PKCS7_F_PKCS7_DATAINIT,0),	"PKCS7_dataInit"},
{ERR_PACK(0,PKCS7_F_PKCS7_DATASIGN,0),	"PKCS7_dataSign"},
{ERR_PACK(0,PKCS7_F_PKCS7_DATAVERIFY,0),	"PKCS7_dataVerify"},
{ERR_PACK(0,PKCS7_F_PKCS7_SET_CIPHER,0),	"PKCS7_set_cipher"},
{ERR_PACK(0,PKCS7_F_PKCS7_SET_CONTENT,0),	"PKCS7_set_content"},
{ERR_PACK(0,PKCS7_F_PKCS7_SET_TYPE,0),	"PKCS7_set_type"},
{0,NULL},
	};

static ERR_STRING_DATA PKCS7_str_reasons[]=
	{
{PKCS7_R_INTERNAL_ERROR                  ,"internal error"},
{PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE,"operation not supported on this type"},
{PKCS7_R_SIGNATURE_FAILURE               ,"signature failure"},
{PKCS7_R_UNABLE_TO_FIND_CERTIFICATE      ,"unable to find certificate"},
{PKCS7_R_UNABLE_TO_FIND_MEM_BIO          ,"unable to find mem bio"},
{PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST   ,"unable to find message digest"},
{PKCS7_R_UNKNOWN_DIGEST_TYPE             ,"unknown digest type"},
{PKCS7_R_UNSUPPORTED_CIPHER_TYPE         ,"unsupported cipher type"},
{PKCS7_R_UNSUPPORTED_CONTENT_TYPE        ,"unsupported content type"},
{PKCS7_R_WRONG_CONTENT_TYPE              ,"wrong content type"},
{0,NULL},
	};

#endif

void ERR_load_PKCS7_strings()
	{
	static int init=1;

	if (init);
		{;
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_PKCS7,PKCS7_str_functs);
		ERR_load_strings(ERR_LIB_PKCS7,PKCS7_str_reasons);
#endif

		}
	}
