/* lib/rsa/rsa_err.c */
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
#include "rsa.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA RSA_str_functs[]=
	{
{ERR_PACK(0,RSA_F_RSA_EAY_PRIVATE_DECRYPT,0),	"RSA_EAY_PRIVATE_DECRYPT"},
{ERR_PACK(0,RSA_F_RSA_EAY_PRIVATE_ENCRYPT,0),	"RSA_EAY_PRIVATE_ENCRYPT"},
{ERR_PACK(0,RSA_F_RSA_EAY_PUBLIC_DECRYPT,0),	"RSA_EAY_PUBLIC_DECRYPT"},
{ERR_PACK(0,RSA_F_RSA_EAY_PUBLIC_ENCRYPT,0),	"RSA_EAY_PUBLIC_ENCRYPT"},
{ERR_PACK(0,RSA_F_RSA_GENERATE_KEY,0),	"RSA_generate_key"},
{ERR_PACK(0,RSA_F_RSA_NEW_METHOD,0),	"RSA_new_method"},
{ERR_PACK(0,RSA_F_RSA_PADDING_ADD_NONE,0),	"RSA_padding_add_none"},
{ERR_PACK(0,RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1,0),	"RSA_padding_add_PKCS1_type_1"},
{ERR_PACK(0,RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2,0),	"RSA_padding_add_PKCS1_type_2"},
{ERR_PACK(0,RSA_F_RSA_PADDING_ADD_SSLV23,0),	"RSA_padding_add_SSLv23"},
{ERR_PACK(0,RSA_F_RSA_PADDING_CHECK_NONE,0),	"RSA_padding_check_none"},
{ERR_PACK(0,RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1,0),	"RSA_padding_check_PKCS1_type_1"},
{ERR_PACK(0,RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2,0),	"RSA_padding_check_PKCS1_type_2"},
{ERR_PACK(0,RSA_F_RSA_PADDING_CHECK_SSLV23,0),	"RSA_padding_check_SSLv23"},
{ERR_PACK(0,RSA_F_RSA_PRINT,0),	"RSA_print"},
{ERR_PACK(0,RSA_F_RSA_PRINT_FP,0),	"RSA_print_fp"},
{ERR_PACK(0,RSA_F_RSA_SIGN,0),	"RSA_sign"},
{ERR_PACK(0,RSA_F_RSA_SIGN_ASN1_OCTET_STRING,0),	"RSA_sign_ASN1_OCTET_STRING"},
{ERR_PACK(0,RSA_F_RSA_VERIFY,0),	"RSA_verify"},
{ERR_PACK(0,RSA_F_RSA_VERIFY_ASN1_OCTET_STRING,0),	"RSA_verify_ASN1_OCTET_STRING"},
{0,NULL},
	};

static ERR_STRING_DATA RSA_str_reasons[]=
	{
{RSA_R_ALGORITHM_MISMATCH                ,"algorithm mismatch"},
{RSA_R_BAD_E_VALUE                       ,"bad e value"},
{RSA_R_BAD_FIXED_HEADER_DECRYPT          ,"bad fixed header decrypt"},
{RSA_R_BAD_PAD_BYTE_COUNT                ,"bad pad byte count"},
{RSA_R_BAD_SIGNATURE                     ,"bad signature"},
{RSA_R_BAD_ZERO_BYTE                     ,"bad zero byte"},
{RSA_R_BLOCK_TYPE_IS_NOT_01              ,"block type is not 01"},
{RSA_R_BLOCK_TYPE_IS_NOT_02              ,"block type is not 02"},
{RSA_R_DATA_GREATER_THAN_MOD_LEN         ,"data greater than mod len"},
{RSA_R_DATA_TOO_LARGE                    ,"data too large"},
{RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE       ,"data too large for key size"},
{RSA_R_DATA_TOO_SMALL                    ,"data too small"},
{RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY        ,"digest too big for rsa key"},
{RSA_R_NULL_BEFORE_BLOCK_MISSING         ,"null before block missing"},
{RSA_R_PADDING_CHECK_FAILED              ,"padding check failed"},
{RSA_R_SSLV3_ROLLBACK_ATTACK             ,"sslv3 rollback attack"},
{RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD,"the asn1 object identifier is not known for this md"},
{RSA_R_UNKNOWN_ALGORITHM_TYPE            ,"unknown algorithm type"},
{RSA_R_UNKNOWN_PADDING_TYPE              ,"unknown padding type"},
{RSA_R_WRONG_SIGNATURE_LENGTH            ,"wrong signature length"},
{0,NULL},
	};

#endif

void ERR_load_RSA_strings()
	{
	static int init=1;

	if (init);
		{;
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_RSA,RSA_str_functs);
		ERR_load_strings(ERR_LIB_RSA,RSA_str_reasons);
#endif

		}
	}
