/* lib/x509/x509_err.c */
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
#include "x509.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA X509_str_functs[]=
	{
{ERR_PACK(0,X509_F_ADD_CERT_DIR,0),	"ADD_CERT_DIR"},
{ERR_PACK(0,X509_F_BY_FILE_CTRL,0),	"BY_FILE_CTRL"},
{ERR_PACK(0,X509_F_DIR_CTRL,0),	"DIR_CTRL"},
{ERR_PACK(0,X509_F_GET_CERT_BY_SUBJECT,0),	"GET_CERT_BY_SUBJECT"},
{ERR_PACK(0,X509_F_X509V3_ADD_EXT,0),	"X509v3_add_ext"},
{ERR_PACK(0,X509_F_X509V3_ADD_EXTENSION,0),	"X509V3_ADD_EXTENSION"},
{ERR_PACK(0,X509_F_X509V3_PACK_STRING,0),	"X509v3_pack_string"},
{ERR_PACK(0,X509_F_X509V3_UNPACK_STRING,0),	"X509v3_unpack_string"},
{ERR_PACK(0,X509_F_X509_EXTENSION_CREATE_BY_NID,0),	"X509_EXTENSION_create_by_NID"},
{ERR_PACK(0,X509_F_X509_EXTENSION_CREATE_BY_OBJ,0),	"X509_EXTENSION_create_by_OBJ"},
{ERR_PACK(0,X509_F_X509_GET_PUBKEY_PARAMETERS,0),	"X509_get_pubkey_parameters"},
{ERR_PACK(0,X509_F_X509_LOAD_CERT_FILE,0),	"X509_LOAD_CERT_FILE"},
{ERR_PACK(0,X509_F_X509_LOAD_CRL_FILE,0),	"X509_LOAD_CRL_FILE"},
{ERR_PACK(0,X509_F_X509_NAME_ADD_ENTRY,0),	"X509_NAME_add_entry"},
{ERR_PACK(0,X509_F_X509_NAME_ENTRY_CREATE_BY_NID,0),	"X509_NAME_ENTRY_create_by_NID"},
{ERR_PACK(0,X509_F_X509_NAME_ENTRY_SET_OBJECT,0),	"X509_NAME_ENTRY_set_object"},
{ERR_PACK(0,X509_F_X509_NAME_ONELINE,0),	"X509_NAME_oneline"},
{ERR_PACK(0,X509_F_X509_NAME_PRINT,0),	"X509_NAME_print"},
{ERR_PACK(0,X509_F_X509_PRINT_FP,0),	"X509_print_fp"},
{ERR_PACK(0,X509_F_X509_PUBKEY_GET,0),	"X509_PUBKEY_get"},
{ERR_PACK(0,X509_F_X509_PUBKEY_SET,0),	"X509_PUBKEY_set"},
{ERR_PACK(0,X509_F_X509_REQ_PRINT,0),	"X509_REQ_print"},
{ERR_PACK(0,X509_F_X509_REQ_PRINT_FP,0),	"X509_REQ_print_fp"},
{ERR_PACK(0,X509_F_X509_REQ_TO_X509,0),	"X509_REQ_to_X509"},
{ERR_PACK(0,X509_F_X509_STORE_ADD_CERT,0),	"X509_STORE_ADD_CERT"},
{ERR_PACK(0,X509_F_X509_STORE_ADD_CRL,0),	"X509_STORE_ADD_CRL"},
{ERR_PACK(0,X509_F_X509_TO_X509_REQ,0),	"X509_to_X509_REQ"},
{ERR_PACK(0,X509_F_X509_VERIFY_CERT,0),	"X509_verify_cert"},
{0,NULL},
	};

static ERR_STRING_DATA X509_str_reasons[]=
	{
{X509_R_BAD_X509_FILETYPE                ,"bad x509 filetype"},
{X509_R_CERT_ALREADY_IN_HASH_TABLE       ,"cert already in hash table"},
{X509_R_ERR_ASN1_LIB                     ,"err asn1 lib"},
{X509_R_LOADING_CERT_DIR                 ,"loading cert dir"},
{X509_R_LOADING_DEFAULTS                 ,"loading defaults"},
{X509_R_NO_CERT_SET_FOR_US_TO_VERIFY     ,"no cert set for us to verify"},
{X509_R_SHOULD_RETRY                     ,"should retry"},
{X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN,"unable to find parameters in chain"},
{X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY   ,"unable to get certs public key"},
{X509_R_UNKNOWN_NID                      ,"unknown nid"},
{X509_R_UNKNOWN_STRING_TYPE              ,"unknown string type"},
{X509_R_UNSUPPORTED_ALGORITHM            ,"unsupported algorithm"},
{X509_R_WRONG_LOOKUP_TYPE                ,"wrong lookup type"},
{0,NULL},
	};

#endif

void ERR_load_X509_strings()
	{
	static int init=1;

	if (init);
		{;
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_X509,X509_str_functs);
		ERR_load_strings(ERR_LIB_X509,X509_str_reasons);
#endif

		}
	}
