/* lib/asn1/asn1_err.c */
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
#include "asn1.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA ASN1_str_functs[]=
	{
{ERR_PACK(0,ASN1_F_A2D_ASN1_OBJECT,0),	"a2d_ASN1_OBJECT"},
{ERR_PACK(0,ASN1_F_A2I_ASN1_INTEGER,0),	"a2i_ASN1_INTEGER"},
{ERR_PACK(0,ASN1_F_A2I_ASN1_STRING,0),	"a2i_ASN1_STRING"},
{ERR_PACK(0,ASN1_F_ASN1_COLLATE_PRIMATIVE,0),	"ASN1_COLLATE_PRIMATIVE"},
{ERR_PACK(0,ASN1_F_ASN1_D2I_BIO,0),	"ASN1_d2i_bio"},
{ERR_PACK(0,ASN1_F_ASN1_D2I_FP,0),	"ASN1_d2i_fp"},
{ERR_PACK(0,ASN1_F_ASN1_DUP,0),	"ASN1_dup"},
{ERR_PACK(0,ASN1_F_ASN1_GET_OBJECT,0),	"ASN1_get_object"},
{ERR_PACK(0,ASN1_F_ASN1_HEADER_NEW,0),	"ASN1_HEADER_new"},
{ERR_PACK(0,ASN1_F_ASN1_I2D_BIO,0),	"ASN1_i2d_bio"},
{ERR_PACK(0,ASN1_F_ASN1_I2D_FP,0),	"ASN1_i2d_fp"},
{ERR_PACK(0,ASN1_F_ASN1_INTEGER_SET,0),	"ASN1_INTEGER_set"},
{ERR_PACK(0,ASN1_F_ASN1_INTEGER_TO_BN,0),	"ASN1_INTEGER_to_BN"},
{ERR_PACK(0,ASN1_F_ASN1_OBJECT_NEW,0),	"ASN1_OBJECT_new"},
{ERR_PACK(0,ASN1_F_ASN1_SIGN,0),	"ASN1_SIGN"},
{ERR_PACK(0,ASN1_F_ASN1_STRING_NEW,0),	"ASN1_STRING_new"},
{ERR_PACK(0,ASN1_F_ASN1_STRING_TYPE_NEW,0),	"ASN1_STRING_type_new"},
{ERR_PACK(0,ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING,0),	"ASN1_TYPE_get_int_octetstring"},
{ERR_PACK(0,ASN1_F_ASN1_TYPE_GET_OCTETSTRING,0),	"ASN1_TYPE_get_octetstring"},
{ERR_PACK(0,ASN1_F_ASN1_TYPE_NEW,0),	"ASN1_TYPE_new"},
{ERR_PACK(0,ASN1_F_ASN1_UTCTIME_NEW,0),	"ASN1_UTCTIME_NEW"},
{ERR_PACK(0,ASN1_F_ASN1_VERIFY,0),	"ASN1_VERIFY"},
{ERR_PACK(0,ASN1_F_BN_TO_ASN1_INTEGER,0),	"BN_to_ASN1_INTEGER"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_BIT_STRING,0),	"d2i_ASN1_BIT_STRING"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_BMPSTRING,0),	"D2I_ASN1_BMPSTRING"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_BOOLEAN,0),	"d2i_ASN1_BOOLEAN"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_BYTES,0),	"d2i_ASN1_bytes"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_HEADER,0),	"d2i_ASN1_HEADER"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_INTEGER,0),	"d2i_ASN1_INTEGER"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_OBJECT,0),	"d2i_ASN1_OBJECT"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_OCTET_STRING,0),	"d2i_ASN1_OCTET_STRING"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_PRINT_TYPE,0),	"D2I_ASN1_PRINT_TYPE"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_SET,0),	"d2i_ASN1_SET"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_TYPE,0),	"d2i_ASN1_TYPE"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_TYPE_BYTES,0),	"d2i_ASN1_type_bytes"},
{ERR_PACK(0,ASN1_F_D2I_ASN1_UTCTIME,0),	"d2i_ASN1_UTCTIME"},
{ERR_PACK(0,ASN1_F_D2I_DHPARAMS,0),	"D2I_DHPARAMS"},
{ERR_PACK(0,ASN1_F_D2I_DSAPARAMS,0),	"D2I_DSAPARAMS"},
{ERR_PACK(0,ASN1_F_D2I_DSAPRIVATEKEY,0),	"D2I_DSAPRIVATEKEY"},
{ERR_PACK(0,ASN1_F_D2I_DSAPUBLICKEY,0),	"D2I_DSAPUBLICKEY"},
{ERR_PACK(0,ASN1_F_D2I_NETSCAPE_PKEY,0),	"D2I_NETSCAPE_PKEY"},
{ERR_PACK(0,ASN1_F_D2I_NETSCAPE_RSA,0),	"D2I_NETSCAPE_RSA"},
{ERR_PACK(0,ASN1_F_D2I_NETSCAPE_RSA_2,0),	"D2I_NETSCAPE_RSA_2"},
{ERR_PACK(0,ASN1_F_D2I_NETSCAPE_SPKAC,0),	"D2I_NETSCAPE_SPKAC"},
{ERR_PACK(0,ASN1_F_D2I_NETSCAPE_SPKI,0),	"D2I_NETSCAPE_SPKI"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7,0),	"D2I_PKCS7"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_DIGEST,0),	"D2I_PKCS7_DIGEST"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_ENCRYPT,0),	"D2I_PKCS7_ENCRYPT"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_ENC_CONTENT,0),	"D2I_PKCS7_ENC_CONTENT"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_ENVELOPE,0),	"D2I_PKCS7_ENVELOPE"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_ISSUER_AND_SERIAL,0),	"D2I_PKCS7_ISSUER_AND_SERIAL"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_RECIP_INFO,0),	"D2I_PKCS7_RECIP_INFO"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_SIGNED,0),	"D2I_PKCS7_SIGNED"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_SIGNER_INFO,0),	"D2I_PKCS7_SIGNER_INFO"},
{ERR_PACK(0,ASN1_F_D2I_PKCS7_SIGN_ENVELOPE,0),	"D2I_PKCS7_SIGN_ENVELOPE"},
{ERR_PACK(0,ASN1_F_D2I_PRIVATEKEY,0),	"D2I_PRIVATEKEY"},
{ERR_PACK(0,ASN1_F_D2I_PUBLICKEY,0),	"D2I_PUBLICKEY"},
{ERR_PACK(0,ASN1_F_D2I_RSAPRIVATEKEY,0),	"D2I_RSAPRIVATEKEY"},
{ERR_PACK(0,ASN1_F_D2I_RSAPUBLICKEY,0),	"D2I_RSAPUBLICKEY"},
{ERR_PACK(0,ASN1_F_D2I_X509,0),	"D2I_X509"},
{ERR_PACK(0,ASN1_F_D2I_X509_ALGOR,0),	"D2I_X509_ALGOR"},
{ERR_PACK(0,ASN1_F_D2I_X509_ATTRIBUTE,0),	"D2I_X509_ATTRIBUTE"},
{ERR_PACK(0,ASN1_F_D2I_X509_CINF,0),	"D2I_X509_CINF"},
{ERR_PACK(0,ASN1_F_D2I_X509_CRL,0),	"D2I_X509_CRL"},
{ERR_PACK(0,ASN1_F_D2I_X509_CRL_INFO,0),	"D2I_X509_CRL_INFO"},
{ERR_PACK(0,ASN1_F_D2I_X509_EXTENSION,0),	"D2I_X509_EXTENSION"},
{ERR_PACK(0,ASN1_F_D2I_X509_KEY,0),	"D2I_X509_KEY"},
{ERR_PACK(0,ASN1_F_D2I_X509_NAME,0),	"D2I_X509_NAME"},
{ERR_PACK(0,ASN1_F_D2I_X509_NAME_ENTRY,0),	"D2I_X509_NAME_ENTRY"},
{ERR_PACK(0,ASN1_F_D2I_X509_PKEY,0),	"D2I_X509_PKEY"},
{ERR_PACK(0,ASN1_F_D2I_X509_PUBKEY,0),	"D2I_X509_PUBKEY"},
{ERR_PACK(0,ASN1_F_D2I_X509_REQ,0),	"D2I_X509_REQ"},
{ERR_PACK(0,ASN1_F_D2I_X509_REQ_INFO,0),	"D2I_X509_REQ_INFO"},
{ERR_PACK(0,ASN1_F_D2I_X509_REVOKED,0),	"D2I_X509_REVOKED"},
{ERR_PACK(0,ASN1_F_D2I_X509_SIG,0),	"D2I_X509_SIG"},
{ERR_PACK(0,ASN1_F_D2I_X509_VAL,0),	"D2I_X509_VAL"},
{ERR_PACK(0,ASN1_F_I2D_ASN1_HEADER,0),	"i2d_ASN1_HEADER"},
{ERR_PACK(0,ASN1_F_I2D_DHPARAMS,0),	"I2D_DHPARAMS"},
{ERR_PACK(0,ASN1_F_I2D_DSAPARAMS,0),	"I2D_DSAPARAMS"},
{ERR_PACK(0,ASN1_F_I2D_DSAPRIVATEKEY,0),	"I2D_DSAPRIVATEKEY"},
{ERR_PACK(0,ASN1_F_I2D_DSAPUBLICKEY,0),	"I2D_DSAPUBLICKEY"},
{ERR_PACK(0,ASN1_F_I2D_NETSCAPE_RSA,0),	"I2D_NETSCAPE_RSA"},
{ERR_PACK(0,ASN1_F_I2D_PKCS7,0),	"I2D_PKCS7"},
{ERR_PACK(0,ASN1_F_I2D_PRIVATEKEY,0),	"I2D_PRIVATEKEY"},
{ERR_PACK(0,ASN1_F_I2D_PUBLICKEY,0),	"I2D_PUBLICKEY"},
{ERR_PACK(0,ASN1_F_I2D_RSAPRIVATEKEY,0),	"I2D_RSAPRIVATEKEY"},
{ERR_PACK(0,ASN1_F_I2D_RSAPUBLICKEY,0),	"I2D_RSAPUBLICKEY"},
{ERR_PACK(0,ASN1_F_I2D_X509_ATTRIBUTE,0),	"I2D_X509_ATTRIBUTE"},
{ERR_PACK(0,ASN1_F_I2T_ASN1_OBJECT,0),	"i2t_ASN1_OBJECT"},
{ERR_PACK(0,ASN1_F_NETSCAPE_PKEY_NEW,0),	"NETSCAPE_PKEY_NEW"},
{ERR_PACK(0,ASN1_F_NETSCAPE_SPKAC_NEW,0),	"NETSCAPE_SPKAC_NEW"},
{ERR_PACK(0,ASN1_F_NETSCAPE_SPKI_NEW,0),	"NETSCAPE_SPKI_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_DIGEST_NEW,0),	"PKCS7_DIGEST_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_ENCRYPT_NEW,0),	"PKCS7_ENCRYPT_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_ENC_CONTENT_NEW,0),	"PKCS7_ENC_CONTENT_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_ENVELOPE_NEW,0),	"PKCS7_ENVELOPE_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_ISSUER_AND_SERIAL_NEW,0),	"PKCS7_ISSUER_AND_SERIAL_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_NEW,0),	"PKCS7_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_RECIP_INFO_NEW,0),	"PKCS7_RECIP_INFO_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_SIGNED_NEW,0),	"PKCS7_SIGNED_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_SIGNER_INFO_NEW,0),	"PKCS7_SIGNER_INFO_NEW"},
{ERR_PACK(0,ASN1_F_PKCS7_SIGN_ENVELOPE_NEW,0),	"PKCS7_SIGN_ENVELOPE_NEW"},
{ERR_PACK(0,ASN1_F_X509_ALGOR_NEW,0),	"X509_ALGOR_NEW"},
{ERR_PACK(0,ASN1_F_X509_ATTRIBUTE_NEW,0),	"X509_ATTRIBUTE_NEW"},
{ERR_PACK(0,ASN1_F_X509_CINF_NEW,0),	"X509_CINF_NEW"},
{ERR_PACK(0,ASN1_F_X509_CRL_INFO_NEW,0),	"X509_CRL_INFO_NEW"},
{ERR_PACK(0,ASN1_F_X509_CRL_NEW,0),	"X509_CRL_NEW"},
{ERR_PACK(0,ASN1_F_X509_DHPARAMS_NEW,0),	"X509_DHPARAMS_NEW"},
{ERR_PACK(0,ASN1_F_X509_EXTENSION_NEW,0),	"X509_EXTENSION_NEW"},
{ERR_PACK(0,ASN1_F_X509_INFO_NEW,0),	"X509_INFO_NEW"},
{ERR_PACK(0,ASN1_F_X509_KEY_NEW,0),	"X509_KEY_NEW"},
{ERR_PACK(0,ASN1_F_X509_NAME_ENTRY_NEW,0),	"X509_NAME_ENTRY_NEW"},
{ERR_PACK(0,ASN1_F_X509_NAME_NEW,0),	"X509_NAME_NEW"},
{ERR_PACK(0,ASN1_F_X509_NEW,0),	"X509_NEW"},
{ERR_PACK(0,ASN1_F_X509_PKEY_NEW,0),	"X509_PKEY_NEW"},
{ERR_PACK(0,ASN1_F_X509_PUBKEY_NEW,0),	"X509_PUBKEY_NEW"},
{ERR_PACK(0,ASN1_F_X509_REQ_INFO_NEW,0),	"X509_REQ_INFO_NEW"},
{ERR_PACK(0,ASN1_F_X509_REQ_NEW,0),	"X509_REQ_NEW"},
{ERR_PACK(0,ASN1_F_X509_REVOKED_NEW,0),	"X509_REVOKED_NEW"},
{ERR_PACK(0,ASN1_F_X509_SIG_NEW,0),	"X509_SIG_NEW"},
{ERR_PACK(0,ASN1_F_X509_VAL_FREE,0),	"X509_VAL_FREE"},
{ERR_PACK(0,ASN1_F_X509_VAL_NEW,0),	"X509_VAL_NEW"},
{0,NULL},
	};

static ERR_STRING_DATA ASN1_str_reasons[]=
	{
{ASN1_R_BAD_CLASS                        ,"bad class"},
{ASN1_R_BAD_GET_OBJECT                   ,"bad get object"},
{ASN1_R_BAD_OBJECT_HEADER                ,"bad object header"},
{ASN1_R_BAD_PASSWORD_READ                ,"bad password read"},
{ASN1_R_BAD_PKCS7_CONTENT                ,"bad pkcs7 content"},
{ASN1_R_BAD_PKCS7_TYPE                   ,"bad pkcs7 type"},
{ASN1_R_BAD_TAG                          ,"bad tag"},
{ASN1_R_BAD_TYPE                         ,"bad type"},
{ASN1_R_BN_LIB                           ,"bn lib"},
{ASN1_R_BOOLEAN_IS_WRONG_LENGTH          ,"boolean is wrong length"},
{ASN1_R_BUFFER_TOO_SMALL                 ,"buffer too small"},
{ASN1_R_DATA_IS_WRONG                    ,"data is wrong"},
{ASN1_R_DECODING_ERROR                   ,"decoding error"},
{ASN1_R_ERROR_STACK                      ,"error stack"},
{ASN1_R_EXPECTING_AN_INTEGER             ,"expecting an integer"},
{ASN1_R_EXPECTING_AN_OBJECT              ,"expecting an object"},
{ASN1_R_EXPECTING_AN_OCTET_STRING        ,"expecting an octet string"},
{ASN1_R_EXPECTING_A_BIT_STRING           ,"expecting a bit string"},
{ASN1_R_EXPECTING_A_BOOLEAN              ,"expecting a boolean"},
{ASN1_R_EXPECTING_A_SEQUENCE             ,"expecting a sequence"},
{ASN1_R_EXPECTING_A_UTCTIME              ,"expecting a utctime"},
{ASN1_R_FIRST_NUM_TOO_LARGE              ,"first num too large"},
{ASN1_R_HEADER_TOO_LONG                  ,"header too long"},
{ASN1_R_INVALID_DIGIT                    ,"invalid digit"},
{ASN1_R_INVALID_SEPARATOR                ,"invalid separator"},
{ASN1_R_INVALID_TIME_FORMAT              ,"invalid time format"},
{ASN1_R_IV_TOO_LARGE                     ,"iv too large"},
{ASN1_R_LENGTH_ERROR                     ,"length error"},
{ASN1_R_LENGTH_MISMATCH                  ,"length mismatch"},
{ASN1_R_MISSING_EOS                      ,"missing eos"},
{ASN1_R_MISSING_SECOND_NUMBER            ,"missing second number"},
{ASN1_R_NON_HEX_CHARACTERS               ,"non hex characters"},
{ASN1_R_NOT_ENOUGH_DATA                  ,"not enough data"},
{ASN1_R_ODD_NUMBER_OF_CHARS              ,"odd number of chars"},
{ASN1_R_PARSING                          ,"parsing"},
{ASN1_R_PRIVATE_KEY_HEADER_MISSING       ,"private key header missing"},
{ASN1_R_SECOND_NUMBER_TOO_LARGE          ,"second number too large"},
{ASN1_R_SHORT_LINE                       ,"short line"},
{ASN1_R_STRING_TOO_SHORT                 ,"string too short"},
{ASN1_R_TAG_VALUE_TOO_HIGH               ,"tag value too high"},
{ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD,"the asn1 object identifier is not known for this md"},
{ASN1_R_TOO_LONG                         ,"too long"},
{ASN1_R_UNABLE_TO_DECODE_RSA_KEY         ,"unable to decode rsa key"},
{ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY ,"unable to decode rsa private key"},
{ASN1_R_UNKNOWN_ATTRIBUTE_TYPE           ,"unknown attribute type"},
{ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM ,"unknown message digest algorithm"},
{ASN1_R_UNKNOWN_OBJECT_TYPE              ,"unknown object type"},
{ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE          ,"unknown public key type"},
{ASN1_R_UNSUPPORTED_CIPHER               ,"unsupported cipher"},
{ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM ,"unsupported encryption algorithm"},
{ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE      ,"unsupported public key type"},
{ASN1_R_UTCTIME_TOO_LONG                 ,"utctime too long"},
{ASN1_R_WRONG_PRINTABLE_TYPE             ,"wrong printable type"},
{ASN1_R_WRONG_TAG                        ,"wrong tag"},
{ASN1_R_WRONG_TYPE                       ,"wrong type"},
{0,NULL},
	};

#endif

void ERR_load_ASN1_strings()
	{
	static int init=1;

	if (init);
		{;
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_ASN1,ASN1_str_functs);
		ERR_load_strings(ERR_LIB_ASN1,ASN1_str_reasons);
#endif

		}
	}
