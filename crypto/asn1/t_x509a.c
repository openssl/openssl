/* t_x509a.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>

/* X509_CERT_AUX and string set routines
 */

static BIT_STRING_BITNAME tbits[] = {
{X509_TRUST_BIT_ALL, "All Purposes", "all"},
{X509_TRUST_BIT_SSL_CLIENT, "SSL client", "sslclient"},
{X509_TRUST_BIT_SSL_SERVER, "SSL server", "sslserver"},
{X509_TRUST_BIT_EMAIL, "S/MIME email", "email"},
{X509_TRUST_BIT_OBJECT_SIGN, "Object Signing", "objsign"},
{-1, NULL, NULL}
};

int X509_trust_set_bit_asc(X509 *x, char *str, int value)
{
	int bitnum;
	bitnum = ASN1_BIT_STRING_num_asc(str, tbits);
	if(bitnum < 0) return 0;
	if(x) return X509_trust_set_bit(x, bitnum, value);
	return 1;
}

int X509_notrust_set_bit_asc(X509 *x, char *str, int value)
{
	int bitnum;
	bitnum = ASN1_BIT_STRING_num_asc(str, tbits);
	if(bitnum < 0) return 0;
	if(x) return X509_notrust_set_bit(x, bitnum, value);
	return 1;
}


int X509_CERT_AUX_print(BIO *out, X509_CERT_AUX *aux, int indent)
{
	char oidstr[80], first;
	int i;
	if(!aux) return 1;
	if(aux->trust) {
		BIO_printf(out, "%*sTrusted for:\n", indent, "");
		ASN1_BIT_STRING_name_print(out, aux->trust, tbits, indent + 2);
	} else BIO_printf(out, "%*sNo Trust Settings\n", indent + 2, "");
	if(aux->notrust) {
		BIO_printf(out, "%*sUntrusted for:\n", indent, "");
		ASN1_BIT_STRING_name_print(out, aux->notrust, tbits, indent + 2);
	} else BIO_printf(out, "%*sNo Untrusted Settings\n", indent + 2, "");
	if(aux->othertrust) {
		first = 1;
		BIO_printf(out, "%*sOther Trusted Uses:\n%*s",
						indent, "", indent + 2, "");
		for(i = 0; i < sk_ASN1_OBJECT_num(aux->othertrust); i++) {
			if(!first) BIO_puts(out, ", ");
			else first = 0;
			OBJ_obj2txt(oidstr, 80,
				sk_ASN1_OBJECT_value(aux->othertrust, i), 0);
			BIO_puts(out, oidstr);
		}
		BIO_puts(out, "\n");
	}
	if(aux->othernotrust) {
		first = 1;
		BIO_printf(out, "%*sOther Untrusted Uses:\n%*s",
						indent, "", indent + 2, "");
		for(i = 0; i < sk_ASN1_OBJECT_num(aux->othernotrust); i++) {
			if(!first) BIO_puts(out, ", ");
			else first = 0;
			OBJ_obj2txt(oidstr, 80,
				sk_ASN1_OBJECT_value(aux->othernotrust, i), 0);
			BIO_puts(out, oidstr);
		}
		BIO_puts(out, "\n");
	}
	if(aux->alias) BIO_printf(out, "%*sAlias: %s\n", indent, "",
							aux->alias->data);
	return 1;
}
