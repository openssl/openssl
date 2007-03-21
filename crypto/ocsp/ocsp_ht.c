/* ocsp_ht.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/asn1.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#ifdef OPENSSL_SYS_SUNOS
#define strtoul (unsigned long)strtol
#endif /* OPENSSL_SYS_SUNOS */

/* Quick and dirty HTTP OCSP request handler.
 * Could make this a bit cleverer by adding
 * support for non blocking BIOs and a few
 * other refinements.
 */

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, char *path, OCSP_REQUEST *req)
{
	BIO *mem = NULL;
	char tmpbuf[1024];
	OCSP_RESPONSE *resp = NULL;
	char *p, *q, *r;
	int len, retcode;
	static char req_txt[] =
"POST %s HTTP/1.0\r\n\
Content-Type: application/ocsp-request\r\n\
Content-Length: %d\r\n\r\n";

	len = i2d_OCSP_REQUEST(req, NULL);
	if(BIO_printf(b, req_txt, path, len) < 0) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_WRITE_ERROR);
		goto err;
	}
	if(i2d_OCSP_REQUEST_bio(b, req) <= 0) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_WRITE_ERROR);
		goto err;
	}
	if(!(mem = BIO_new(BIO_s_mem()))) goto err;
	/* Copy response to a memory BIO: socket bios can't do gets! */
	while ((len = BIO_read(b, tmpbuf, sizeof tmpbuf))) {
		if(len < 0) {
			OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_READ_ERROR);
			goto err;
		}
		BIO_write(mem, tmpbuf, len);
	}
	if(BIO_gets(mem, tmpbuf, 512) <= 0) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
		goto err;
	}
	/* Parse the HTTP response. This will look like this:
	 * "HTTP/1.0 200 OK". We need to obtain the numeric code and
         * (optional) informational message.
	 */

	/* Skip to first white space (passed protocol info) */
	for(p = tmpbuf; *p && !isspace((unsigned char)*p); p++) continue;
	if(!*p) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
		goto err;
	}
	/* Skip past white space to start of response code */
	while(*p && isspace((unsigned char)*p)) p++;
	if(!*p) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
		goto err;
	}
	/* Find end of response code: first whitespace after start of code */
	for(q = p; *q && !isspace((unsigned char)*q); q++) continue;
	if(!*q) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_PARSE_ERROR);
		goto err;
	}
	/* Set end of response code and start of message */ 
	*q++ = 0;
	/* Attempt to parse numeric code */
	retcode = strtoul(p, &r, 10);
	if(*r) goto err;
	/* Skip over any leading white space in message */
	while(*q && isspace((unsigned char)*q))  q++;
	if(*q) {
	/* Finally zap any trailing white space in message (include CRLF) */
	/* We know q has a non white space character so this is OK */
		for(r = q + strlen(q) - 1; isspace((unsigned char)*r); r--) *r = 0;
	}
	if(retcode != 200) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_SERVER_RESPONSE_ERROR);
		if(!*q) { 
			ERR_add_error_data(2, "Code=", p);
		}
		else {
			ERR_add_error_data(4, "Code=", p, ",Reason=", q);
		}
		goto err;
	}
	/* Find blank line marking beginning of content */	
	while(BIO_gets(mem, tmpbuf, 512) > 0)
	{
		for(p = tmpbuf; *p && isspace((unsigned char)*p); p++) continue;
		if(!*p) break;
	}
	if(*p) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,OCSP_R_NO_CONTENT);
		goto err;
	}
	if(!(resp = d2i_OCSP_RESPONSE_bio(mem, NULL))) {
		OCSPerr(OCSP_F_OCSP_SENDREQ_BIO,ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}
	err:
	BIO_free(mem);
	return resp;
}
