/* demos/sign/sign.c */
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

/* sign-it.cpp  -  Simple test app using SSLeay envelopes to sign data
   29.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* converted to C - eay :-) */

#include <stdio.h>
#include "rsa.h"
#include "evp.h"
#include "objects.h"
#include "x509.h"
#include "err.h"
#include "pem.h"
#include "ssl.h"

void main ()
{
  int err;
  int sig_len;
  unsigned char sig_buf [4096];
  static char certfile[] = "cert.pem";
  static char keyfile[]  = "key.pem";
  static char data[]     = "I owe you...";
  EVP_MD_CTX     md_ctx;
  EVP_PKEY *      pkey;
  FILE *          fp;
  X509 *	x509;

  /* Just load the crypto library error strings,
   * SSL_load_error_strings() loads the crypto AND the SSL ones */
  /* SSL_load_error_strings();*/
  ERR_load_crypto_strings();
  
  /* Read private key */
  
  fp = fopen (keyfile, "r");   if (fp == NULL) exit (1);
  pkey = (EVP_PKEY*)PEM_ASN1_read ((char *(*)())d2i_PrivateKey,
				   PEM_STRING_EVP_PKEY,
				   fp,
				   NULL, NULL);
  if (pkey == NULL) {  ERR_print_errors_fp (stderr);    exit (1);  }
  fclose (fp);
  
  /* Do the signature */
  
  EVP_SignInit   (&md_ctx, EVP_md5());
  EVP_SignUpdate (&md_ctx, data, strlen(data));
  sig_len = sizeof(sig_buf);
  err = EVP_SignFinal (&md_ctx,
		       sig_buf, 
		       &sig_len,
		       pkey);
  if (err != 1) {  ERR_print_errors_fp (stderr);    exit (1);  }
  EVP_PKEY_free (pkey);
  
  /* Read public key */
  
  fp = fopen (certfile, "r");   if (fp == NULL) exit (1);
  x509 = (X509 *)PEM_ASN1_read ((char *(*)())d2i_X509,
				   PEM_STRING_X509,
				   fp, NULL, NULL);
  if (x509 == NULL) {  ERR_print_errors_fp (stderr);    exit (1);  }
  fclose (fp);
  
  /* Get public key - eay */
  pkey=X509_extract_key(x509);
  if (pkey == NULL) {  ERR_print_errors_fp (stderr);    exit (1);  }

  /* Verify the signature */
  
  EVP_VerifyInit   (&md_ctx, EVP_md5());
  EVP_VerifyUpdate (&md_ctx, data, strlen((char*)data));
  err = EVP_VerifyFinal (&md_ctx,
			 sig_buf,
			 sig_len,
			 pkey);
  if (err != 1) {  ERR_print_errors_fp (stderr);    exit (1);  }
  EVP_PKEY_free (pkey);
  printf ("Signature Verified Ok.\n");
}
