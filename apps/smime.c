/* smime.c */
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

/* S/MIME utility function */

#include <stdio.h>
#include <string.h>
#include "apps.h"
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#undef PROG
#define PROG smime_main
static X509 *load_cert(char *file);
static EVP_PKEY *load_key(char *file, char *pass);
static STACK_OF(X509) *load_certs(char *file);
static X509_STORE *setup_verify(char *CAfile, char *CApath);
static int save_certs(char *signerfile, STACK_OF(X509) *signers);

#define SMIME_OP	0x10
#define SMIME_ENCRYPT	(1 | SMIME_OP)
#define SMIME_DECRYPT	2
#define SMIME_SIGN	(3 | SMIME_OP)
#define SMIME_VERIFY	4
#define SMIME_PK7OUT	5

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
	int operation = 0;
	int ret = 0;
	char **args;
	char *inmode = "r", *outmode = "w";
	char *infile = NULL, *outfile = NULL;
	char *signerfile = NULL, *recipfile = NULL;
	char *certfile = NULL, *keyfile = NULL;
	EVP_CIPHER *cipher = NULL;
	PKCS7 *p7 = NULL;
	X509_STORE *store = NULL;
	X509 *cert = NULL, *recip = NULL, *signer = NULL;
	EVP_PKEY *key = NULL;
	STACK_OF(X509) *encerts = NULL, *other = NULL;
	BIO *in = NULL, *out = NULL, *indata = NULL;
	int badarg = 0;
	int flags = PKCS7_DETACHED;
	char *to = NULL, *from = NULL, *subject = NULL;
	char *CAfile = NULL, *CApath = NULL;
	char *passargin = NULL, *passin = NULL;
	char *inrand = NULL;
	int need_rand = 0;
	args = argv + 1;

	ret = 1;

	while (!badarg && *args && *args[0] == '-') {
		if (!strcmp (*args, "-encrypt")) operation = SMIME_ENCRYPT;
		else if (!strcmp (*args, "-decrypt")) operation = SMIME_DECRYPT;
		else if (!strcmp (*args, "-sign")) operation = SMIME_SIGN;
		else if (!strcmp (*args, "-verify")) operation = SMIME_VERIFY;
		else if (!strcmp (*args, "-pk7out")) operation = SMIME_PK7OUT;
#ifndef NO_DES
		else if (!strcmp (*args, "-des3")) 
				cipher = EVP_des_ede3_cbc();
		else if (!strcmp (*args, "-des")) 
				cipher = EVP_des_cbc();
#endif
#ifndef NO_RC2
		else if (!strcmp (*args, "-rc2-40")) 
				cipher = EVP_rc2_40_cbc();
		else if (!strcmp (*args, "-rc2-128")) 
				cipher = EVP_rc2_cbc();
		else if (!strcmp (*args, "-rc2-64")) 
				cipher = EVP_rc2_64_cbc();
#endif
		else if (!strcmp (*args, "-text")) 
				flags |= PKCS7_TEXT;
		else if (!strcmp (*args, "-nointern")) 
				flags |= PKCS7_NOINTERN;
		else if (!strcmp (*args, "-noverify")) 
				flags |= PKCS7_NOVERIFY;
		else if (!strcmp (*args, "-nochain")) 
				flags |= PKCS7_NOCHAIN;
		else if (!strcmp (*args, "-nocerts")) 
				flags |= PKCS7_NOCERTS;
		else if (!strcmp (*args, "-noattr")) 
				flags |= PKCS7_NOATTR;
		else if (!strcmp (*args, "-nodetach")) 
				flags &= ~PKCS7_DETACHED;
		else if (!strcmp (*args, "-binary"))
				flags |= PKCS7_BINARY;
		else if (!strcmp (*args, "-nosigs"))
				flags |= PKCS7_NOSIGS;
		else if (!strcmp(*args,"-rand")) {
			if (args[1]) {
				args++;
				inrand = *args;
			} else badarg = 1;
			need_rand = 1;
		} else if (!strcmp(*args,"-passin")) {
			if (args[1]) {
				args++;
				passargin = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-to")) {
			if (args[1]) {
				args++;
				to = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-from")) {
			if (args[1]) {
				args++;
				from = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-subject")) {
			if (args[1]) {
				args++;
				subject = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-signer")) {
			if (args[1]) {
				args++;
				signerfile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-recip")) {
			if (args[1]) {
				args++;
				recipfile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-inkey")) {
			if (args[1]) {
				args++;
				keyfile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-certfile")) {
			if (args[1]) {
				args++;
				certfile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-CAfile")) {
			if (args[1]) {
				args++;
				CAfile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-CApath")) {
			if (args[1]) {
				args++;
				CApath = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-in")) {
			if (args[1]) {
				args++;
				infile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-out")) {
			if (args[1]) {
				args++;
				outfile = *args;
			} else badarg = 1;
		} else badarg = 1;
		args++;
	}

	if(operation == SMIME_SIGN) {
		if(!signerfile) {
			BIO_printf(bio_err, "No signer certificate specified\n");
			badarg = 1;
		}
		need_rand = 1;
	} else if(operation == SMIME_DECRYPT) {
		if(!recipfile) {
			BIO_printf(bio_err, "No recipient certificate and key specified\n");
			badarg = 1;
		}
	} else if(operation == SMIME_ENCRYPT) {
		if(!*args) {
			BIO_printf(bio_err, "No recipient(s) certificate(s) specified\n");
			badarg = 1;
		}
		need_rand = 1;
	} else if(!operation) badarg = 1;

	if (badarg) {
		BIO_printf (bio_err, "Usage smime [options] cert.pem ...\n");
		BIO_printf (bio_err, "where options are\n");
		BIO_printf (bio_err, "-encrypt       encrypt message\n");
		BIO_printf (bio_err, "-decrypt       decrypt encrypted message\n");
		BIO_printf (bio_err, "-sign          sign message\n");
		BIO_printf (bio_err, "-verify        verify signed message\n");
		BIO_printf (bio_err, "-pk7out        output PKCS#7 structure\n");
#ifndef NO_DES
		BIO_printf (bio_err, "-des3          encrypt with triple DES\n");
		BIO_printf (bio_err, "-des           encrypt with DES\n");
#endif
#ifndef NO_RC2
		BIO_printf (bio_err, "-rc2-40        encrypt with RC2-40 (default)\n");
		BIO_printf (bio_err, "-rc2-64        encrypt with RC2-64\n");
		BIO_printf (bio_err, "-rc2-128       encrypt with RC2-128\n");
#endif
		BIO_printf (bio_err, "-nointern      don't search certificates in message for signer\n");
		BIO_printf (bio_err, "-nosigs        don't verify message signature\n");
		BIO_printf (bio_err, "-noverify      don't verify signers certificate\n");
		BIO_printf (bio_err, "-nocerts       don't include signers certificate when signing\n");
		BIO_printf (bio_err, "-nodetach      use opaque signing\n");
		BIO_printf (bio_err, "-noattr        don't include any signed attributes\n");
		BIO_printf (bio_err, "-binary        don't translate message to text\n");
		BIO_printf (bio_err, "-certfile file other certificates file\n");
		BIO_printf (bio_err, "-signer file   signer certificate file\n");
		BIO_printf (bio_err, "-recip  file   recipient certificate file for decryption\n");
		BIO_printf (bio_err, "-in file       input file\n");
		BIO_printf (bio_err, "-inkey file    input private key (if not signer or recipient)\n");
		BIO_printf (bio_err, "-out file      output file\n");
		BIO_printf (bio_err, "-to addr       to address\n");
		BIO_printf (bio_err, "-from ad       from address\n");
		BIO_printf (bio_err, "-subject s     subject\n");
		BIO_printf (bio_err, "-text          include or delete text MIME headers\n");
		BIO_printf (bio_err, "-CApath dir    trusted certificates directory\n");
		BIO_printf (bio_err, "-CAfile file   trusted certificates file\n");
		BIO_printf(bio_err,  "-rand file:file:...\n");
		BIO_printf(bio_err,  "               load the file (or the files in the directory) into\n");
		BIO_printf(bio_err,  "               the random number generator\n");
		BIO_printf (bio_err, "cert.pem       recipient certificate(s) for encryption\n");
		goto end;
	}

	if(!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
		BIO_printf(bio_err, "Error getting password\n");
		goto end;
	}

	if (need_rand) {
		app_RAND_load_file(NULL, bio_err, (inrand != NULL));
		if (inrand != NULL)
			BIO_printf(bio_err,"%ld semi-random bytes loaded\n",
				app_RAND_load_files(inrand));
	}

	ret = 2;

	if(operation != SMIME_SIGN) flags &= ~PKCS7_DETACHED;

	if(flags & PKCS7_BINARY) {
		if(operation & SMIME_OP) inmode = "rb";
		else outmode = "rb";
	}

	if(operation == SMIME_ENCRYPT) {
		if (!cipher) {
#ifndef NO_RC2			
			cipher = EVP_rc2_40_cbc();
#else
			BIO_printf(bio_err, "No cipher selected\n");
			goto end;
#endif
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("load encryption certificates");
#endif		
		encerts = sk_X509_new_null();
		while (*args) {
			if(!(cert = load_cert(*args))) {
				BIO_printf(bio_err, "Can't read recipient certificate file %s\n", *args);
				goto end;
			}
			sk_X509_push(encerts, cert);
			cert = NULL;
			args++;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	}

	if(signerfile && (operation == SMIME_SIGN)) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("load signer certificate");
#endif		
		if(!(signer = load_cert(signerfile))) {
			BIO_printf(bio_err, "Can't read signer certificate file %s\n", signerfile);
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	}

	if(certfile) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("load other certfiles");
#endif		
		if(!(other = load_certs(certfile))) {
			BIO_printf(bio_err, "Can't read certificate file %s\n", certfile);
			ERR_print_errors(bio_err);
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	}

	if(recipfile && (operation == SMIME_DECRYPT)) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("load recipient certificate");
#endif		
		if(!(recip = load_cert(recipfile))) {
			BIO_printf(bio_err, "Can't read recipient certificate file %s\n", recipfile);
			ERR_print_errors(bio_err);
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	}

	if(operation == SMIME_DECRYPT) {
		if(!keyfile) keyfile = recipfile;
	} else if(operation == SMIME_SIGN) {
		if(!keyfile) keyfile = signerfile;
	} else keyfile = NULL;

	if(keyfile) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("load keyfile");
#endif		
		if(!(key = load_key(keyfile, passin))) {
			BIO_printf(bio_err, "Can't read recipient certificate file %s\n", keyfile);
			ERR_print_errors(bio_err);
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	}

#ifdef CRYPTO_MDEBUG
	CRYPTO_push_info("open input files");
#endif		
	if (infile) {
		if (!(in = BIO_new_file(infile, inmode))) {
			BIO_printf (bio_err,
				 "Can't open input file %s\n", infile);
			goto end;
		}
	} else in = BIO_new_fp(stdin, BIO_NOCLOSE);
#ifdef CRYPTO_MDEBUG
	CRYPTO_pop_info();
#endif		

#ifdef CRYPTO_MDEBUG
	CRYPTO_push_info("open output files");
#endif		
	if (outfile) {
		if (!(out = BIO_new_file(outfile, outmode))) {
			BIO_printf (bio_err,
				 "Can't open output file %s\n", outfile);
			goto end;
		}
	} else out = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef CRYPTO_MDEBUG
	CRYPTO_pop_info();
#endif		

	if(operation == SMIME_VERIFY) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("setup_verify");
#endif		
		if(!(store = setup_verify(CAfile, CApath))) goto end;
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	}

	ret = 3;

	if(operation == SMIME_ENCRYPT) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("PKCS7_encrypt");
#endif		
		p7 = PKCS7_encrypt(encerts, in, cipher, flags);
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	} else if(operation == SMIME_SIGN) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("PKCS7_sign");
#endif		
		p7 = PKCS7_sign(signer, key, other, in, flags);
		BIO_reset(in);
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	} else {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("SMIME_read_PKCS7");
#endif		
		if(!(p7 = SMIME_read_PKCS7(in, &indata))) {
			BIO_printf(bio_err, "Error reading S/MIME message\n");
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	}

	if(!p7) {
		BIO_printf(bio_err, "Error creating PKCS#7 structure\n");
		goto end;
	}

	ret = 4;
	if(operation == SMIME_DECRYPT) {
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("PKCS7_decrypt");
#endif		
		if(!PKCS7_decrypt(p7, key, recip, out, flags)) {
			BIO_printf(bio_err, "Error decrypting PKCS#7 structure\n");
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
	} else if(operation == SMIME_VERIFY) {
		STACK_OF(X509) *signers;
#ifdef CRYPTO_MDEBUG
		CRYPTO_push_info("PKCS7_verify");
#endif		
		if(PKCS7_verify(p7, other, store, indata, out, flags)) {
			BIO_printf(bio_err, "Verification Successful\n");
		} else {
			BIO_printf(bio_err, "Verification Failure\n");
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
		CRYPTO_push_info("PKCS7_get0_signers");
#endif		
		signers = PKCS7_get0_signers(p7, other, flags);
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
		CRYPTO_push_info("save_certs");
#endif		
		if(!save_certs(signerfile, signers)) {
			BIO_printf(bio_err, "Error writing signers to %s\n",
								signerfile);
			ret = 5;
			goto end;
		}
#ifdef CRYPTO_MDEBUG
		CRYPTO_pop_info();
#endif		
		sk_X509_free(signers);
	} else if(operation == SMIME_PK7OUT) {
		PEM_write_bio_PKCS7(out, p7);
	} else {
		if(to) BIO_printf(out, "To: %s\n", to);
		if(from) BIO_printf(out, "From: %s\n", from);
		if(subject) BIO_printf(out, "Subject: %s\n", subject);
		SMIME_write_PKCS7(out, p7, in, flags);
	}
	ret = 0;
end:
#ifdef CRYPTO_MDEBUG
	CRYPTO_remove_all_info();
#endif
	if (need_rand)
		app_RAND_write_file(NULL, bio_err);
	if(ret) ERR_print_errors(bio_err);
	sk_X509_pop_free(encerts, X509_free);
	sk_X509_pop_free(other, X509_free);
	X509_STORE_free(store);
	X509_free(cert);
	X509_free(recip);
	X509_free(signer);
	EVP_PKEY_free(key);
	PKCS7_free(p7);
	BIO_free(in);
	BIO_free(indata);
	BIO_free(out);
	if(passin) Free(passin);
	return (ret);
}

static X509 *load_cert(char *file)
{
	BIO *in;
	X509 *cert;
	if(!(in = BIO_new_file(file, "r"))) return NULL;
	cert = PEM_read_bio_X509(in, NULL, NULL,NULL);
	BIO_free(in);
	return cert;
}

static EVP_PKEY *load_key(char *file, char *pass)
{
	BIO *in;
	EVP_PKEY *key;
	if(!(in = BIO_new_file(file, "r"))) return NULL;
	key = PEM_read_bio_PrivateKey(in, NULL,NULL,pass);
	BIO_free(in);
	return key;
}

static STACK_OF(X509) *load_certs(char *file)
{
	BIO *in;
	int i;
	STACK_OF(X509) *othercerts;
	STACK_OF(X509_INFO) *allcerts;
	X509_INFO *xi;
	if(!(in = BIO_new_file(file, "r"))) return NULL;
	othercerts = sk_X509_new(NULL);
	if(!othercerts) return NULL;
	allcerts = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
	for(i = 0; i < sk_X509_INFO_num(allcerts); i++) {
		xi = sk_X509_INFO_value (allcerts, i);
		if (xi->x509) {
			sk_X509_push(othercerts, xi->x509);
			xi->x509 = NULL;
		}
	}
	sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
	BIO_free(in);
	return othercerts;
}

static X509_STORE *setup_verify(char *CAfile, char *CApath)
{
	X509_STORE *store;
	X509_LOOKUP *lookup;
#ifdef CRYPTO_MDEBUG
	CRYPTO_push_info("X509_STORE_new");
#endif	
	if(!(store = X509_STORE_new())) goto end;
#ifdef CRYPTO_MDEBUG
	CRYPTO_pop_info();
	CRYPTO_push_info("X509_STORE_add_lookup(...file)");
#endif	
	lookup=X509_STORE_add_lookup(store,X509_LOOKUP_file());
	if (lookup == NULL) goto end;
#ifdef CRYPTO_MDEBUG
	CRYPTO_pop_info();
	CRYPTO_push_info("X509_LOOKUP_load_file");
#endif	
	if (CAfile) {
		if(!X509_LOOKUP_load_file(lookup,CAfile,X509_FILETYPE_PEM)) {
			BIO_printf(bio_err, "Error loading file %s\n", CAfile);
			goto end;
		}
	} else X509_LOOKUP_load_file(lookup,NULL,X509_FILETYPE_DEFAULT);
		
#ifdef CRYPTO_MDEBUG
	CRYPTO_pop_info();
	CRYPTO_push_info("X509_STORE_add_lookup(...hash_dir)");
#endif	
	lookup=X509_STORE_add_lookup(store,X509_LOOKUP_hash_dir());
	if (lookup == NULL) goto end;
#ifdef CRYPTO_MDEBUG
	CRYPTO_pop_info();
	CRYPTO_push_info("X509_LOOKUP_add_dir");
#endif	
	if (CApath) {
		if(!X509_LOOKUP_add_dir(lookup,CApath,X509_FILETYPE_PEM)) {
			BIO_printf(bio_err, "Error loading directory %s\n", CApath);
			goto end;
		}
	} else X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);
#ifdef CRYPTO_MDEBUG
	CRYPTO_pop_info();
#endif	

	ERR_clear_error();
	return store;
	end:
	X509_STORE_free(store);
	return NULL;
}

static int save_certs(char *signerfile, STACK_OF(X509) *signers)
{
	int i;
	BIO *tmp;
	if(!signerfile) return 1;
	tmp = BIO_new_file(signerfile, "w");
	if(!tmp) return 0;
	for(i = 0; i < sk_X509_num(signers); i++)
		PEM_write_bio_X509(tmp, sk_X509_value(signers, i));
	BIO_free(tmp);
	return 1;
}
	
