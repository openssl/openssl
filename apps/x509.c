/* apps/x509.c */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NO_STDIO
#define APPS_WIN16
#endif
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#undef PROG
#define PROG x509_main

#undef POSTFIX
#define	POSTFIX	".srl"
#define DEF_DAYS	30

#define CERT_HDR	"certificate"

static char *x509_usage[]={
"usage: x509 args\n",
" -inform arg     - input format - default PEM (one of DER, NET or PEM)\n",
" -outform arg    - output format - default PEM (one of DER, NET or PEM)\n",
" -keyform arg    - private key format - default PEM\n",
" -CAform arg     - CA format - default PEM\n",
" -CAkeyform arg  - CA key format - default PEM\n",
" -in arg         - input file - default stdin\n",
" -out arg        - output file - default stdout\n",
" -serial         - print serial number value\n",
" -hash           - print hash value\n",
" -subject        - print subject DN\n",
" -issuer         - print issuer DN\n",
" -startdate      - notBefore field\n",
" -enddate        - notAfter field\n",
" -dates          - both Before and After dates\n",
" -modulus        - print the RSA key modulus\n",
" -fingerprint    - print the certificate fingerprint\n",
" -noout          - no certificate output\n",

" -days arg       - How long till expiry of a signed certificate - def 30 days\n",
" -signkey arg    - self sign cert with arg\n",
" -x509toreq      - output a certification request object\n",
" -req            - input is a certificate request, sign and output.\n",
" -CA arg         - set the CA certificate, must be PEM format.\n",
" -CAkey arg      - set the CA key, must be PEM format\n",
"                   missing, it is asssumed to be in the CA file.\n",
" -CAcreateserial - create serial number file if it does not exist\n",
" -CAserial       - serial file\n",
" -text           - print the certificate in text form\n",
" -C              - print out C code forms\n",
" -md2/-md5/-sha1/-mdc2 - digest to do an RSA sign with\n",
" -extfile        - configuration file with X509V3 extensions to add\n",
NULL
};

static int MS_CALLBACK callb(int ok, X509_STORE_CTX *ctx);
static EVP_PKEY *load_key(char *file, int format);
static X509 *load_cert(char *file, int format);
static int sign (X509 *x, EVP_PKEY *pkey,int days,const EVP_MD *digest,
						LHASH *conf, char *section);
static int x509_certify (X509_STORE *ctx,char *CAfile,const EVP_MD *digest,
			 X509 *x,X509 *xca,EVP_PKEY *pkey,char *serial,
			 int create,int days, LHASH *conf, char *section);
static int reqfile=0;

int MAIN(int argc, char **argv)
	{
	int ret=1;
	X509_REQ *req=NULL;
	X509 *x=NULL,*xca=NULL;
	EVP_PKEY *Upkey=NULL,*CApkey=NULL;
	int i,num,badops=0;
	BIO *out=NULL;
	BIO *STDout=NULL;
	int informat,outformat,keyformat,CAformat,CAkeyformat;
	char *infile=NULL,*outfile=NULL,*keyfile=NULL,*CAfile=NULL;
	char *CAkeyfile=NULL,*CAserial=NULL;
	int text=0,serial=0,hash=0,subject=0,issuer=0,startdate=0,enddate=0;
	int noout=0,sign_flag=0,CA_flag=0,CA_createserial=0;
	int C=0;
	int x509req=0,days=DEF_DAYS,modulus=0;
	char **pp;
	X509_STORE *ctx=NULL;
	X509_REQ *rq=NULL;
	int fingerprint=0;
	char buf[256];
	const EVP_MD *md_alg,*digest=EVP_md5();
	LHASH *extconf = NULL;
	char *extsect = NULL, *extfile = NULL;

	reqfile=0;

	apps_startup();

	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	STDout=BIO_new_fp(stdout,BIO_NOCLOSE);

	informat=FORMAT_PEM;
	outformat=FORMAT_PEM;
	keyformat=FORMAT_PEM;
	CAformat=FORMAT_PEM;
	CAkeyformat=FORMAT_PEM;

	ctx=X509_STORE_new();
	if (ctx == NULL) goto end;
	X509_STORE_set_verify_cb_func(ctx,callb);

	argc--;
	argv++;
	num=0;
	while (argc >= 1)
		{
		if 	(strcmp(*argv,"-inform") == 0)
			{
			if (--argc < 1) goto bad;
			informat=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-outform") == 0)
			{
			if (--argc < 1) goto bad;
			outformat=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-keyform") == 0)
			{
			if (--argc < 1) goto bad;
			keyformat=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-req") == 0)
			reqfile=1;
		else if (strcmp(*argv,"-CAform") == 0)
			{
			if (--argc < 1) goto bad;
			CAformat=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-CAkeyform") == 0)
			{
			if (--argc < 1) goto bad;
			CAformat=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-days") == 0)
			{
			if (--argc < 1) goto bad;
			days=atoi(*(++argv));
			if (days == 0)
				{
				BIO_printf(STDout,"bad number of days\n");
				goto bad;
				}
			}
		else if (strcmp(*argv,"-extfile") == 0)
			{
			if (--argc < 1) goto bad;
			extfile= *(++argv);
			}
		else if (strcmp(*argv,"-in") == 0)
			{
			if (--argc < 1) goto bad;
			infile= *(++argv);
			}
		else if (strcmp(*argv,"-out") == 0)
			{
			if (--argc < 1) goto bad;
			outfile= *(++argv);
			}
		else if (strcmp(*argv,"-signkey") == 0)
			{
			if (--argc < 1) goto bad;
			keyfile= *(++argv);
			sign_flag= ++num;
			}
		else if (strcmp(*argv,"-CA") == 0)
			{
			if (--argc < 1) goto bad;
			CAfile= *(++argv);
			CA_flag= ++num;
			}
		else if (strcmp(*argv,"-CAkey") == 0)
			{
			if (--argc < 1) goto bad;
			CAkeyfile= *(++argv);
			}
		else if (strcmp(*argv,"-CAserial") == 0)
			{
			if (--argc < 1) goto bad;
			CAserial= *(++argv);
			}
		else if (strcmp(*argv,"-C") == 0)
			C= ++num;
		else if (strcmp(*argv,"-serial") == 0)
			serial= ++num;
		else if (strcmp(*argv,"-modulus") == 0)
			modulus= ++num;
		else if (strcmp(*argv,"-x509toreq") == 0)
			x509req= ++num;
		else if (strcmp(*argv,"-text") == 0)
			text= ++num;
		else if (strcmp(*argv,"-hash") == 0)
			hash= ++num;
		else if (strcmp(*argv,"-subject") == 0)
			subject= ++num;
		else if (strcmp(*argv,"-issuer") == 0)
			issuer= ++num;
		else if (strcmp(*argv,"-fingerprint") == 0)
			fingerprint= ++num;
		else if (strcmp(*argv,"-dates") == 0)
			{
			startdate= ++num;
			enddate= ++num;
			}
		else if (strcmp(*argv,"-startdate") == 0)
			startdate= ++num;
		else if (strcmp(*argv,"-enddate") == 0)
			enddate= ++num;
		else if (strcmp(*argv,"-noout") == 0)
			noout= ++num;
		else if (strcmp(*argv,"-CAcreateserial") == 0)
			CA_createserial= ++num;
		else if ((md_alg=EVP_get_digestbyname(&((*argv)[1]))) != NULL)
			{
			/* ok */
			digest=md_alg;
			}
		else
			{
			BIO_printf(bio_err,"unknown option %s\n",*argv);
			badops=1;
			break;
			}
		argc--;
		argv++;
		}

	if (badops)
		{
bad:
		for (pp=x509_usage; (*pp != NULL); pp++)
			BIO_printf(bio_err,*pp);
		goto end;
		}

	ERR_load_crypto_strings();
	X509V3_add_standard_extensions();

	if (!X509_STORE_set_default_paths(ctx))
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if ((CAkeyfile == NULL) && (CA_flag) && (CAformat == FORMAT_PEM))
		{ CAkeyfile=CAfile; }
	else if ((CA_flag) && (CAkeyfile == NULL))
		{
		BIO_printf(bio_err,"need to specify a CAkey if using the CA command\n");
		goto end;
		}

	if (extfile) {
		long errorline;
		X509V3_CTX ctx2;
		if (!(extconf=CONF_load(NULL,extfile,&errorline))) {
			if (errorline <= 0)
				BIO_printf(bio_err,
					"error loading the config file '%s'\n",
								extfile);
                	else
                        	BIO_printf(bio_err,
				       "error on line %ld of config file '%s'\n"
							,errorline,extfile);
			goto end;
		}
		if(!(extsect = CONF_get_string(extconf, "default",
					 "extensions"))) extsect = "default";
		X509V3_set_ctx_test(&ctx2);
		X509V3_set_conf_lhash(&ctx2, extconf);
		if(!X509V3_EXT_add_conf(extconf, &ctx2, extsect, NULL)) {
			BIO_printf(bio_err,
				"Error Loading extension section %s\n",
								 extsect);
			ERR_print_errors(bio_err);
			goto end;
                }
	} 


	if (reqfile)
		{
		EVP_PKEY *pkey;
		X509_CINF *ci;
		BIO *in;

		if (!sign_flag && !CA_flag)
			{
			BIO_printf(bio_err,"We need a private key to sign with\n");
			goto end;
			}
		in=BIO_new(BIO_s_file());
		if (in == NULL)
			{
			ERR_print_errors(bio_err);
			goto end;
			}

		if (infile == NULL)
			BIO_set_fp(in,stdin,BIO_NOCLOSE|BIO_FP_TEXT);
		else
			{
			if (BIO_read_filename(in,infile) <= 0)
				{
				perror(infile);
				goto end;
				}
			}
		req=PEM_read_bio_X509_REQ(in,NULL,NULL,NULL);
		BIO_free(in);

		if (req == NULL) { perror(infile); goto end; }

		if (	(req->req_info == NULL) ||
			(req->req_info->pubkey == NULL) ||
			(req->req_info->pubkey->public_key == NULL) ||
			(req->req_info->pubkey->public_key->data == NULL))
			{
			BIO_printf(bio_err,"The certificate request appears to corrupted\n");
			BIO_printf(bio_err,"It does not contain a public key\n");
			goto end;
			}
		if ((pkey=X509_REQ_get_pubkey(req)) == NULL)
	                {
	                BIO_printf(bio_err,"error unpacking public key\n");
	                goto end;
	                }
		i=X509_REQ_verify(req,pkey);
		EVP_PKEY_free(pkey);
		if (i < 0)
			{
			BIO_printf(bio_err,"Signature verification error\n");
			ERR_print_errors(bio_err);
			goto end;
			}
	        if (i == 0)
			{
			BIO_printf(bio_err,"Signature did not match the certificate request\n");
			goto end;
			}
		else
			BIO_printf(bio_err,"Signature ok\n");
		
		X509_NAME_oneline(req->req_info->subject,buf,256);
		BIO_printf(bio_err,"subject=%s\n",buf);

		if ((x=X509_new()) == NULL) goto end;
		ci=x->cert_info;

		if (!ASN1_INTEGER_set(X509_get_serialNumber(x),0)) goto end;
		if (!X509_set_issuer_name(x,req->req_info->subject)) goto end;
		if (!X509_set_subject_name(x,req->req_info->subject)) goto end;

		X509_gmtime_adj(X509_get_notBefore(x),0);
	        X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);

#if 0
		X509_PUBKEY_free(ci->key);
		ci->key=req->req_info->pubkey;
	        req->req_info->pubkey=NULL;
#else
		pkey = X509_REQ_get_pubkey(req);
		X509_set_pubkey(x,pkey);
		EVP_PKEY_free(pkey);
#endif
		}
	else
		x=load_cert(infile,informat);

	if (x == NULL) goto end;
	if (CA_flag)
		{
		xca=load_cert(CAfile,CAformat);
		if (xca == NULL) goto end;
		}

	if (!noout || text)
		{
		OBJ_create("2.99999.3",
			"SET.ex3","SET x509v3 extension 3");

		out=BIO_new(BIO_s_file());
		if (out == NULL)
			{
			ERR_print_errors(bio_err);
			goto end;
			}
		if (outfile == NULL)
			BIO_set_fp(out,stdout,BIO_NOCLOSE);
		else
			{
			if (BIO_write_filename(out,outfile) <= 0)
				{
				perror(outfile);
				goto end;
				}
			}
		}

	if (num)
		{
		for (i=1; i<=num; i++)
			{
			if (issuer == i)
				{
				X509_NAME_oneline(X509_get_issuer_name(x),
					buf,256);
				BIO_printf(STDout,"issuer= %s\n",buf);
				}
			else if (subject == i) 
				{
				X509_NAME_oneline(X509_get_subject_name(x),
					buf,256);
				BIO_printf(STDout,"subject=%s\n",buf);
				}
			else if (serial == i)
				{
				BIO_printf(STDout,"serial=");
				i2a_ASN1_INTEGER(STDout,x->cert_info->serialNumber);
				BIO_printf(STDout,"\n");
				}
			else if (hash == i)
				{
				BIO_printf(STDout,"%08lx\n",X509_subject_name_hash(x));
				}
			else
				if (modulus == i)
				{
				EVP_PKEY *pkey;

				pkey=X509_get_pubkey(x);
				if (pkey == NULL)
					{
					BIO_printf(bio_err,"Modulus=unavailable\n");
					ERR_print_errors(bio_err);
					goto end;
					}
				BIO_printf(STDout,"Modulus=");
#ifndef NO_RSA
				if (pkey->type == EVP_PKEY_RSA)
					BN_print(STDout,pkey->pkey.rsa->n);
				else
#endif
#ifndef NO_DSA
				if (pkey->type == EVP_PKEY_DSA)
					BN_print(STDout,pkey->pkey.dsa->pub_key);
				else
#endif
					BIO_printf(STDout,"Wrong Algorithm type");
				BIO_printf(STDout,"\n");
				EVP_PKEY_free(pkey);
				}
			else
				if (C == i)
				{
				unsigned char *d;
				char *m;
				int y,z;

				X509_NAME_oneline(X509_get_subject_name(x),
					buf,256);
				BIO_printf(STDout,"/* subject:%s */\n",buf);
				m=X509_NAME_oneline(
					X509_get_issuer_name(x),buf,256);
				BIO_printf(STDout,"/* issuer :%s */\n",buf);

				z=i2d_X509(x,NULL);
				m=Malloc(z);

				d=(unsigned char *)m;
				z=i2d_X509_NAME(X509_get_subject_name(x),&d);
				BIO_printf(STDout,"unsigned char XXX_subject_name[%d]={\n",z);
				d=(unsigned char *)m;
				for (y=0; y<z; y++)
					{
					BIO_printf(STDout,"0x%02X,",d[y]);
					if ((y & 0x0f) == 0x0f) BIO_printf(STDout,"\n");
					}
				if (y%16 != 0) BIO_printf(STDout,"\n");
				BIO_printf(STDout,"};\n");

				z=i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x),&d);
				BIO_printf(STDout,"unsigned char XXX_public_key[%d]={\n",z);
				d=(unsigned char *)m;
				for (y=0; y<z; y++)
					{
					BIO_printf(STDout,"0x%02X,",d[y]);
					if ((y & 0x0f) == 0x0f)
						BIO_printf(STDout,"\n");
					}
				if (y%16 != 0) BIO_printf(STDout,"\n");
				BIO_printf(STDout,"};\n");

				z=i2d_X509(x,&d);
				BIO_printf(STDout,"unsigned char XXX_certificate[%d]={\n",z);
				d=(unsigned char *)m;
				for (y=0; y<z; y++)
					{
					BIO_printf(STDout,"0x%02X,",d[y]);
					if ((y & 0x0f) == 0x0f)
						BIO_printf(STDout,"\n");
					}
				if (y%16 != 0) BIO_printf(STDout,"\n");
				BIO_printf(STDout,"};\n");

				Free(m);
				}
			else if (text == i)
				{
				X509_print(out,x);
				}
			else if (startdate == i)
				{
				BIO_puts(STDout,"notBefore=");
				ASN1_TIME_print(STDout,X509_get_notBefore(x));
				BIO_puts(STDout,"\n");
				}
			else if (enddate == i)
				{
				BIO_puts(STDout,"notAfter=");
				ASN1_TIME_print(STDout,X509_get_notAfter(x));
				BIO_puts(STDout,"\n");
				}
			else if (fingerprint == i)
				{
				int j;
				unsigned int n;
				unsigned char md[EVP_MAX_MD_SIZE];

				if (!X509_digest(x,EVP_md5(),md,&n))
					{
					BIO_printf(bio_err,"out of memory\n");
					goto end;
					}
				BIO_printf(STDout,"MD5 Fingerprint=");
				for (j=0; j<(int)n; j++)
					{
					BIO_printf(STDout,"%02X%c",md[j],
						(j+1 == (int)n)
						?'\n':':');
					}
				}

			/* should be in the library */
			else if ((sign_flag == i) && (x509req == 0))
				{
				BIO_printf(bio_err,"Getting Private key\n");
				if (Upkey == NULL)
					{
					Upkey=load_key(keyfile,keyformat);
					if (Upkey == NULL) goto end;
					}
#ifndef NO_DSA
		                if (Upkey->type == EVP_PKEY_DSA)
		                        digest=EVP_dss1();
#endif

				if (!sign(x,Upkey,days,digest,
						 extconf, extsect)) goto end;
				}
			else if (CA_flag == i)
				{
				BIO_printf(bio_err,"Getting CA Private Key\n");
				if (CAkeyfile != NULL)
					{
					CApkey=load_key(CAkeyfile,CAkeyformat);
					if (CApkey == NULL) goto end;
					}
#ifndef NO_DSA
		                if (CApkey->type == EVP_PKEY_DSA)
		                        digest=EVP_dss1();
#endif
				
				if (!x509_certify(ctx,CAfile,digest,x,xca,
					CApkey, CAserial,CA_createserial,days,
					extconf, extsect))
					goto end;
				}
			else if (x509req == i)
				{
				EVP_PKEY *pk;

				BIO_printf(bio_err,"Getting request Private Key\n");
				if (keyfile == NULL)
					{
					BIO_printf(bio_err,"no request key file specified\n");
					goto end;
					}
				else
					{
					pk=load_key(keyfile,FORMAT_PEM);
					if (pk == NULL) goto end;
					}

				BIO_printf(bio_err,"Generating certificate request\n");

				rq=X509_to_X509_REQ(x,pk,EVP_md5());
				EVP_PKEY_free(pk);
				if (rq == NULL)
					{
					ERR_print_errors(bio_err);
					goto end;
					}
				if (!noout)
					{
					X509_REQ_print(out,rq);
					PEM_write_bio_X509_REQ(out,rq);
					}
				noout=1;
				}
			}
		}

	if (noout)
		{
		ret=0;
		goto end;
		}

	if 	(outformat == FORMAT_ASN1)
		i=i2d_X509_bio(out,x);
	else if (outformat == FORMAT_PEM)
		i=PEM_write_bio_X509(out,x);
	else if (outformat == FORMAT_NETSCAPE)
		{
		ASN1_HEADER ah;
		ASN1_OCTET_STRING os;

		os.data=(unsigned char *)CERT_HDR;
		os.length=strlen(CERT_HDR);
		ah.header= &os;
		ah.data=(char *)x;
		ah.meth=X509_asn1_meth();

		/* no macro for this one yet */
		i=ASN1_i2d_bio(i2d_ASN1_HEADER,out,(unsigned char *)&ah);
		}
	else	{
		BIO_printf(bio_err,"bad output format specified for outfile\n");
		goto end;
		}
	if (!i) {
		BIO_printf(bio_err,"unable to write certificate\n");
		ERR_print_errors(bio_err);
		goto end;
		}
	ret=0;
end:
	OBJ_cleanup();
	CONF_free(extconf);
	BIO_free(out);
	BIO_free(STDout);
	X509_STORE_free(ctx);
	X509_REQ_free(req);
	X509_free(x);
	X509_free(xca);
	EVP_PKEY_free(Upkey);
	EVP_PKEY_free(CApkey);
	X509_REQ_free(rq);
	X509V3_EXT_cleanup();
	EXIT(ret);
	}

static int x509_certify(X509_STORE *ctx, char *CAfile, const EVP_MD *digest,
	     X509 *x, X509 *xca, EVP_PKEY *pkey, char *serialfile, int create,
	     int days, LHASH *conf, char *section)
	{
	int ret=0;
	BIO *io=NULL;
	MS_STATIC char buf2[1024];
	char *buf=NULL,*p;
	BIGNUM *serial=NULL;
	ASN1_INTEGER *bs=NULL,bs2;
	X509_STORE_CTX xsc;
	EVP_PKEY *upkey;

	upkey = X509_get_pubkey(xca);
	EVP_PKEY_copy_parameters(upkey,pkey);
	EVP_PKEY_free(upkey);

	X509_STORE_CTX_init(&xsc,ctx,x,NULL);
	buf=(char *)Malloc(EVP_PKEY_size(pkey)*2+
		((serialfile == NULL)
			?(strlen(CAfile)+strlen(POSTFIX)+1)
			:(strlen(serialfile)))+1);
	if (buf == NULL) { BIO_printf(bio_err,"out of mem\n"); goto end; }
	if (serialfile == NULL)
		{
		strcpy(buf,CAfile);
		for (p=buf; *p; p++)
			if (*p == '.')
				{
				*p='\0';
				break;
				}
		strcat(buf,POSTFIX);
		}
	else
		strcpy(buf,serialfile);
	serial=BN_new();
	bs=ASN1_INTEGER_new();
	if ((serial == NULL) || (bs == NULL))
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	io=BIO_new(BIO_s_file());
	if (io == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}
	
	if (BIO_read_filename(io,buf) <= 0)
		{
		if (!create)
			{
			perror(buf);
			goto end;
			}
		else
			{
			ASN1_INTEGER_set(bs,0);
			BN_zero(serial);
			}
		}
	else 
		{
		if (!a2i_ASN1_INTEGER(io,bs,buf2,1024))
			{
			BIO_printf(bio_err,"unable to load serial number from %s\n",buf);
			ERR_print_errors(bio_err);
			goto end;
			}
		else
			{
			serial=BN_bin2bn(bs->data,bs->length,serial);
			if (serial == NULL)
				{
				BIO_printf(bio_err,"error converting bin 2 bn");
				goto end;
				}
			}
		}

	if (!BN_add_word(serial,1))
		{ BIO_printf(bio_err,"add_word failure\n"); goto end; }
	bs2.data=(unsigned char *)buf2;
	bs2.length=BN_bn2bin(serial,bs2.data);

	if (BIO_write_filename(io,buf) <= 0)
		{
		BIO_printf(bio_err,"error attempting to write serial number file\n");
		perror(buf);
		goto end;
		}
	i2a_ASN1_INTEGER(io,&bs2);
	BIO_puts(io,"\n");
	BIO_free(io);
	io=NULL;
	
	if (!X509_STORE_add_cert(ctx,x)) goto end;

	/* NOTE: this certificate can/should be self signed, unless it was
	 * a certificate request in which case it is not. */
	X509_STORE_CTX_set_cert(&xsc,x);
	if (!reqfile && !X509_verify_cert(&xsc))
		goto end;

	if (!X509_check_private_key(xca,pkey))
		{
		BIO_printf(bio_err,"CA certificate and CA private key do not match\n");
		goto end;
		}

	if (!X509_set_issuer_name(x,X509_get_subject_name(xca))) goto end;
	if (!X509_set_serialNumber(x,bs)) goto end;

	if (X509_gmtime_adj(X509_get_notBefore(x),0L) == NULL)
		goto end;

	/* hardwired expired */
	if (X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days) == NULL)
		goto end;

	if(conf) {
		X509V3_CTX ctx2;
		X509_set_version(x,2); /* version 3 certificate */
                X509V3_set_ctx(&ctx2, xca, x, NULL, NULL, 0);
                X509V3_set_conf_lhash(&ctx2, conf);
                if(!X509V3_EXT_add_conf(conf, &ctx2, section, x)) goto end;
	}

	if (!X509_sign(x,pkey,digest)) goto end;
	ret=1;
end:
	X509_STORE_CTX_cleanup(&xsc);
	if (!ret)
		ERR_print_errors(bio_err);
	if (buf != NULL) Free(buf);
	if (bs != NULL) ASN1_INTEGER_free(bs);
	if (io != NULL)	BIO_free(io);
	if (serial != NULL) BN_free(serial);
	return(ret);
	}

static int MS_CALLBACK callb(int ok, X509_STORE_CTX *ctx)
	{
	char buf[256];
	int err;
	X509 *err_cert;

	/* it is ok to use a self signed certificate
	 * This case will catch both the initial ok == 0 and the
	 * final ok == 1 calls to this function */
	err=X509_STORE_CTX_get_error(ctx);
	if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
		return(1);

	/* BAD we should have gotten an error.  Normally if everything
	 * worked X509_STORE_CTX_get_error(ctx) will still be set to
	 * DEPTH_ZERO_SELF_.... */
	if (ok)
		{
		BIO_printf(bio_err,"error with certificate to be certified - should be self signed\n");
		return(0);
		}
	else
		{
		err_cert=X509_STORE_CTX_get_current_cert(ctx);
		X509_NAME_oneline(X509_get_subject_name(err_cert),buf,256);
		BIO_printf(bio_err,"%s\n",buf);
		BIO_printf(bio_err,"error with certificate - error %d at depth %d\n%s\n",
			err,X509_STORE_CTX_get_error_depth(ctx),
			X509_verify_cert_error_string(err));
		return(1);
		}
	}

static EVP_PKEY *load_key(char *file, int format)
	{
	BIO *key=NULL;
	EVP_PKEY *pkey=NULL;

	if (file == NULL)
		{
		BIO_printf(bio_err,"no keyfile specified\n");
		goto end;
		}
	key=BIO_new(BIO_s_file());
	if (key == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}
	if (BIO_read_filename(key,file) <= 0)
		{
		perror(file);
		goto end;
		}
#ifndef NO_RSA
	if	(format == FORMAT_ASN1)
		{
		RSA *rsa;

		rsa=d2i_RSAPrivateKey_bio(key,NULL);
		if (rsa != NULL)
			{
			if ((pkey=EVP_PKEY_new()) != NULL)
				EVP_PKEY_assign_RSA(pkey,rsa);
			else
				RSA_free(rsa);
			}
		}
	else
#endif
		if (format == FORMAT_PEM)
		{
		pkey=PEM_read_bio_PrivateKey(key,NULL,NULL,NULL);
		}
	else
		{
		BIO_printf(bio_err,"bad input format specified for key\n");
		goto end;
		}
end:
	if (key != NULL) BIO_free(key);
	if (pkey == NULL)
		BIO_printf(bio_err,"unable to load Private Key\n");
	return(pkey);
	}

static X509 *load_cert(char *file, int format)
	{
	ASN1_HEADER *ah=NULL;
	BUF_MEM *buf=NULL;
	X509 *x=NULL;
	BIO *cert;

	if ((cert=BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (file == NULL)
		BIO_set_fp(cert,stdin,BIO_NOCLOSE);
	else
		{
		if (BIO_read_filename(cert,file) <= 0)
			{
			perror(file);
			goto end;
			}
		}
	if 	(format == FORMAT_ASN1)
		x=d2i_X509_bio(cert,NULL);
	else if (format == FORMAT_NETSCAPE)
		{
		unsigned char *p,*op;
		int size=0,i;

		/* We sort of have to do it this way because it is sort of nice
		 * to read the header first and check it, then
		 * try to read the certificate */
		buf=BUF_MEM_new();
		for (;;)
			{
			if ((buf == NULL) || (!BUF_MEM_grow(buf,size+1024*10)))
				goto end;
			i=BIO_read(cert,&(buf->data[size]),1024*10);
			size+=i;
			if (i == 0) break;
			if (i < 0)
				{
				perror("reading certificate");
				goto end;
				}
			}
		p=(unsigned char *)buf->data;
		op=p;

		/* First load the header */
		if ((ah=d2i_ASN1_HEADER(NULL,&p,(long)size)) == NULL)
			goto end;
		if ((ah->header == NULL) || (ah->header->data == NULL) ||
			(strncmp(CERT_HDR,(char *)ah->header->data,
			ah->header->length) != 0))
			{
			BIO_printf(bio_err,"Error reading header on certificate\n");
			goto end;
			}
		/* header is ok, so now read the object */
		p=op;
		ah->meth=X509_asn1_meth();
		if ((ah=d2i_ASN1_HEADER(&ah,&p,(long)size)) == NULL)
			goto end;
		x=(X509 *)ah->data;
		ah->data=NULL;
		}
	else if (format == FORMAT_PEM)
		x=PEM_read_bio_X509(cert,NULL,NULL,NULL);
	else	{
		BIO_printf(bio_err,"bad input format specified for input cert\n");
		goto end;
		}
end:
	if (x == NULL)
		{
		BIO_printf(bio_err,"unable to load certificate\n");
		ERR_print_errors(bio_err);
		}
	if (ah != NULL) ASN1_HEADER_free(ah);
	if (cert != NULL) BIO_free(cert);
	if (buf != NULL) BUF_MEM_free(buf);
	return(x);
	}

/* self sign */
static int sign(X509 *x, EVP_PKEY *pkey, int days, const EVP_MD *digest, 
						LHASH *conf, char *section)
	{

	EVP_PKEY *pktmp;

	pktmp = X509_get_pubkey(x);
	EVP_PKEY_copy_parameters(pktmp,pkey);
	EVP_PKEY_save_parameters(pktmp,1);
	EVP_PKEY_free(pktmp);

	if (!X509_set_issuer_name(x,X509_get_subject_name(x))) goto err;
	if (X509_gmtime_adj(X509_get_notBefore(x),0) == NULL) goto err;

	/* Lets just make it 12:00am GMT, Jan 1 1970 */
	/* memcpy(x->cert_info->validity->notBefore,"700101120000Z",13); */
	/* 28 days to be certified */

	if (X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days) == NULL)
		goto err;

	if (!X509_set_pubkey(x,pkey)) goto err;
	if(conf) {
		X509V3_CTX ctx;
		X509_set_version(x,2); /* version 3 certificate */
                X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
                X509V3_set_conf_lhash(&ctx, conf);
                if(!X509V3_EXT_add_conf(conf, &ctx, section, x)) goto err;
	}
	if (!X509_sign(x,pkey,digest)) goto err;
	return(1);
err:
	ERR_print_errors(bio_err);
	return(0);
	}
