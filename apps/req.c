/* apps/req.c */
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
#include <time.h>
#include <string.h>
#ifdef NO_STDIO
#define APPS_WIN16
#endif
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#define SECTION		"req"

#define BITS		"default_bits"
#define KEYFILE		"default_keyfile"
#define DISTINGUISHED_NAME	"distinguished_name"
#define ATTRIBUTES	"attributes"
#define V3_EXTENSIONS	"x509_extensions"

#define DEFAULT_KEY_LENGTH	512
#define MIN_KEY_LENGTH		384

#undef PROG
#define PROG	req_main

/* -inform arg	- input format - default PEM (one of DER, TXT or PEM)
 * -outform arg - output format - default PEM
 * -in arg	- input file - default stdin
 * -out arg	- output file - default stdout
 * -verify	- check request signature
 * -noout	- don't print stuff out.
 * -text	- print out human readable text.
 * -nodes	- no des encryption
 * -config file	- Load configuration file.
 * -key file	- make a request using key in file (or use it for verification).
 * -keyform	- key file format.
 * -newkey	- make a key and a request.
 * -modulus	- print RSA modulus.
 * -x509	- output a self signed X509 structure instead.
 * -asn1-kludge	- output new certificate request in a format that some CA's
 *		  require.  This format is wrong
 */

static int make_REQ(X509_REQ *req,EVP_PKEY *pkey,int attribs);
static int add_attribute_object(STACK_OF(X509_ATTRIBUTE) *n, char *text,
				char *def, char *value, int nid, int min,
				int max);
static int add_DN_object(X509_NAME *n, char *text, char *def, char *value,
	int nid,int min,int max);
static void MS_CALLBACK req_cb(int p,int n,void *arg);
static int req_fix_data(int nid,int *type,int len,int min,int max);
static int check_end(char *str, char *end);
static int add_oid_section(LHASH *conf);
#ifndef MONOLITH
static char *default_config_file=NULL;
static LHASH *config=NULL;
#endif
static LHASH *req_conf=NULL;

#define TYPE_RSA	1
#define TYPE_DSA	2
#define TYPE_DH		3

int MAIN(int argc, char **argv)
	{
#ifndef NO_DSA
	DSA *dsa_params=NULL;
#endif
	int ex=1,x509=0,days=30;
	X509 *x509ss=NULL;
	X509_REQ *req=NULL;
	EVP_PKEY *pkey=NULL;
	int i,badops=0,newreq=0,newkey= -1,pkey_type=0;
	BIO *in=NULL,*out=NULL;
	int informat,outformat,verify=0,noout=0,text=0,keyform=FORMAT_PEM;
	int nodes=0,kludge=0;
	char *infile,*outfile,*prog,*keyfile=NULL,*template=NULL,*keyout=NULL;
	char *extensions = NULL;
	EVP_CIPHER *cipher=NULL;
	int modulus=0;
	char *p;
	const EVP_MD *md_alg=NULL,*digest=EVP_md5();
#ifndef MONOLITH
	MS_STATIC char config_name[256];
#endif

#ifndef NO_DES
	cipher=EVP_des_ede3_cbc();
#endif
	apps_startup();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	infile=NULL;
	outfile=NULL;
	informat=FORMAT_PEM;
	outformat=FORMAT_PEM;

	prog=argv[0];
	argc--;
	argv++;
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
		else if (strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto bad;
			keyfile= *(++argv);
			}
		else if (strcmp(*argv,"-new") == 0)
			{
			pkey_type=TYPE_RSA;
			newreq=1;
			}
		else if (strcmp(*argv,"-config") == 0)
			{	
			if (--argc < 1) goto bad;
			template= *(++argv);
			}
		else if (strcmp(*argv,"-keyform") == 0)
			{
			if (--argc < 1) goto bad;
			keyform=str2fmt(*(++argv));
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
		else if (strcmp(*argv,"-keyout") == 0)
			{
			if (--argc < 1) goto bad;
			keyout= *(++argv);
			}
		else if (strcmp(*argv,"-newkey") == 0)
			{
			int is_numeric;

			if (--argc < 1) goto bad;
			p= *(++argv);
			is_numeric = p[0] >= '0' && p[0] <= '9';
			if (strncmp("rsa:",p,4) == 0 || is_numeric)
				{
				pkey_type=TYPE_RSA;
				if(!is_numeric)
				    p+=4;
				newkey= atoi(p);
				}
			else
#ifndef NO_DSA
				if (strncmp("dsa:",p,4) == 0)
				{
				X509 *xtmp=NULL;
				EVP_PKEY *dtmp;

				pkey_type=TYPE_DSA;
				p+=4;
				if ((in=BIO_new_file(p,"r")) == NULL)
					{
					perror(p);
					goto end;
					}
				if ((dsa_params=PEM_read_bio_DSAparams(in,NULL,NULL,NULL)) == NULL)
					{
					ERR_clear_error();
					(void)BIO_reset(in);
					if ((xtmp=PEM_read_bio_X509(in,NULL,NULL,NULL)) == NULL)
						{
						BIO_printf(bio_err,"unable to load DSA parameters from file\n");
						goto end;
						}

					dtmp=X509_get_pubkey(xtmp);
					if (dtmp->type == EVP_PKEY_DSA)
						dsa_params=DSAparams_dup(dtmp->pkey.dsa);
					EVP_PKEY_free(dtmp);
					X509_free(xtmp);
					if (dsa_params == NULL)
						{
						BIO_printf(bio_err,"Certificate does not contain DSA parameters\n");
						goto end;
						}
					}
				BIO_free(in);
				newkey=BN_num_bits(dsa_params->p);
				in=NULL;
				}
			else 
#endif
#ifndef NO_DH
				if (strncmp("dh:",p,4) == 0)
				{
				pkey_type=TYPE_DH;
				p+=3;
				}
			else
#endif
				pkey_type=TYPE_RSA;

			newreq=1;
			}
		else if (strcmp(*argv,"-modulus") == 0)
			modulus=1;
		else if (strcmp(*argv,"-verify") == 0)
			verify=1;
		else if (strcmp(*argv,"-nodes") == 0)
			nodes=1;
		else if (strcmp(*argv,"-noout") == 0)
			noout=1;
		else if (strcmp(*argv,"-text") == 0)
			text=1;
		else if (strcmp(*argv,"-x509") == 0)
			x509=1;
		else if (strcmp(*argv,"-asn1-kludge") == 0)
			kludge=1;
		else if (strcmp(*argv,"-no-asn1-kludge") == 0)
			kludge=0;
		else if (strcmp(*argv,"-days") == 0)
			{
			if (--argc < 1) goto bad;
			days= atoi(*(++argv));
			if (days == 0) days=30;
			}
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
		BIO_printf(bio_err,"%s [options] <infile >outfile\n",prog);
		BIO_printf(bio_err,"where options  are\n");
		BIO_printf(bio_err," -inform arg    input format - one of DER TXT PEM\n");
		BIO_printf(bio_err," -outform arg   output format - one of DER TXT PEM\n");
		BIO_printf(bio_err," -in arg        input file\n");
		BIO_printf(bio_err," -out arg       output file\n");
		BIO_printf(bio_err," -text          text form of request\n");
		BIO_printf(bio_err," -noout         do not output REQ\n");
		BIO_printf(bio_err," -verify        verify signature on REQ\n");
		BIO_printf(bio_err," -modulus       RSA modulus\n");
		BIO_printf(bio_err," -nodes         don't encrypt the output key\n");
		BIO_printf(bio_err," -key file	use the private key contained in file\n");
		BIO_printf(bio_err," -keyform arg   key file format\n");
		BIO_printf(bio_err," -keyout arg    file to send the key to\n");
		BIO_printf(bio_err," -newkey rsa:bits generate a new RSA key of 'bits' in size\n");
		BIO_printf(bio_err," -newkey dsa:file generate a new DSA key, parameters taken from CA in 'file'\n");

		BIO_printf(bio_err," -[digest]      Digest to sign with (md5, sha1, md2, mdc2)\n");
		BIO_printf(bio_err," -config file   request template file.\n");
		BIO_printf(bio_err," -new           new request.\n");
		BIO_printf(bio_err," -x509          output a x509 structure instead of a cert. req.\n");
		BIO_printf(bio_err," -days          number of days a x509 generated by -x509 is valid for.\n");
		BIO_printf(bio_err," -asn1-kludge   Output the 'request' in a format that is wrong but some CA's\n");
		BIO_printf(bio_err,"                have been reported as requiring\n");
		BIO_printf(bio_err,"                [ It is now always turned on but can be turned off with -no-asn1-kludge ]\n");
		goto end;
		}

	ERR_load_crypto_strings();
	X509V3_add_standard_extensions();

#ifndef MONOLITH
	/* Lets load up our environment a little */
	p=getenv("OPENSSL_CONF");
	if (p == NULL)
		p=getenv("SSLEAY_CONF");
	if (p == NULL)
		{
		strcpy(config_name,X509_get_default_cert_area());
#ifndef VMS
		strcat(config_name,"/");
#endif
		strcat(config_name,OPENSSL_CONF);
		p=config_name;
		}
        default_config_file=p;
	config=CONF_load(config,p,NULL);
#endif

	if (template != NULL)
		{
		long errline;

		BIO_printf(bio_err,"Using configuration from %s\n",template);
		req_conf=CONF_load(NULL,template,&errline);
		if (req_conf == NULL)
			{
			BIO_printf(bio_err,"error on line %ld of %s\n",errline,template);
			goto end;
			}
		}
	else
		{
		req_conf=config;
		BIO_printf(bio_err,"Using configuration from %s\n",
			default_config_file);
		if (req_conf == NULL)
			{
			BIO_printf(bio_err,"Unable to load config info\n");
			}
		}

	if (req_conf != NULL)
		{
		p=CONF_get_string(req_conf,NULL,"oid_file");
		if (p != NULL)
			{
			BIO *oid_bio;

			oid_bio=BIO_new_file(p,"r");
			if (oid_bio == NULL) 
				{
				/*
				BIO_printf(bio_err,"problems opening %s for extra oid's\n",p);
				ERR_print_errors(bio_err);
				*/
				}
			else
				{
				OBJ_create_objects(oid_bio);
				BIO_free(oid_bio);
				}
			}
		}
		if(!add_oid_section(req_conf)) goto end;

	if ((md_alg == NULL) &&
		((p=CONF_get_string(req_conf,SECTION,"default_md")) != NULL))
		{
		if ((md_alg=EVP_get_digestbyname(p)) != NULL)
			digest=md_alg;
		}

	extensions = CONF_get_string(req_conf, SECTION, V3_EXTENSIONS);
	if(extensions) {
		/* Check syntax of file */
		X509V3_CTX ctx;
		X509V3_set_ctx_test(&ctx);
		X509V3_set_conf_lhash(&ctx, req_conf);
		if(!X509V3_EXT_add_conf(req_conf, &ctx, extensions, NULL)) {
			BIO_printf(bio_err,
			 "Error Loading extension section %s\n", extensions);
			goto end;
		}
	}

	in=BIO_new(BIO_s_file());
	out=BIO_new(BIO_s_file());
	if ((in == NULL) || (out == NULL))
		goto end;

	if (keyfile != NULL)
		{
		if (BIO_read_filename(in,keyfile) <= 0)
			{
			perror(keyfile);
			goto end;
			}

/*		if (keyform == FORMAT_ASN1)
			rsa=d2i_RSAPrivateKey_bio(in,NULL);
		else */
		if (keyform == FORMAT_PEM)
			pkey=PEM_read_bio_PrivateKey(in,NULL,NULL,NULL);
		else
			{
			BIO_printf(bio_err,"bad input format specified for X509 request\n");
			goto end;
			}

		if (pkey == NULL)
			{
			BIO_printf(bio_err,"unable to load Private key\n");
			goto end;
			}
		}

	if (newreq && (pkey == NULL))
		{
		char *randfile;
		char buffer[200];

		if ((randfile=CONF_get_string(req_conf,SECTION,"RANDFILE")) == NULL)
			randfile=RAND_file_name(buffer,200);
#ifdef WINDOWS
		BIO_printf(bio_err,"Loading 'screen' into random state -");
		BIO_flush(bio_err);
		RAND_screen();
		BIO_printf(bio_err," done\n");
#endif
		if ((randfile == NULL) || !RAND_load_file(randfile,1024L*1024L))
			{
			BIO_printf(bio_err,"unable to load 'random state'\n");
			BIO_printf(bio_err,"What this means is that the random number generator has not been seeded\n");
			BIO_printf(bio_err,"with much random data.\n");
			BIO_printf(bio_err,"Consider setting the RANDFILE environment variable to point at a file that\n");
			BIO_printf(bio_err,"'random' data can be kept in.\n");
			}
		if (newkey <= 0)
			{
			newkey=(int)CONF_get_number(req_conf,SECTION,BITS);
			if (newkey <= 0)
				newkey=DEFAULT_KEY_LENGTH;
			}

		if (newkey < MIN_KEY_LENGTH)
			{
			BIO_printf(bio_err,"private key length is too short,\n");
			BIO_printf(bio_err,"it needs to be at least %d bits, not %d\n",MIN_KEY_LENGTH,newkey);
			goto end;
			}
		BIO_printf(bio_err,"Generating a %d bit %s private key\n",
			newkey,(pkey_type == TYPE_RSA)?"RSA":"DSA");

		if ((pkey=EVP_PKEY_new()) == NULL) goto end;

#ifndef NO_RSA
		if (pkey_type == TYPE_RSA)
			{
			if (!EVP_PKEY_assign_RSA(pkey,
				RSA_generate_key(newkey,0x10001,
					req_cb,bio_err)))
				goto end;
			}
		else
#endif
#ifndef NO_DSA
			if (pkey_type == TYPE_DSA)
			{
			if (!DSA_generate_key(dsa_params)) goto end;
			if (!EVP_PKEY_assign_DSA(pkey,dsa_params)) goto end;
			dsa_params=NULL;
			}
#endif

		if ((randfile == NULL) || (RAND_write_file(randfile) == 0))
			BIO_printf(bio_err,"unable to write 'random state'\n");

		if (pkey == NULL) goto end;

		if (keyout == NULL)
			keyout=CONF_get_string(req_conf,SECTION,KEYFILE);

		if (keyout == NULL)
			{
			BIO_printf(bio_err,"writing new private key to stdout\n");
			BIO_set_fp(out,stdout,BIO_NOCLOSE);
			}
		else
			{
			BIO_printf(bio_err,"writing new private key to '%s'\n",keyout);
			if (BIO_write_filename(out,keyout) <= 0)
				{
				perror(keyout);
				goto end;
				}
			}

		p=CONF_get_string(req_conf,SECTION,"encrypt_rsa_key");
		if (p == NULL)
			p=CONF_get_string(req_conf,SECTION,"encrypt_key");
		if ((p != NULL) && (strcmp(p,"no") == 0))
			cipher=NULL;
		if (nodes) cipher=NULL;
		
		i=0;
loop:
		if (!PEM_write_bio_PrivateKey(out,pkey,cipher,
			NULL,0,NULL,NULL))
			{
			if ((ERR_GET_REASON(ERR_peek_error()) ==
				PEM_R_PROBLEMS_GETTING_PASSWORD) && (i < 3))
				{
				ERR_clear_error();
				i++;
				goto loop;
				}
			goto end;
			}
		BIO_printf(bio_err,"-----\n");
		}

	if (!newreq)
		{
		/* Since we are using a pre-existing certificate
		 * request, the kludge 'format' info should not be
		 * changed. */
		kludge= -1;
		if (infile == NULL)
			BIO_set_fp(in,stdin,BIO_NOCLOSE);
		else
			{
			if (BIO_read_filename(in,infile) <= 0)
				{
				perror(infile);
				goto end;
				}
			}

		if	(informat == FORMAT_ASN1)
			req=d2i_X509_REQ_bio(in,NULL);
		else if (informat == FORMAT_PEM)
			req=PEM_read_bio_X509_REQ(in,NULL,NULL,NULL);
		else
			{
			BIO_printf(bio_err,"bad input format specified for X509 request\n");
			goto end;
			}
		if (req == NULL)
			{
			BIO_printf(bio_err,"unable to load X509 request\n");
			goto end;
			}
		}

	if (newreq || x509)
		{
#ifndef NO_DSA
		if (pkey->type == EVP_PKEY_DSA)
			digest=EVP_dss1();
#endif

		if (pkey == NULL)
			{
			BIO_printf(bio_err,"you need to specify a private key\n");
			goto end;
			}
		if (req == NULL)
			{
			req=X509_REQ_new();
			if (req == NULL)
				{
				goto end;
				}

			i=make_REQ(req,pkey,!x509);
			if (kludge >= 0)
				req->req_info->req_kludge=kludge;
			if (!i)
				{
				BIO_printf(bio_err,"problems making Certificate Request\n");
				goto end;
				}
			}
		if (x509)
			{
			EVP_PKEY *tmppkey;
			X509V3_CTX ext_ctx;
			if ((x509ss=X509_new()) == NULL) goto end;

			/* Set version to V3 */
			if(!X509_set_version(x509ss, 2)) goto end;
			ASN1_INTEGER_set(X509_get_serialNumber(x509ss),0L);

			X509_set_issuer_name(x509ss,
				X509_REQ_get_subject_name(req));
			X509_gmtime_adj(X509_get_notBefore(x509ss),0);
			X509_gmtime_adj(X509_get_notAfter(x509ss),
				(long)60*60*24*days);
			X509_set_subject_name(x509ss,
				X509_REQ_get_subject_name(req));
			tmppkey = X509_REQ_get_pubkey(req);
			X509_set_pubkey(x509ss,tmppkey);
			EVP_PKEY_free(tmppkey);

			/* Set up V3 context struct */

			X509V3_set_ctx(&ext_ctx, x509ss, x509ss, NULL, NULL, 0);
			X509V3_set_conf_lhash(&ext_ctx, req_conf);

			/* Add extensions */
			if(extensions && !X509V3_EXT_add_conf(req_conf, 
				 	&ext_ctx, extensions, x509ss))
			    {
			    BIO_printf(bio_err,
				       "Error Loading extension section %s\n",
				       extensions);
			    goto end;
			    }

			if (!(i=X509_sign(x509ss,pkey,digest)))
				goto end;
			}
		else
			{
			if (!(i=X509_REQ_sign(req,pkey,digest)))
				goto end;
			}
		}

	if (verify && !x509)
		{
		int tmp=0;

		if (pkey == NULL)
			{
			pkey=X509_REQ_get_pubkey(req);
			tmp=1;
			if (pkey == NULL) goto end;
			}

		i=X509_REQ_verify(req,pkey);
		if (tmp) {
			EVP_PKEY_free(pkey);
			pkey=NULL;
		}

		if (i < 0)
			{
			goto end;
			}
		else if (i == 0)
			{
			BIO_printf(bio_err,"verify failure\n");
			}
		else /* if (i > 0) */
			BIO_printf(bio_err,"verify OK\n");
		}

	if (noout && !text && !modulus)
		{
		ex=0;
		goto end;
		}

	if (outfile == NULL)
		BIO_set_fp(out,stdout,BIO_NOCLOSE);
	else
		{
		if ((keyout != NULL) && (strcmp(outfile,keyout) == 0))
			i=(int)BIO_append_filename(out,outfile);
		else
			i=(int)BIO_write_filename(out,outfile);
		if (!i)
			{
			perror(outfile);
			goto end;
			}
		}

	if (text)
		{
		if (x509)
			X509_print(out,x509ss);
		else	
			X509_REQ_print(out,req);
		}

	if (modulus)
		{
		EVP_PKEY *pubkey;

		if (x509)
			pubkey=X509_get_pubkey(x509ss);
		else
			pubkey=X509_REQ_get_pubkey(req);
		if (pubkey == NULL)
			{
			fprintf(stdout,"Modulus=unavailable\n");
			goto end; 
			}
		fprintf(stdout,"Modulus=");
#ifndef NO_RSA
		if (pubkey->type == EVP_PKEY_RSA)
			BN_print(out,pubkey->pkey.rsa->n);
		else
#endif
			fprintf(stdout,"Wrong Algorithm type");
		fprintf(stdout,"\n");
		}

	if (!noout && !x509)
		{
		if 	(outformat == FORMAT_ASN1)
			i=i2d_X509_REQ_bio(out,req);
		else if (outformat == FORMAT_PEM)
			i=PEM_write_bio_X509_REQ(out,req);
		else	{
			BIO_printf(bio_err,"bad output format specified for outfile\n");
			goto end;
			}
		if (!i)
			{
			BIO_printf(bio_err,"unable to write X509 request\n");
			goto end;
			}
		}
	if (!noout && x509 && (x509ss != NULL))
		{
		if 	(outformat == FORMAT_ASN1)
			i=i2d_X509_bio(out,x509ss);
		else if (outformat == FORMAT_PEM)
			i=PEM_write_bio_X509(out,x509ss);
		else	{
			BIO_printf(bio_err,"bad output format specified for outfile\n");
			goto end;
			}
		if (!i)
			{
			BIO_printf(bio_err,"unable to write X509 certificate\n");
			goto end;
			}
		}
	ex=0;
end:
	if (ex)
		{
		ERR_print_errors(bio_err);
		}
	if ((req_conf != NULL) && (req_conf != config)) CONF_free(req_conf);
	BIO_free(in);
	BIO_free(out);
	EVP_PKEY_free(pkey);
	X509_REQ_free(req);
	X509_free(x509ss);
	X509V3_EXT_cleanup();
	OBJ_cleanup();
#ifndef NO_DSA
	if (dsa_params != NULL) DSA_free(dsa_params);
#endif
	EXIT(ex);
	}

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, int attribs)
	{
	int ret=0,i;
	char *p,*q;
	X509_REQ_INFO *ri;
	char buf[100];
	int nid,min,max;
	char *type,*def,*tmp,*value,*tmp_attr;
	STACK_OF(CONF_VALUE) *sk, *attr=NULL;
	CONF_VALUE *v;
	
	tmp=CONF_get_string(req_conf,SECTION,DISTINGUISHED_NAME);
	if (tmp == NULL)
		{
		BIO_printf(bio_err,"unable to find '%s' in config\n",
			DISTINGUISHED_NAME);
		goto err;
		}
	sk=CONF_get_section(req_conf,tmp);
	if (sk == NULL)
		{
		BIO_printf(bio_err,"unable to get '%s' section\n",tmp);
		goto err;
		}

	tmp_attr=CONF_get_string(req_conf,SECTION,ATTRIBUTES);
	if (tmp_attr == NULL)
		attr=NULL;
	else
		{
		attr=CONF_get_section(req_conf,tmp_attr);
		if (attr == NULL)
			{
			BIO_printf(bio_err,"unable to get '%s' section\n",tmp_attr);
			goto err;
			}
		}

	ri=req->req_info;

	BIO_printf(bio_err,"You are about to be asked to enter information that will be incorporated\n");
	BIO_printf(bio_err,"into your certificate request.\n");
	BIO_printf(bio_err,"What you are about to enter is what is called a Distinguished Name or a DN.\n");
	BIO_printf(bio_err,"There are quite a few fields but you can leave some blank\n");
	BIO_printf(bio_err,"For some fields there will be a default value,\n");
	BIO_printf(bio_err,"If you enter '.', the field will be left blank.\n");
	BIO_printf(bio_err,"-----\n");

	/* setup version number */
	if (!ASN1_INTEGER_set(ri->version,0L)) goto err; /* version 1 */

	if (sk_CONF_VALUE_num(sk))
		{
		i= -1;
start:		for (;;)
			{
			i++;
			if (sk_CONF_VALUE_num(sk) <= i) break;

			v=sk_CONF_VALUE_value(sk,i);
			p=q=NULL;
			type=v->name;
			if(!check_end(type,"_min") || !check_end(type,"_max") ||
				!check_end(type,"_default") ||
					 !check_end(type,"_value")) continue;
			/* Skip past any leading X. X: X, etc to allow for
			 * multiple instances 
			 */
			for(p = v->name; *p ; p++) 
				if ((*p == ':') || (*p == ',') ||
							 (*p == '.')) {
					p++;
					if(*p) type = p;
					break;
				}
			/* If OBJ not recognised ignore it */
			if ((nid=OBJ_txt2nid(type)) == NID_undef) goto start;
			sprintf(buf,"%s_default",v->name);
			if ((def=CONF_get_string(req_conf,tmp,buf)) == NULL)
				def="";
				
			sprintf(buf,"%s_value",v->name);
			if ((value=CONF_get_string(req_conf,tmp,buf)) == NULL)
				value=NULL;

			sprintf(buf,"%s_min",v->name);
			min=(int)CONF_get_number(req_conf,tmp,buf);

			sprintf(buf,"%s_max",v->name);
			max=(int)CONF_get_number(req_conf,tmp,buf);

			if (!add_DN_object(ri->subject,v->value,def,value,nid,
				min,max))
				goto err;
			}
		if (sk_X509_NAME_ENTRY_num(ri->subject->entries) == 0)
			{
			BIO_printf(bio_err,"error, no objects specified in config file\n");
			goto err;
			}

		if (attribs)
			{
			if ((attr != NULL) && (sk_CONF_VALUE_num(attr) > 0))
				{
				BIO_printf(bio_err,"\nPlease enter the following 'extra' attributes\n");
				BIO_printf(bio_err,"to be sent with your certificate request\n");
				}

			i= -1;
start2:			for (;;)
				{
				i++;
				if ((attr == NULL) ||
					    (sk_CONF_VALUE_num(attr) <= i))
					break;

				v=sk_CONF_VALUE_value(attr,i);
				type=v->name;
				if ((nid=OBJ_txt2nid(type)) == NID_undef)
					goto start2;

				sprintf(buf,"%s_default",type);
				if ((def=CONF_get_string(req_conf,tmp_attr,buf))
					== NULL)
					def="";
				
				sprintf(buf,"%s_value",type);
				if ((value=CONF_get_string(req_conf,tmp_attr,buf))
					== NULL)
					value=NULL;

				sprintf(buf,"%s_min",type);
				min=(int)CONF_get_number(req_conf,tmp_attr,buf);

				sprintf(buf,"%s_max",type);
				max=(int)CONF_get_number(req_conf,tmp_attr,buf);

				if (!add_attribute_object(ri->attributes,
					v->value,def,value,nid,min,max))
					goto err;
				}
			}
		}
	else
		{
		BIO_printf(bio_err,"No template, please set one up.\n");
		goto err;
		}

	X509_REQ_set_pubkey(req,pkey);

	ret=1;
err:
	return(ret);
	}

static int add_DN_object(X509_NAME *n, char *text, char *def, char *value,
	     int nid, int min, int max)
	{
	int i,j,ret=0;
	X509_NAME_ENTRY *ne=NULL;
	MS_STATIC char buf[1024];

	BIO_printf(bio_err,"%s [%s]:",text,def);
	(void)BIO_flush(bio_err);
	if (value != NULL)
		{
		strcpy(buf,value);
		strcat(buf,"\n");
		BIO_printf(bio_err,"%s\n",value);
		}
	else
		{
		buf[0]='\0';
		fgets(buf,1024,stdin);
		}

	if (buf[0] == '\0') return(0);
	else if (buf[0] == '\n')
		{
		if ((def == NULL) || (def[0] == '\0'))
			return(1);
		strcpy(buf,def);
		strcat(buf,"\n");
		}
	else if ((buf[0] == '.') && (buf[1] == '\n')) return(1);

	i=strlen(buf);
	if (buf[i-1] != '\n')
		{
		BIO_printf(bio_err,"weird input :-(\n");
		return(0);
		}
	buf[--i]='\0';

	j=ASN1_PRINTABLE_type((unsigned char *)buf,-1);
	if (req_fix_data(nid,&j,i,min,max) == 0)
		goto err;
#ifdef CHARSET_EBCDIC
	ebcdic2ascii(buf, buf, i);
#endif
	if ((ne=X509_NAME_ENTRY_create_by_NID(NULL,nid,j,(unsigned char *)buf,
		strlen(buf)))
		== NULL) goto err;
	if (!X509_NAME_add_entry(n,ne,X509_NAME_entry_count(n),0))
		goto err;

	ret=1;
err:
	if (ne != NULL) X509_NAME_ENTRY_free(ne);
	return(ret);
	}

static int add_attribute_object(STACK_OF(X509_ATTRIBUTE) *n, char *text,
				char *def, char *value, int nid, int min,
				int max)
	{
	int i,z;
	X509_ATTRIBUTE *xa=NULL;
	static char buf[1024];
	ASN1_BIT_STRING *bs=NULL;
	ASN1_TYPE *at=NULL;

start:
	BIO_printf(bio_err,"%s [%s]:",text,def);
	(void)BIO_flush(bio_err);
	if (value != NULL)
		{
		strcpy(buf,value);
		strcat(buf,"\n");
		BIO_printf(bio_err,"%s\n",value);
		}
	else
		{
		buf[0]='\0';
		fgets(buf,1024,stdin);
		}

	if (buf[0] == '\0') return(0);
	else if (buf[0] == '\n')
		{
		if ((def == NULL) || (def[0] == '\0'))
			return(1);
		strcpy(buf,def);
		strcat(buf,"\n");
		}
	else if ((buf[0] == '.') && (buf[1] == '\n')) return(1);

	i=strlen(buf);
	if (buf[i-1] != '\n')
		{
		BIO_printf(bio_err,"weird input :-(\n");
		return(0);
		}
	buf[--i]='\0';

	/* add object plus value */
	if ((xa=X509_ATTRIBUTE_new()) == NULL)
		goto err;
	if ((xa->value.set=sk_ASN1_TYPE_new_null()) == NULL)
		goto err;
	xa->set=1;

	if (xa->object != NULL) ASN1_OBJECT_free(xa->object);
	xa->object=OBJ_nid2obj(nid);

	if ((bs=ASN1_BIT_STRING_new()) == NULL) goto err;

	bs->type=ASN1_PRINTABLE_type((unsigned char *)buf,-1);

	z=req_fix_data(nid,&bs->type,i,min,max);
	if (z == 0)
		{
		if (value == NULL)
			goto start;
		else	goto err;
		}

	if (!ASN1_STRING_set(bs,(unsigned char *)buf,i+1))
		{ BIO_printf(bio_err,"Malloc failure\n"); goto err; }

	if ((at=ASN1_TYPE_new()) == NULL)
		{ BIO_printf(bio_err,"Malloc failure\n"); goto err; }

	ASN1_TYPE_set(at,bs->type,(char *)bs);
	sk_ASN1_TYPE_push(xa->value.set,at);
	bs=NULL;
	at=NULL;
	/* only one item per attribute */

	if (!sk_X509_ATTRIBUTE_push(n,xa)) goto err;
	return(1);
err:
	if (xa != NULL) X509_ATTRIBUTE_free(xa);
	if (at != NULL) ASN1_TYPE_free(at);
	if (bs != NULL) ASN1_BIT_STRING_free(bs);
	return(0);
	}

static void MS_CALLBACK req_cb(int p, int n, void *arg)
	{
	char c='*';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	BIO_write((BIO *)arg,&c,1);
	(void)BIO_flush((BIO *)arg);
#ifdef LINT
	p=n;
#endif
	}

static int req_fix_data(int nid, int *type, int len, int min, int max)
	{
	if (nid == NID_pkcs9_emailAddress)
		*type=V_ASN1_IA5STRING;
	if ((nid == NID_commonName) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_challengePassword) &&
		(*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;

	if ((nid == NID_pkcs9_unstructuredName) &&
		(*type == V_ASN1_T61STRING))
		{
		BIO_printf(bio_err,"invalid characters in string, please re-enter the string\n");
		return(0);
		}
	if (nid == NID_pkcs9_unstructuredName)
		*type=V_ASN1_IA5STRING;

	if (len < min)
		{
		BIO_printf(bio_err,"string is too short, it needs to be at least %d bytes long\n",min);
		return(0);
		}
	if ((max != 0) && (len > max))
		{
		BIO_printf(bio_err,"string is too long, it needs to be less than  %d bytes long\n",max);
		return(0);
		}
	return(1);
	}

/* Check if the end of a string matches 'end' */
static int check_end(char *str, char *end)
{
	int elen, slen;	
	char *tmp;
	elen = strlen(end);
	slen = strlen(str);
	if(elen > slen) return 1;
	tmp = str + slen - elen;
	return strcmp(tmp, end);
}

static int add_oid_section(LHASH *conf)
{	
	char *p;
	STACK_OF(CONF_VALUE) *sktmp;
	CONF_VALUE *cnf;
	int i;
	if(!(p=CONF_get_string(conf,NULL,"oid_section"))) return 1;
	if(!(sktmp = CONF_get_section(conf, p))) {
		BIO_printf(bio_err, "problem loading oid section %s\n", p);
		return 0;
	}
	for(i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
		cnf = sk_CONF_VALUE_value(sktmp, i);
		if(OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
			BIO_printf(bio_err, "problem creating object %s=%s\n",
							 cnf->name, cnf->value);
			return 0;
		}
	}
	return 1;
}
