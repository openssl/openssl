/* apps/ca.c */
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

/* The PPKI stuff has been donated by Jeff Barber <jeffb@issl.atl.hp.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "apps.h"
#include "bio.h"
#include "err.h"
#include "bn.h"
#include "txt_db.h"
#include "evp.h"
#include "x509.h"
#include "objects.h"
#include "pem.h"
#include "conf.h"

#ifndef W_OK
#include <sys/file.h>
#endif

#undef PROG
#define PROG ca_main

#define BASE_SECTION	"ca"
#define CONFIG_FILE "lib/ssleay.cnf"

#define ENV_DEFAULT_CA		"default_ca"

#define ENV_DIR			"dir"
#define ENV_CERTS		"certs"
#define ENV_CRL_DIR		"crl_dir"
#define ENV_CA_DB		"CA_DB"
#define ENV_NEW_CERTS_DIR	"new_certs_dir"
#define ENV_CERTIFICATE 	"certificate"
#define ENV_SERIAL		"serial"
#define ENV_CRL			"crl"
#define ENV_PRIVATE_KEY		"private_key"
#define ENV_RANDFILE		"RANDFILE"
#define ENV_DEFAULT_DAYS 	"default_days"
#define ENV_DEFAULT_STARTDATE 	"default_startdate"
#define ENV_DEFAULT_CRL_DAYS 	"default_crl_days"
#define ENV_DEFAULT_CRL_HOURS 	"default_crl_hours"
#define ENV_DEFAULT_MD		"default_md"
#define ENV_PRESERVE		"preserve"
#define ENV_POLICY      	"policy"
#define ENV_EXTENSIONS      	"x509_extensions"
#define ENV_MSIE_HACK		"msie_hack"

#define ENV_DATABASE		"database"

#define DB_type         0
#define DB_exp_date     1
#define DB_rev_date     2
#define DB_serial       3       /* index - unique */
#define DB_file         4       
#define DB_name         5       /* index - unique for active */
#define DB_NUMBER       6

#define DB_TYPE_REV	'R'
#define DB_TYPE_EXP	'E'
#define DB_TYPE_VAL	'V'

static char *ca_usage[]={
"usage: ca args\n",
"\n",
" -verbose        - Talk alot while doing things\n",
" -config file    - A config file\n",
" -name arg       - The particular CA definition to use\n",
" -gencrl         - Generate a new CRL\n",
" -crldays days   - Days is when the next CRL is due\n",
" -crlhours hours - Hours is when the next CRL is due\n",
" -days arg       - number of days to certify the certificate for\n",
" -md arg         - md to use, one of md2, md5, sha or sha1\n",
" -policy arg     - The CA 'policy' to support\n",
" -keyfile arg    - PEM private key file\n",
" -key arg        - key to decode the private key if it is encrypted\n",
" -cert           - The CA certificate\n",
" -in file        - The input PEM encoded certificate request(s)\n",
" -out file       - Where to put the output file(s)\n",
" -outdir dir     - Where to put output certificates\n",
" -infiles ....   - The last argument, requests to process\n",
" -spkac file     - File contains DN and signed public key and challenge\n",
" -ss_cert file   - File contains a self signed cert to sign\n",
" -preserveDN     - Don't re-order the DN\n",
" -batch	  - Don't ask questions\n",
" -msie_hack	  - msie modifications to handle all thos universal strings\n",
NULL
};

#ifdef EFENCE
extern int EF_PROTECT_FREE;
extern int EF_PROTECT_BELOW;
extern int EF_ALIGNMENT;
#endif

#ifndef NOPROTO
static STACK *load_extensions(char *section);
static void lookup_fail(char *name,char *tag);
static int MS_CALLBACK key_callback(char *buf,int len,int verify);
static unsigned long index_serial_hash(char **a);
static int index_serial_cmp(char **a, char **b);
static unsigned long index_name_hash(char **a);
static int index_name_qual(char **a);
static int index_name_cmp(char **a,char **b);
static BIGNUM *load_serial(char *serialfile);
static int save_serial(char *serialfile, BIGNUM *serial);
static int certify(X509 **xret, char *infile,EVP_PKEY *pkey,X509 *x509,
	EVP_MD *dgst,STACK *policy,TXT_DB *db,BIGNUM *serial,char *startdate,
	int days, int batch, STACK *extensions,int verbose);
static int certify_cert(X509 **xret, char *infile,EVP_PKEY *pkey,X509 *x509,
	EVP_MD *dgst,STACK *policy,TXT_DB *db,BIGNUM *serial,char *startdate,
	int days,int batch,STACK *extensions,int verbose);
static int certify_spkac(X509 **xret, char *infile,EVP_PKEY *pkey,X509 *x509,
	EVP_MD *dgst,STACK *policy,TXT_DB *db,BIGNUM *serial,char *startdate,
	int days,STACK *extensions,int verbose);
static int fix_data(int nid, int *type);
static void write_new_certificate(BIO *bp, X509 *x, int output_der);
static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509, EVP_MD *dgst,
	STACK *policy, TXT_DB *db, BIGNUM *serial, char *startdate,
	int days, int batch, int verbose, X509_REQ *req, STACK *extensions);
static int check_time_format(char *str);
#else
static STACK *load_extensions();
static void lookup_fail();
static int MS_CALLBACK key_callback();
static unsigned long index_serial_hash();
static int index_serial_cmp();
static unsigned long index_name_hash();
static int index_name_qual();
static int index_name_cmp();
static int fix_data();
static BIGNUM *load_serial();
static int save_serial();
static int certify();
static int certify_cert();
static int certify_spkac();
static void write_new_certificate();
static int do_body();
static int check_time_format();
#endif

static LHASH *conf;
static char *key=NULL;
static char *section=NULL;

static int preserve=0;
static int msie_hack=0;

int MAIN(argc, argv)
int argc;
char **argv;
	{
	int total=0;
	int total_done=0;
	int badops=0;
	int ret=1;
	int req=0;
	int verbose=0;
	int gencrl=0;
	long crldays=0;
	long crlhours=0;
	long errorline= -1;
	char *configfile=NULL;
	char *md=NULL;
	char *policy=NULL;
	char *keyfile=NULL;
	char *certfile=NULL;
	char *infile=NULL;
	char *spkac_file=NULL;
	char *ss_cert_file=NULL;
	EVP_PKEY *pkey=NULL;
	int output_der = 0;
	char *outfile=NULL;
	char *outdir=NULL;
	char *serialfile=NULL;
	char *extensions=NULL;
	BIGNUM *serial=NULL;
	char *startdate=NULL;
	int days=0;
	int batch=0;
	X509 *x509=NULL;
	X509 *x=NULL;
	BIO *in=NULL,*out=NULL,*Sout=NULL,*Cout=NULL;
	char *dbfile=NULL;
	TXT_DB *db=NULL;
	X509_CRL *crl=NULL;
	X509_CRL_INFO *ci=NULL;
	X509_REVOKED *r=NULL;
	char **pp,*p,*f;
	int i,j;
	long l;
	EVP_MD *dgst=NULL;
	STACK *attribs=NULL;
	STACK *extensions_sk=NULL;
	STACK *cert_sk=NULL;
	BIO *hex=NULL;
#undef BSIZE
#define BSIZE 256
	MS_STATIC char buf[3][BSIZE];

#ifdef EFENCE
EF_PROTECT_FREE=1;
EF_PROTECT_BELOW=1;
EF_ALIGNMENT=0;
#endif

	apps_startup();

	X509v3_add_netscape_extensions();

	preserve=0;
	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	argc--;
	argv++;
	while (argc >= 1)
		{
		if	(strcmp(*argv,"-verbose") == 0)
			verbose=1;
		else if	(strcmp(*argv,"-config") == 0)
			{
			if (--argc < 1) goto bad;
			configfile= *(++argv);
			}
		else if (strcmp(*argv,"-name") == 0)
			{
			if (--argc < 1) goto bad;
			section= *(++argv);
			}
		else if (strcmp(*argv,"-startdate") == 0)
			{
			if (--argc < 1) goto bad;
			startdate= *(++argv);
			}
		else if (strcmp(*argv,"-days") == 0)
			{
			if (--argc < 1) goto bad;
			days=atoi(*(++argv));
			}
		else if (strcmp(*argv,"-md") == 0)
			{
			if (--argc < 1) goto bad;
			md= *(++argv);
			}
		else if (strcmp(*argv,"-policy") == 0)
			{
			if (--argc < 1) goto bad;
			policy= *(++argv);
			}
		else if (strcmp(*argv,"-keyfile") == 0)
			{
			if (--argc < 1) goto bad;
			keyfile= *(++argv);
			}
		else if (strcmp(*argv,"-key") == 0)
			{
			if (--argc < 1) goto bad;
			key= *(++argv);
			}
		else if (strcmp(*argv,"-cert") == 0)
			{
			if (--argc < 1) goto bad;
			certfile= *(++argv);
			}
		else if (strcmp(*argv,"-in") == 0)
			{
			if (--argc < 1) goto bad;
			infile= *(++argv);
			req=1;
			}
		else if (strcmp(*argv,"-out") == 0)
			{
			if (--argc < 1) goto bad;
			outfile= *(++argv);
			}
		else if (strcmp(*argv,"-outdir") == 0)
			{
			if (--argc < 1) goto bad;
			outdir= *(++argv);
			}
		else if (strcmp(*argv,"-batch") == 0)
			batch=1;
		else if (strcmp(*argv,"-preserveDN") == 0)
			preserve=1;
		else if (strcmp(*argv,"-gencrl") == 0)
			gencrl=1;
		else if (strcmp(*argv,"-msie_hack") == 0)
			msie_hack=1;
		else if (strcmp(*argv,"-crldays") == 0)
			{
			if (--argc < 1) goto bad;
			crldays= atol(*(++argv));
			}
		else if (strcmp(*argv,"-crlhours") == 0)
			{
			if (--argc < 1) goto bad;
			crlhours= atol(*(++argv));
			}
		else if (strcmp(*argv,"-infiles") == 0)
			{
			argc--;
			argv++;
			req=1;
			break;
			}
		else if (strcmp(*argv, "-ss_cert") == 0)
			{
			if (--argc < 1) goto bad;
			ss_cert_file = *(++argv);
			req=1;
			}
		else if (strcmp(*argv, "-spkac") == 0)
			{
			if (--argc < 1) goto bad;
			spkac_file = *(++argv);
			req=1;
			}
		else
			{
bad:
			BIO_printf(bio_err,"unknown option %s\n",*argv);
			badops=1;
			break;
			}
		argc--;
		argv++;
		}

	if (badops)
		{
		for (pp=ca_usage; (*pp != NULL); pp++)
			BIO_printf(bio_err,*pp);
		goto err;
		}

	ERR_load_crypto_strings();

	/*****************************************************************/
	if (configfile == NULL)
		{
		/* We will just use 'buf[0]' as a temporary buffer.  */
		strncpy(buf[0],X509_get_default_cert_area(),
			sizeof(buf[0])-2-sizeof(CONFIG_FILE));
		strcat(buf[0],"/");
		strcat(buf[0],CONFIG_FILE);
		configfile=buf[0];
		}

	BIO_printf(bio_err,"Using configuration from %s\n",configfile);
	if ((conf=CONF_load(NULL,configfile,&errorline)) == NULL)
		{
		if (errorline <= 0)
			BIO_printf(bio_err,"error loading the config file '%s'\n",
				configfile);
		else
			BIO_printf(bio_err,"error on line %ld of config file '%s'\n"
				,errorline,configfile);
		goto err;
		}

	/* Lets get the config section we are using */
	if (section == NULL)
		{
		section=CONF_get_string(conf,BASE_SECTION,ENV_DEFAULT_CA);
		if (section == NULL)
			{
			lookup_fail(BASE_SECTION,ENV_DEFAULT_CA);
			goto err;
			}
		}

	in=BIO_new(BIO_s_file());
	out=BIO_new(BIO_s_file());
	Sout=BIO_new(BIO_s_file());
	Cout=BIO_new(BIO_s_file());
	if ((in == NULL) || (out == NULL) || (Sout == NULL) || (Cout == NULL))
		{
		ERR_print_errors(bio_err);
		goto err;
		}

	/*****************************************************************/
	/* we definitly need an public key, so lets get it */

	if ((keyfile == NULL) && ((keyfile=CONF_get_string(conf,
		section,ENV_PRIVATE_KEY)) == NULL))
		{
		lookup_fail(section,ENV_PRIVATE_KEY);
		goto err;
		}
	if (BIO_read_filename(in,keyfile) <= 0)
		{
		perror(keyfile);
		BIO_printf(bio_err,"trying to load CA private key\n");
		goto err;
		}
	if (key == NULL)
		pkey=PEM_read_bio_PrivateKey(in,NULL,NULL);
	else
		{
		pkey=PEM_read_bio_PrivateKey(in,NULL,key_callback);
		memset(key,0,strlen(key));
		}
	if (pkey == NULL)
		{
		BIO_printf(bio_err,"unable to load CA private key\n");
		goto err;
		}

	/*****************************************************************/
	/* we need a certificate */
	if ((certfile == NULL) && ((certfile=CONF_get_string(conf,
		section,ENV_CERTIFICATE)) == NULL))
		{
		lookup_fail(section,ENV_CERTIFICATE);
		goto err;
		}
        if (BIO_read_filename(in,certfile) <= 0)
		{
		perror(certfile);
		BIO_printf(bio_err,"trying to load CA certificate\n");
		goto err;
		}
	x509=PEM_read_bio_X509(in,NULL,NULL);
	if (x509 == NULL)
		{
		BIO_printf(bio_err,"unable to load CA certificate\n");
		goto err;
		}

	f=CONF_get_string(conf,BASE_SECTION,ENV_PRESERVE);
	if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
		preserve=1;
	f=CONF_get_string(conf,BASE_SECTION,ENV_MSIE_HACK);
	if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
		msie_hack=1;

	/*****************************************************************/
	/* lookup where to write new certificates */
	if ((outdir == NULL) && (req))
		{
		struct stat sb;

		if ((outdir=CONF_get_string(conf,section,ENV_NEW_CERTS_DIR))
			== NULL)
			{
			BIO_printf(bio_err,"there needs to be defined a directory for new certificate to be placed in\n");
			goto err;
			}
		if (access(outdir,R_OK|W_OK|X_OK) != 0)
			{
			BIO_printf(bio_err,"I am unable to acces the %s directory\n",outdir);
			perror(outdir);
			goto err;
			}

		if (stat(outdir,&sb) != 0)
			{
			BIO_printf(bio_err,"unable to stat(%s)\n",outdir);
			perror(outdir);
			goto err;
			}
		if (!(sb.st_mode & S_IFDIR))
			{
			BIO_printf(bio_err,"%s need to be a directory\n",outdir);
			perror(outdir);
			goto err;
			}
		}

	/*****************************************************************/
	/* we need to load the database file */
	if ((dbfile=CONF_get_string(conf,section,ENV_DATABASE)) == NULL)
		{
		lookup_fail(section,ENV_DATABASE);
		goto err;
		}
        if (BIO_read_filename(in,dbfile) <= 0)
		{
		perror(dbfile);
		BIO_printf(bio_err,"unable to open '%s'\n",dbfile);
		goto err;
		}
	db=TXT_DB_read(in,DB_NUMBER);
	if (db == NULL) goto err;

	/* Lets check some fields */
	for (i=0; i<sk_num(db->data); i++)
		{
		pp=(char **)sk_value(db->data,i);
		if ((pp[DB_type][0] != DB_TYPE_REV) &&
			(pp[DB_rev_date][0] != '\0'))
			{
			BIO_printf(bio_err,"entry %d: not, revoked yet has a revokation date\n",i+1);
			goto err;
			}
		if ((pp[DB_type][0] == DB_TYPE_REV) &&
			!check_time_format(pp[DB_rev_date]))
			{
			BIO_printf(bio_err,"entry %d: invalid revokation date\n",
				i+1);
			goto err;
			}
		if (!check_time_format(pp[DB_exp_date]))
			{
			BIO_printf(bio_err,"entry %d: invalid expiry date\n",i+1);
			goto err;
			}
		p=pp[DB_serial];
		j=strlen(p);
		if ((j&1) || (j < 2))
			{
			BIO_printf(bio_err,"entry %d: bad serial number length (%d)\n",i+1,j);
			goto err;
			}
		while (*p)
			{
			if (!(	((*p >= '0') && (*p <= '9')) ||
				((*p >= 'A') && (*p <= 'F')) ||
				((*p >= 'a') && (*p <= 'f')))  )
				{
				BIO_printf(bio_err,"entry %d: bad serial number characters, char pos %ld, char is '%c'\n",i+1,(long)(p-pp[DB_serial]),*p);
				goto err;
				}
			p++;
			}
		}
	if (verbose)
		{
		BIO_set_fp(out,stdout,BIO_NOCLOSE|BIO_FP_TEXT); /* cannot fail */
		TXT_DB_write(out,db);
		BIO_printf(bio_err,"%d entries loaded from the database\n",
			db->data->num);
		BIO_printf(bio_err,"generating indexs\n");
		}
	
	if (!TXT_DB_create_index(db,DB_serial,NULL,index_serial_hash,
		index_serial_cmp))
		{
		BIO_printf(bio_err,"error creating serial number index:(%ld,%ld,%ld)\n",db->error,db->arg1,db->arg2);
		goto err;
		}

	if (!TXT_DB_create_index(db,DB_name,index_name_qual,index_name_hash,
		index_name_cmp))
		{
		BIO_printf(bio_err,"error creating name index:(%ld,%ld,%ld)\n",
			db->error,db->arg1,db->arg2);
		goto err;
		}

	/*****************************************************************/
	if (req || gencrl)
		{
		if (outfile != NULL)
			{

			if (BIO_write_filename(Sout,outfile) <= 0)
				{
				perror(outfile);
				goto err;
				}
			}
		else
			BIO_set_fp(Sout,stdout,BIO_NOCLOSE|BIO_FP_TEXT);
		}

	if (req)
		{
		if ((md == NULL) && ((md=CONF_get_string(conf,
			section,ENV_DEFAULT_MD)) == NULL))
			{
			lookup_fail(section,ENV_DEFAULT_MD);
			goto err;
			}
		if ((dgst=EVP_get_digestbyname(md)) == NULL)
			{
			BIO_printf(bio_err,"%s is an unsupported message digest type\n",md);
			goto err;
			}
		if (verbose)
			BIO_printf(bio_err,"message digest is %s\n",
				OBJ_nid2ln(dgst->type));
		if ((policy == NULL) && ((policy=CONF_get_string(conf,
			section,ENV_POLICY)) == NULL))
			{
			lookup_fail(section,ENV_POLICY);
			goto err;
			}
		if (verbose)
			BIO_printf(bio_err,"policy is %s\n",policy);

		if ((serialfile=CONF_get_string(conf,section,ENV_SERIAL))
			== NULL)
			{
			lookup_fail(section,ENV_SERIAL);
			goto err;
			}

		if ((extensions=CONF_get_string(conf,section,ENV_EXTENSIONS))
			!= NULL)
			{
			if ((extensions_sk=load_extensions(extensions)) == NULL)
				goto err;
			}

		if (startdate == NULL)
			{
			startdate=(char *)CONF_get_string(conf,section,
				ENV_DEFAULT_STARTDATE);
			if (startdate == NULL)
				startdate="today";
			else
				{
				if (!ASN1_UTCTIME_set_string(NULL,startdate))
					{
					BIO_printf(bio_err,"start date is invalid, it should be YYMMDDHHMMSS\n");
					goto err;
					}
				}
			}

		if (days == 0)
			{
			days=(int)CONF_get_number(conf,section,
				ENV_DEFAULT_DAYS);
			}
		if (days == 0)
			{
			BIO_printf(bio_err,"cannot lookup how many days to certify for\n");
			goto err;
			}

		if ((serial=load_serial(serialfile)) == NULL)
			{
			BIO_printf(bio_err,"error while loading serial number\n");
			goto err;
			}
		if (verbose)
			{
			if ((f=BN_bn2ascii(serial)) == NULL) goto err;
			BIO_printf(bio_err,"next serial number is %s\n",f);
			Free(f);
			}

		if ((attribs=CONF_get_section(conf,policy)) == NULL)
			{
			BIO_printf(bio_err,"unable to find 'section' for %s\n",policy);
			goto err;
			}

		if ((cert_sk=sk_new_null()) == NULL)
			{
			BIO_printf(bio_err,"Malloc failure\n");
			goto err;
			}
		if (spkac_file != NULL)
			{
			total++;
			j=certify_spkac(&x,spkac_file,pkey,x509,dgst,attribs,db,
				serial,startdate,days,extensions_sk,verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_push(cert_sk,(char *)x))
					{
					BIO_printf(bio_err,"Malloc failure\n");
					goto err;
					}
				if (outfile)
					{
					output_der = 1;
					batch = 1;
					}
				}
			}
		if (ss_cert_file != NULL)
			{
			total++;
			j=certify_cert(&x,ss_cert_file,pkey,x509,dgst,attribs,
				db,serial,startdate,days,batch,
				extensions_sk,verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_push(cert_sk,(char *)x))
					{
					BIO_printf(bio_err,"Malloc failure\n");
					goto err;
					}
				}
			}
		if (infile != NULL)
			{
			total++;
			j=certify(&x,infile,pkey,x509,dgst,attribs,db,
				serial,startdate,days,batch,
				extensions_sk,verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_push(cert_sk,(char *)x))
					{
					BIO_printf(bio_err,"Malloc failure\n");
					goto err;
					}
				}
			}
		for (i=0; i<argc; i++)
			{
			total++;
			j=certify(&x,argv[i],pkey,x509,dgst,attribs,db,
				serial,startdate,days,batch,
				extensions_sk,verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_push(cert_sk,(char *)x))
					{
					BIO_printf(bio_err,"Malloc failure\n");
					goto err;
					}
				}
			}	
		/* we have a stack of newly certified certificates
		 * and a data base and serial number that need
		 * updating */

		if (sk_num(cert_sk) > 0)
			{
			if (!batch)
				{
				BIO_printf(bio_err,"\n%d out of %d certificate requests certified, commit? [y/n]",total_done,total);
				BIO_flush(bio_err);
				buf[0][0]='\0';
				fgets(buf[0],10,stdin);
				if ((buf[0][0] != 'y') && (buf[0][0] != 'Y'))
					{
					BIO_printf(bio_err,"CERTIFICATION CANCELED\n"); 
					ret=0;
					goto err;
					}
				}

			BIO_printf(bio_err,"Write out database with %d new entries\n",sk_num(cert_sk));

			strncpy(buf[0],serialfile,BSIZE-4);
			strcat(buf[0],".new");

			if (!save_serial(buf[0],serial)) goto err;

			strncpy(buf[1],dbfile,BSIZE-4);
			strcat(buf[1],".new");
			if (BIO_write_filename(out,buf[1]) <= 0)
				{
				perror(dbfile);
				BIO_printf(bio_err,"unable to open '%s'\n",dbfile);
				goto err;
				}
			l=TXT_DB_write(out,db);
			if (l <= 0) goto err;
			}
	
		if (verbose)
			BIO_printf(bio_err,"writing new certificates\n");
		for (i=0; i<sk_num(cert_sk); i++)
			{
			int k;
			unsigned char *n;

			x=(X509 *)sk_value(cert_sk,i);

			j=x->cert_info->serialNumber->length;
			p=(char *)x->cert_info->serialNumber->data;
			
			strncpy(buf[2],outdir,BSIZE-(j*2)-6);
			strcat(buf[2],"/");
			n=(unsigned char *)&(buf[2][strlen(buf[2])]);
			if (j > 0)
				{
				for (k=0; k<j; k++)
					{
					sprintf((char *)n,"%02X",(unsigned char)*(p++));
					n+=2;
					}
				}
			else
				{
				*(n++)='0';
				*(n++)='0';
				}
			*(n++)='.'; *(n++)='p'; *(n++)='e'; *(n++)='m';
			*n='\0';
			if (verbose)
				BIO_printf(bio_err,"writing %s\n",buf[2]);

			if (BIO_write_filename(Cout,buf[2]) <= 0)
				{
				perror(buf[2]);
				goto err;
				}
			write_new_certificate(Cout,x, 0);
			write_new_certificate(Sout,x, output_der);
			}

		if (sk_num(cert_sk))
			{
			/* Rename the database and the serial file */
			strncpy(buf[2],serialfile,BSIZE-4);
			strcat(buf[2],".old");
			BIO_free(in);
			BIO_free(out);
			in=NULL;
			out=NULL;
			if (rename(serialfile,buf[2]) < 0)
				{
				BIO_printf(bio_err,"unabel to rename %s to %s\n",
					serialfile,buf[2]);
				perror("reason");
				goto err;
				}
			if (rename(buf[0],serialfile) < 0)
				{
				BIO_printf(bio_err,"unabel to rename %s to %s\n",
					buf[0],serialfile);
				perror("reason");
				rename(buf[2],serialfile);
				goto err;
				}

			strncpy(buf[2],dbfile,BSIZE-4);
			strcat(buf[2],".old");
			if (rename(dbfile,buf[2]) < 0)
				{
				BIO_printf(bio_err,"unabel to rename %s to %s\n",
					dbfile,buf[2]);
				perror("reason");
				goto err;
				}
			if (rename(buf[1],dbfile) < 0)
				{
				BIO_printf(bio_err,"unabel to rename %s to %s\n",
					buf[1],dbfile);
				perror("reason");
				rename(buf[2],dbfile);
				goto err;
				}
			BIO_printf(bio_err,"Data Base Updated\n");
			}
		}
	
	/*****************************************************************/
	if (gencrl)
		{
		if ((hex=BIO_new(BIO_s_mem())) == NULL) goto err;

		if (!crldays && !crlhours)
			{
			crldays=CONF_get_number(conf,section,
				ENV_DEFAULT_CRL_DAYS);
			crlhours=CONF_get_number(conf,section,
				ENV_DEFAULT_CRL_HOURS);
			}
		if ((crldays == 0) && (crlhours == 0))
			{
			BIO_printf(bio_err,"cannot lookup how long until the next CRL is issuer\n");
			goto err;
			}

		if (verbose) BIO_printf(bio_err,"making CRL\n");
		if ((crl=X509_CRL_new()) == NULL) goto err;
		ci=crl->crl;
		X509_NAME_free(ci->issuer);
		ci->issuer=X509_NAME_dup(x509->cert_info->subject);
		if (ci->issuer == NULL) goto err;

		X509_gmtime_adj(ci->lastUpdate,0);
		if (ci->nextUpdate == NULL)
			ci->nextUpdate=ASN1_UTCTIME_new();
		X509_gmtime_adj(ci->nextUpdate,(crldays*24+crlhours)*60*60);

		for (i=0; i<sk_num(db->data); i++)
			{
			pp=(char **)sk_value(db->data,i);
			if (pp[DB_type][0] == DB_TYPE_REV)
				{
				if ((r=X509_REVOKED_new()) == NULL) goto err;
				ASN1_STRING_set((ASN1_STRING *)
					r->revocationDate,
					(unsigned char *)pp[DB_rev_date],
					strlen(pp[DB_rev_date]));
				/* strcpy(r->revocationDate,pp[DB_rev_date]);*/

				BIO_reset(hex);
				if (!BIO_puts(hex,pp[DB_serial]))
					goto err;
				if (!a2i_ASN1_INTEGER(hex,r->serialNumber,
					buf[0],BSIZE)) goto err;

				sk_push(ci->revoked,(char *)r);
				}
			}
		/* sort the data so it will be written in serial
		 * number order */
		sk_find(ci->revoked,NULL);
		for (i=0; i<sk_num(ci->revoked); i++)
			{
			r=(X509_REVOKED *)sk_value(ci->revoked,i);
			r->sequence=i;
			}

		/* we how have a CRL */
		if (verbose) BIO_printf(bio_err,"signing CRL\n");
		if (md != NULL)
			{
			if ((dgst=EVP_get_digestbyname(md)) == NULL)
				{
				BIO_printf(bio_err,"%s is an unsupported message digest type\n",md);
				goto err;
				}
			}
		else
			dgst=EVP_md5();
		if (!X509_CRL_sign(crl,pkey,dgst)) goto err;

		PEM_write_bio_X509_CRL(Sout,crl);
		}
	/*****************************************************************/
	ret=0;
err:
	if (hex != NULL) BIO_free(hex);
	if (Cout != NULL) BIO_free(Cout);
	if (Sout != NULL) BIO_free(Sout);
	if (out != NULL) BIO_free(out);
	if (in != NULL) BIO_free(in);

	if (cert_sk != NULL) sk_pop_free(cert_sk,X509_free);
	if (extensions_sk != NULL)
		sk_pop_free(extensions_sk,X509_EXTENSION_free);

	if (ret) ERR_print_errors(bio_err);
	if (serial != NULL) BN_free(serial);
	if (db != NULL) TXT_DB_free(db);
	if (pkey != NULL) EVP_PKEY_free(pkey);
	if (x509 != NULL) X509_free(x509);
	if (crl != NULL) X509_CRL_free(crl);
	if (conf != NULL) CONF_free(conf);
	X509v3_cleanup_extensions();
	EXIT(ret);
	}

static void lookup_fail(name,tag)
char *name;
char *tag;
	{
	BIO_printf(bio_err,"variable lookup failed for %s::%s\n",name,tag);
	}

static int MS_CALLBACK key_callback(buf,len,verify)
char *buf;
int len,verify;
	{
	int i;

	if (key == NULL) return(0);
	i=strlen(key);
	i=(i > len)?len:i;
	memcpy(buf,key,i);
	return(i);
	}

static unsigned long index_serial_hash(a)
char **a;
	{
	char *n;

	n=a[DB_serial];
	while (*n == '0') n++;
	return(lh_strhash(n));
	}

static int index_serial_cmp(a,b)
char **a;
char **b;
	{
	char *aa,*bb;

	for (aa=a[DB_serial]; *aa == '0'; aa++);
	for (bb=b[DB_serial]; *bb == '0'; bb++);
	return(strcmp(aa,bb));
	}

static unsigned long index_name_hash(a)
char **a;
	{ return(lh_strhash(a[DB_name])); }

static int index_name_qual(a)
char **a;
	{ return(a[0][0] == 'V'); }

static int index_name_cmp(a,b)
char **a;
char **b;
	{ return(strcmp(a[DB_name],b[DB_name])); }

static BIGNUM *load_serial(serialfile)
char *serialfile;
	{
	BIO *in=NULL;
	BIGNUM *ret=NULL;
	MS_STATIC char buf[1024];
	ASN1_INTEGER *ai=NULL;

	if ((in=BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(bio_err);
		goto err;
		}

	if (BIO_read_filename(in,serialfile) <= 0)
		{
		perror(serialfile);
		goto err;
		}
	ai=ASN1_INTEGER_new();
	if (ai == NULL) goto err;
	if (!a2i_ASN1_INTEGER(in,ai,buf,1024))
		{
		BIO_printf(bio_err,"unable to load number from %s\n",
			serialfile);
		goto err;
		}
	ret=ASN1_INTEGER_to_BN(ai,NULL);
	if (ret == NULL)
		{
		BIO_printf(bio_err,"error converting number from bin to BIGNUM");
		goto err;
		}
err:
	if (in != NULL) BIO_free(in);
	if (ai != NULL) ASN1_INTEGER_free(ai);
	return(ret);
	}

static int save_serial(serialfile,serial)
char *serialfile;
BIGNUM *serial;
	{
	BIO *out;
	int ret=0;
	ASN1_INTEGER *ai=NULL;

	out=BIO_new(BIO_s_file());
	if (out == NULL)
		{
		ERR_print_errors(bio_err);
		goto err;
		}
	if (BIO_write_filename(out,serialfile) <= 0)
		{
		perror(serialfile);
		goto err;
		}

	if ((ai=BN_to_ASN1_INTEGER(serial,NULL)) == NULL)
		{
		BIO_printf(bio_err,"error converting serial to ASN.1 format\n");
		goto err;
		}
	i2a_ASN1_INTEGER(out,ai);
	BIO_puts(out,"\n");
	ret=1;
err:
	if (out != NULL) BIO_free(out);
	if (ai != NULL) ASN1_INTEGER_free(ai);
	return(ret);
	}

static int certify(xret,infile,pkey,x509,dgst,policy,db,serial,startdate,days,
	batch,extensions,verbose)
X509 **xret;
char *infile;
EVP_PKEY *pkey;
X509 *x509;
EVP_MD *dgst;
STACK *policy;
TXT_DB *db;
BIGNUM *serial;
char *startdate;
int days;
int batch;
STACK *extensions;
int verbose;
	{
	X509_REQ *req=NULL;
	BIO *in=NULL;
	EVP_PKEY *pktmp=NULL;
	int ok= -1,i;

	in=BIO_new(BIO_s_file());

	if (BIO_read_filename(in,infile) <= 0)
		{
		perror(infile);
		goto err;
		}
	if ((req=PEM_read_bio_X509_REQ(in,NULL,NULL)) == NULL)
		{
		BIO_printf(bio_err,"Error reading certificate request in %s\n",
			infile);
		goto err;
		}
	if (verbose)
		X509_REQ_print(bio_err,req);

	BIO_printf(bio_err,"Check that the request matches the signature\n");

	if ((pktmp=X509_REQ_get_pubkey(req)) == NULL)
		{
		BIO_printf(bio_err,"error unpacking public key\n");
		goto err;
		}
	i=X509_REQ_verify(req,pktmp);
	if (i < 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature verification problems....\n");
		goto err;
		}
	if (i == 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature did not match the certificate request\n");
		goto err;
		}
	else
		BIO_printf(bio_err,"Signature ok\n");

	ok=do_body(xret,pkey,x509,dgst,policy,db,serial,startdate,
		days,batch,verbose,req,extensions);

err:
	if (req != NULL) X509_REQ_free(req);
	if (in != NULL) BIO_free(in);
	return(ok);
	}

static int certify_cert(xret,infile,pkey,x509,dgst,policy,db,serial,startdate,
	days, batch,extensions,verbose)
X509 **xret;
char *infile;
EVP_PKEY *pkey;
X509 *x509;
EVP_MD *dgst;
STACK *policy;
TXT_DB *db;
BIGNUM *serial;
char *startdate;
int days;
int batch;
STACK *extensions;
int verbose;
	{
	X509 *req=NULL;
	X509_REQ *rreq=NULL;
	BIO *in=NULL;
	EVP_PKEY *pktmp=NULL;
	int ok= -1,i;

	in=BIO_new(BIO_s_file());

	if (BIO_read_filename(in,infile) <= 0)
		{
		perror(infile);
		goto err;
		}
	if ((req=PEM_read_bio_X509(in,NULL,NULL)) == NULL)
		{
		BIO_printf(bio_err,"Error reading self signed certificate in %s\n",infile);
		goto err;
		}
	if (verbose)
		X509_print(bio_err,req);

	BIO_printf(bio_err,"Check that the request matches the signature\n");

	if ((pktmp=X509_get_pubkey(req)) == NULL)
		{
		BIO_printf(bio_err,"error unpacking public key\n");
		goto err;
		}
	i=X509_verify(req,pktmp);
	if (i < 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature verification problems....\n");
		goto err;
		}
	if (i == 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature did not match the certificate request\n");
		goto err;
		}
	else
		BIO_printf(bio_err,"Signature ok\n");

	if ((rreq=X509_to_X509_REQ(req,NULL,EVP_md5())) == NULL)
		goto err;

	ok=do_body(xret,pkey,x509,dgst,policy,db,serial,startdate,days,
		batch,verbose,rreq,extensions);

err:
	if (rreq != NULL) X509_REQ_free(rreq);
	if (req != NULL) X509_free(req);
	if (in != NULL) BIO_free(in);
	return(ok);
	}

static int do_body(xret,pkey,x509,dgst,policy,db,serial,startdate,days,
	batch,verbose,req, extensions)
X509 **xret;
EVP_PKEY *pkey;
X509 *x509;
EVP_MD *dgst;
STACK *policy;
TXT_DB *db;
BIGNUM *serial;
char *startdate;
int days;
int batch;
int verbose;
X509_REQ *req;
STACK *extensions;
	{
	X509_NAME *name=NULL,*CAname=NULL,*subject=NULL;
	ASN1_UTCTIME *tm,*tmptm;
	ASN1_STRING *str,*str2;
	ASN1_OBJECT *obj;
	X509 *ret=NULL;
	X509_CINF *ci;
	X509_NAME_ENTRY *ne;
	X509_NAME_ENTRY *tne,*push;
	X509_EXTENSION *ex=NULL;
	EVP_PKEY *pktmp;
	int ok= -1,i,j,last,nid;
	char *p;
	CONF_VALUE *cv;
	char *row[DB_NUMBER],**rrow,**irow=NULL;
	char buf[25],*pbuf;

	tmptm=ASN1_UTCTIME_new();
	if (tmptm == NULL)
		{
		BIO_printf(bio_err,"malloc error\n");
		return(0);
		}

	for (i=0; i<DB_NUMBER; i++)
		row[i]=NULL;

	BIO_printf(bio_err,"The Subjects Distinguished Name is as follows\n");
	name=X509_REQ_get_subject_name(req);
	for (i=0; i<X509_NAME_entry_count(name); i++)
		{
		ne=(X509_NAME_ENTRY *)X509_NAME_get_entry(name,i);
		obj=X509_NAME_ENTRY_get_object(ne);
		j=i2a_ASN1_OBJECT(bio_err,obj);
		str=X509_NAME_ENTRY_get_data(ne);
		pbuf=buf;
		for (j=22-j; j>0; j--)
			*(pbuf++)=' ';
		*(pbuf++)=':';
		*(pbuf++)='\0';
		BIO_puts(bio_err,buf);

		if (msie_hack)
			{
			/* assume all type should be strings */
			nid=OBJ_obj2nid(ne->object);

			if (str->type == V_ASN1_UNIVERSALSTRING)
				ASN1_UNIVERSALSTRING_to_string(str);

			if ((str->type == V_ASN1_IA5STRING) &&
				(nid != NID_pkcs9_emailAddress))
				str->type=V_ASN1_T61STRING;

			if ((nid == NID_pkcs9_emailAddress) &&
				(str->type == V_ASN1_PRINTABLESTRING))
				str->type=V_ASN1_IA5STRING;
			}

		if (str->type == V_ASN1_PRINTABLESTRING)
			BIO_printf(bio_err,"PRINTABLE:'");
		else if (str->type == V_ASN1_T61STRING)
			BIO_printf(bio_err,"T61STRING:'");
		else if (str->type == V_ASN1_IA5STRING)
			BIO_printf(bio_err,"IA5STRING:'");
		else if (str->type == V_ASN1_UNIVERSALSTRING)
			BIO_printf(bio_err,"UNIVERSALSTRING:'");
		else
			BIO_printf(bio_err,"ASN.1 %2d:'",str->type);

		/* check some things */
		if ((OBJ_obj2nid(obj) == NID_pkcs9_emailAddress) &&
			(str->type != V_ASN1_IA5STRING))
			{
			BIO_printf(bio_err,"\nemailAddress type needs to be of type IA5STRING\n");
			goto err;
			}
		j=ASN1_PRINTABLE_type(str->data,str->length);
		if (	((j == V_ASN1_T61STRING) &&
			 (str->type != V_ASN1_T61STRING)) ||
			((j == V_ASN1_IA5STRING) &&
			 (str->type == V_ASN1_PRINTABLESTRING)))
			{
			BIO_printf(bio_err,"\nThe string contains characters that are illegal for the ASN.1 type\n");
			goto err;
			}
			
		p=(char *)str->data;
		for (j=str->length; j>0; j--)
			{
			if ((*p >= ' ') && (*p <= '~'))
				BIO_printf(bio_err,"%c",*p);
			else if (*p & 0x80)
				BIO_printf(bio_err,"\\0x%02X",*p);
			else if ((unsigned char)*p == 0xf7)
				BIO_printf(bio_err,"^?");
			else	BIO_printf(bio_err,"^%c",*p+'@');
			p++;
			}
		BIO_printf(bio_err,"'\n");
		}

	/* Ok, now we check the 'policy' stuff. */
	if ((subject=X509_NAME_new()) == NULL)
		{
		BIO_printf(bio_err,"Malloc failure\n");
		goto err;
		}

	/* take a copy of the issuer name before we mess with it. */
	CAname=X509_NAME_dup(x509->cert_info->subject);
	if (CAname == NULL) goto err;
	str=str2=NULL;

	for (i=0; i<sk_num(policy); i++)
		{
		cv=(CONF_VALUE *)sk_value(policy,i); /* get the object id */
		if ((j=OBJ_txt2nid(cv->name)) == NID_undef)
			{
			BIO_printf(bio_err,"%s:unknown object type in 'policy' configuration\n",cv->name);
			goto err;
			}
		obj=OBJ_nid2obj(j);

		last= -1;
		for (;;)
			{
			/* lookup the object in the supplied name list */
			j=X509_NAME_get_index_by_OBJ(name,obj,last);
			if (j < 0)
				{
				if (last != -1) break;
				tne=NULL;
				}
			else
				{
				tne=X509_NAME_get_entry(name,j);
				}
			last=j;

			/* depending on the 'policy', decide what to do. */
			push=NULL;
			if (strcmp(cv->value,"optional") == 0)
				{
				if (tne != NULL)
					push=tne;
				}
			else if (strcmp(cv->value,"supplied") == 0)
				{
				if (tne == NULL)
					{
					BIO_printf(bio_err,"The %s field needed to be supplied and was missing\n",cv->name);
					goto err;
					}
				else
					push=tne;
				}
			else if (strcmp(cv->value,"match") == 0)
				{
				int last2;

				if (tne == NULL)
					{
					BIO_printf(bio_err,"The mandatory %s field was missing\n",cv->name);
					goto err;
					}

				last2= -1;

again2:
				j=X509_NAME_get_index_by_OBJ(CAname,obj,last2);
				if ((j < 0) && (last2 == -1))
					{
					BIO_printf(bio_err,"The %s field does not exist in the CA certificate,\nthe 'policy' is misconfigured\n",cv->name);
					goto err;
					}
				if (j >= 0)
					{
					push=X509_NAME_get_entry(CAname,j);
					str=X509_NAME_ENTRY_get_data(tne);
					str2=X509_NAME_ENTRY_get_data(push);
					last2=j;
					if (ASN1_STRING_cmp(str,str2) != 0)
						goto again2;
					}
				if (j < 0)
					{
					BIO_printf(bio_err,"The %s field needed to be the same in the\nCA certificate (%s) and the request (%s)\n",cv->name,((str == NULL)?"NULL":(char *)str->data),((str2 == NULL)?"NULL":(char *)str2->data));
					goto err;
					}
				}
			else
				{
				BIO_printf(bio_err,"%s:invalid type in 'policy' configuration\n",cv->value);
				goto err;
				}

			if (push != NULL)
				{
				if (!X509_NAME_add_entry(subject,push,
					X509_NAME_entry_count(subject),0))
					{
					if (push != NULL)
						X509_NAME_ENTRY_free(push);
					BIO_printf(bio_err,"Malloc failure\n");
					goto err;
					}
				}
			if (j < 0) break;
			}
		}

	if (preserve)
		{
		X509_NAME_free(subject);
		subject=X509_NAME_dup(X509_REQ_get_subject_name(req));
		if (subject == NULL) goto err;
		}

	if (verbose)
		BIO_printf(bio_err,"The subject name apears to be ok, checking data base for clashes\n");

	row[DB_name]=X509_NAME_oneline(subject,NULL,0);
	row[DB_serial]=BN_bn2ascii(serial);
	if ((row[DB_name] == NULL) || (row[DB_serial] == NULL))
		{
		BIO_printf(bio_err,"Malloc failure\n");
		goto err;
		}

	rrow=TXT_DB_get_by_index(db,DB_name,row);
	if (rrow != NULL)
		{
		BIO_printf(bio_err,"ERROR:There is already a certificate for %s\n",
			row[DB_name]);
		}
	else
		{
		rrow=TXT_DB_get_by_index(db,DB_serial,row);
		if (rrow != NULL)
			{
			BIO_printf(bio_err,"ERROR:Serial number %s has already been issued,\n",
				row[DB_serial]);
			BIO_printf(bio_err,"      check the database/serial_file for corruption\n");
			}
		}

	if (rrow != NULL)
		{
		BIO_printf(bio_err,
			"The matching entry has the following details\n");
		if (rrow[DB_type][0] == 'E')
			p="Expired";
		else if (rrow[DB_type][0] == 'R')
			p="Revoked";
		else if (rrow[DB_type][0] == 'V')
			p="Valid";
		else
			p="\ninvalid type, Data base error\n";
		BIO_printf(bio_err,"Type          :%s\n",p);;
		if (rrow[DB_type][0] == 'R')
			{
			p=rrow[DB_exp_date]; if (p == NULL) p="undef";
			BIO_printf(bio_err,"Was revoked on:%s\n",p);
			}
		p=rrow[DB_exp_date]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"Expires on    :%s\n",p);
		p=rrow[DB_serial]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"Serial Number :%s\n",p);
		p=rrow[DB_file]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"File name     :%s\n",p);
		p=rrow[DB_name]; if (p == NULL) p="undef";
		BIO_printf(bio_err,"Subject Name  :%s\n",p);
		ok= -1; /* This is now a 'bad' error. */
		goto err;
		}

	/* We are now totaly happy, lets make and sign the certificate */
	if (verbose)
		BIO_printf(bio_err,"Everything appears to be ok, creating and signing the certificate\n");

	if ((ret=X509_new()) == NULL) goto err;
	ci=ret->cert_info;

#ifdef X509_V3
	/* Make it an X509 v3 certificate. */
	if (!X509_set_version(x509,2)) goto err;
#endif

	if (BN_to_ASN1_INTEGER(serial,ci->serialNumber) == NULL)
		goto err;
	if (!X509_set_issuer_name(ret,X509_get_subject_name(x509)))
		goto err;

	BIO_printf(bio_err,"Certificate is to be certified until ");
	if (strcmp(startdate,"today") == 0)
		{
		X509_gmtime_adj(X509_get_notBefore(ret),0);
		X509_gmtime_adj(X509_get_notAfter(ret),(long)60*60*24*days);
		}
	else
		{
		/*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX*/
		ASN1_UTCTIME_set_string(X509_get_notBefore(ret),startdate);
		}
	ASN1_UTCTIME_print(bio_err,X509_get_notAfter(ret));
	BIO_printf(bio_err," (%d days)\n",days);

	if (!X509_set_subject_name(ret,subject)) goto err;

	pktmp=X509_REQ_get_pubkey(req);
	if (!X509_set_pubkey(ret,pktmp)) goto err;

	/* Lets add the extensions, if there are any */
	if ((extensions != NULL) && (sk_num(extensions) > 0))
		{
		if (ci->version == NULL)
			if ((ci->version=ASN1_INTEGER_new()) == NULL)
				goto err;
		ASN1_INTEGER_set(ci->version,2); /* version 3 certificate */

		/* Free the current entries if any, there should not
		 * be any I belive */
		if (ci->extensions != NULL)
			sk_pop_free(ci->extensions,X509_EXTENSION_free);

		if ((ci->extensions=sk_new_null()) == NULL)
			goto err;

		/* Lets 'copy' in the new ones */
		for (i=0; i<sk_num(extensions); i++)
			{
			ex=X509_EXTENSION_dup((X509_EXTENSION *)
				sk_value(extensions,i));
			if (ex == NULL) goto err;
			if (!sk_push(ci->extensions,(char *)ex)) goto err;
			}
		}


	if (!batch)
		{
		BIO_printf(bio_err,"Sign the certificate? [y/n]:");
		BIO_flush(bio_err);
		buf[0]='\0';
		fgets(buf,sizeof(buf)-1,stdin);
		if (!((buf[0] == 'y') || (buf[0] == 'Y')))
			{
			BIO_printf(bio_err,"CERTIFICATE WILL NOT BE CERTIFIED\n");
			ok=0;
			goto err;
			}
		}

#ifndef NO_DSA
        pktmp=X509_get_pubkey(ret);
        if (EVP_PKEY_missing_parameters(pktmp) &&
		!EVP_PKEY_missing_parameters(pkey))
		EVP_PKEY_copy_parameters(pktmp,pkey);
#endif

	if (!X509_sign(ret,pkey,dgst))
		goto err;

	/* We now just add it to the database */
	row[DB_type]=(char *)Malloc(2);

	tm=X509_get_notAfter(ret);
	row[DB_exp_date]=(char *)Malloc(tm->length+1);
	memcpy(row[DB_exp_date],tm->data,tm->length);
	row[DB_exp_date][tm->length]='\0';

	row[DB_rev_date]=NULL;

	/* row[DB_serial] done already */
	row[DB_file]=(char *)Malloc(8);
	/* row[DB_name] done already */

	if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
		(row[DB_file] == NULL))
		{
		BIO_printf(bio_err,"Malloc failure\n");
		goto err;
		}
	strcpy(row[DB_file],"unknown");
	row[DB_type][0]='V';
	row[DB_type][1]='\0';

	if ((irow=(char **)Malloc(sizeof(char *)*(DB_NUMBER+1))) == NULL)
		{
		BIO_printf(bio_err,"Malloc failure\n");
		goto err;
		}

	for (i=0; i<DB_NUMBER; i++)
		{
		irow[i]=row[i];
		row[i]=NULL;
		}
	irow[DB_NUMBER]=NULL;

	if (!TXT_DB_insert(db,irow))
		{
		BIO_printf(bio_err,"failed to update database\n");
		BIO_printf(bio_err,"TXT_DB error number %ld\n",db->error);
		goto err;
		}
	ok=1;
err:
	for (i=0; i<DB_NUMBER; i++)
		if (row[i] != NULL) Free(row[i]);

	if (CAname != NULL)
		X509_NAME_free(CAname);
	if (subject != NULL)
		X509_NAME_free(subject);
	if (ok <= 0)
		{
		if (ret != NULL) X509_free(ret);
		ret=NULL;
		}
	else
		*xret=ret;
	return(ok);
	}

static void write_new_certificate(bp,x, output_der)
BIO *bp;
X509 *x;
int output_der;
	{
	char *f;
	char buf[256];

	if (output_der)
		{
		(void)i2d_X509_bio(bp,x);
		return;
		}

	f=X509_NAME_oneline(X509_get_issuer_name(x),buf,256);
	BIO_printf(bp,"issuer :%s\n",f);

	f=X509_NAME_oneline(X509_get_subject_name(x),buf,256);
	BIO_printf(bp,"subject:%s\n",f);

	BIO_puts(bp,"serial :");
	i2a_ASN1_INTEGER(bp,x->cert_info->serialNumber);
	BIO_puts(bp,"\n\n");
	X509_print(bp,x);
	BIO_puts(bp,"\n");
	PEM_write_bio_X509(bp,x);
	BIO_puts(bp,"\n");
	}

static int certify_spkac(xret,infile,pkey,x509,dgst,policy,db,serial,
	startdate,days,extensions,verbose)
X509 **xret;
char *infile;
EVP_PKEY *pkey;
X509 *x509;
EVP_MD *dgst;
STACK *policy;
TXT_DB *db;
BIGNUM *serial;
char *startdate;
int days;
STACK *extensions;
int verbose;
	{
	STACK *sk=NULL;
	LHASH *parms=NULL;
	X509_REQ *req=NULL;
	CONF_VALUE *cv=NULL;
	NETSCAPE_SPKI *spki = NULL;
	unsigned char *spki_der = NULL,*p;
	X509_REQ_INFO *ri;
	char *type,*buf;
	EVP_PKEY *pktmp=NULL;
	X509_NAME *n=NULL;
	X509_NAME_ENTRY *ne=NULL;
	int ok= -1,i,j;
	long errline;
	int nid;

	/*
	 * Load input file into a hash table.  (This is just an easy
	 * way to read and parse the file, then put it into a convenient
	 * STACK format).
	 */
	parms=CONF_load(NULL,infile,&errline);
	if (parms == NULL)
		{
		BIO_printf(bio_err,"error on line %ld of %s\n",errline,infile);
		ERR_print_errors(bio_err);
		goto err;
		}

	sk=CONF_get_section(parms, "default");
	if (sk_num(sk) == 0)
		{
		BIO_printf(bio_err, "no name/value pairs found in %s\n", infile);
		CONF_free(parms);
		goto err;
		}

	/*
	 * Now create a dummy X509 request structure.  We don't actually
	 * have an X509 request, but we have many of the components
	 * (a public key, various DN components).  The idea is that we
	 * put these components into the right X509 request structure
	 * and we can use the same code as if you had a real X509 request.
	 */
	req=X509_REQ_new();
	if (req == NULL)
		{
		ERR_print_errors(bio_err);
		goto err;
		}

	/*
	 * Build up the subject name set.
	 */
	ri=req->req_info;
	n = ri->subject;

	for (i = 0; ; i++)
		{
		if ((int)sk_num(sk) <= i) break;

		cv=(CONF_VALUE *)sk_value(sk,i);
		type=cv->name;
		buf=cv->value;

		if ((nid=OBJ_txt2nid(type)) == NID_undef)
			{
			if (strcmp(type, "SPKAC") == 0)
				{
				spki_der=(unsigned char *)Malloc(
					strlen(cv->value)+1);
				if (spki_der == NULL)
					{
					BIO_printf(bio_err,"Malloc failure\n");
					goto err;
					}
				j = EVP_DecodeBlock(spki_der, (unsigned char *)cv->value,
					strlen(cv->value));
				if (j <= 0)
					{
					BIO_printf(bio_err, "Can't b64 decode SPKAC structure\n");
					goto err;
					}

				p=spki_der;
				spki = d2i_NETSCAPE_SPKI(&spki, &p, j);
				Free(spki_der);
				spki_der = NULL;
				if (spki == NULL)
					{
					BIO_printf(bio_err,"unable to load Netscape SPKAC structure\n");
					ERR_print_errors(bio_err);
					goto err;
					}
				}
			continue;
			}

		j=ASN1_PRINTABLE_type((unsigned char *)buf,-1);
		if (fix_data(nid, &j) == 0)
			{
			BIO_printf(bio_err,
				"invalid characters in string %s\n",buf);
			goto err;
			}

		if ((ne=X509_NAME_ENTRY_create_by_NID(&ne,nid,j,
			(unsigned char *)buf,
			strlen(buf))) == NULL)
			goto err;

		if (!X509_NAME_add_entry(n,ne,X509_NAME_entry_count(n),0))
			goto err;
		}
	if (spki == NULL)
		{
		BIO_printf(bio_err,"Netscape SPKAC structure not found in %s\n",
			infile);
		goto err;
		}

	/*
	 * Now extract the key from the SPKI structure.
	 */

	BIO_printf(bio_err,"Check that the SPKAC request matches the signature\n");

	if ((pktmp=X509_PUBKEY_get(spki->spkac->pubkey)) == NULL)
		{
		BIO_printf(bio_err,"error unpacking SPKAC public key\n");
		goto err;
		}

	j = NETSCAPE_SPKI_verify(spki, pktmp);
	if (j <= 0)
		{
		BIO_printf(bio_err,"signature verification failed on SPKAC public key\n");
		goto err;
		}
	BIO_printf(bio_err,"Signature ok\n");

	X509_REQ_set_pubkey(req,pktmp);
	ok=do_body(xret,pkey,x509,dgst,policy,db,serial,startdate,
		days,1,verbose,req,extensions);
err:
	if (req != NULL) X509_REQ_free(req);
	if (parms != NULL) CONF_free(parms);
	if (spki_der != NULL) Free(spki_der);
	if (spki != NULL) NETSCAPE_SPKI_free(spki);
	if (ne != NULL) X509_NAME_ENTRY_free(ne);

	return(ok);
	}

static int fix_data(nid,type)
int nid;
int *type;
	{
	if (nid == NID_pkcs9_emailAddress)
		*type=V_ASN1_IA5STRING;
	if ((nid == NID_commonName) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_challengePassword) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_unstructuredName) && (*type == V_ASN1_T61STRING))
		return(0);
	if (nid == NID_pkcs9_unstructuredName)
		*type=V_ASN1_IA5STRING;
	return(1);
	}


static STACK *load_extensions(sec)
char *sec;
	{
	STACK *ext;
	STACK *ret=NULL;
	CONF_VALUE *cv;
	ASN1_OCTET_STRING *str=NULL;
	ASN1_STRING *tmp=NULL;
	X509_EXTENSION *x;
	BIO *mem=NULL;
	BUF_MEM *buf=NULL;
	int i,nid,len;
	unsigned char *ptr;
	int pack_type;
	int data_type;

	if ((ext=CONF_get_section(conf,sec)) == NULL)
		{
		BIO_printf(bio_err,"unable to find extension section called '%s'\n",sec);
		return(NULL);
		}

	if ((ret=sk_new_null()) == NULL) return(NULL);

	for (i=0; i<sk_num(ext); i++)
		{
		cv=(CONF_VALUE *)sk_value(ext,i); /* get the object id */
		if ((nid=OBJ_txt2nid(cv->name)) == NID_undef)
			{
			BIO_printf(bio_err,"%s:unknown object type in section, '%s'\n",sec,cv->name);
			goto err;
			}

		pack_type=X509v3_pack_type_by_NID(nid);
		data_type=X509v3_data_type_by_NID(nid);

		/* pack up the input bytes */
		ptr=(unsigned char *)cv->value;
		len=strlen((char *)ptr);
		if ((len > 2) && (cv->value[0] == '0') &&
			(cv->value[1] == 'x'))
			{
			if (data_type == V_ASN1_UNDEF)
				{
				BIO_printf(bio_err,"data type for extension %s is unknown\n",cv->name);
				goto err;
				}
			if (mem == NULL)
				if ((mem=BIO_new(BIO_s_mem())) == NULL)
					goto err;
			if (((buf=BUF_MEM_new()) == NULL) ||
				!BUF_MEM_grow(buf,128))
				goto err;
			if ((tmp=ASN1_STRING_new()) == NULL) goto err;

			BIO_reset(mem);
			BIO_write(mem,(char *)&(ptr[2]),len-2);
			if (!a2i_ASN1_STRING(mem,tmp,buf->data,buf->max))
				goto err;
			len=tmp->length;
			ptr=tmp->data;
			}

		switch (pack_type)
			{
		case X509_EXT_PACK_STRING:
			if ((str=X509v3_pack_string(&str,
				data_type,ptr,len)) == NULL)
				goto err;
			break;
		case X509_EXT_PACK_UNKNOWN:
		default:
			BIO_printf(bio_err,"Don't know how to pack extension %s\n",cv->name);
			goto err;
			break;
			}

		if ((x=X509_EXTENSION_create_by_NID(NULL,nid,0,str)) == NULL)
			goto err;
		sk_push(ret,(char *)x);
		}

	if (0)
		{
err:
		if (ret != NULL) sk_pop_free(ret,X509_EXTENSION_free);
		ret=NULL;
		}
	if (str != NULL) ASN1_OCTET_STRING_free(str);
	if (tmp != NULL) ASN1_STRING_free(tmp);
	if (buf != NULL) BUF_MEM_free(buf);
	if (mem != NULL) BIO_free(mem);
	return(ret);
	}

static int check_time_format(str)
char *str;
	{
	ASN1_UTCTIME tm;

	tm.data=(unsigned char *)str;
	tm.length=strlen(str);
	tm.type=V_ASN1_UTCTIME;
	return(ASN1_UTCTIME_check(&tm));
	}

