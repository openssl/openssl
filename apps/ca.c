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
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/txt_db.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#ifndef W_OK
#  ifdef VMS
#    if defined(__DECC)
#      include <unistd.h>
#    else
#      include <unixlib.h>
#    endif
#  elif !defined(VXWORKS)
#    include <sys/file.h>
#  endif
#endif

#ifndef W_OK
#  define F_OK 0
#  define X_OK 1
#  define W_OK 2
#  define R_OK 4
#endif

#undef PROG
#define PROG ca_main

#define BASE_SECTION	"ca"
#define CONFIG_FILE "openssl.cnf"

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
#define ENV_DEFAULT_ENDDATE 	"default_enddate"
#define ENV_DEFAULT_CRL_DAYS 	"default_crl_days"
#define ENV_DEFAULT_CRL_HOURS 	"default_crl_hours"
#define ENV_DEFAULT_MD		"default_md"
#define ENV_PRESERVE		"preserve"
#define ENV_POLICY      	"policy"
#define ENV_EXTENSIONS      	"x509_extensions"
#define ENV_CRLEXT      	"crl_extensions"
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
" -startdate YYMMDDHHMMSSZ  - certificate validity notBefore\n",
" -enddate YYMMDDHHMMSSZ    - certificate validity notAfter (overrides -days)\n",
" -days arg       - number of days to certify the certificate for\n",
" -md arg         - md to use, one of md2, md5, sha or sha1\n",
" -policy arg     - The CA 'policy' to support\n",
" -keyfile arg    - PEM private key file\n",
" -key arg        - key to decode the private key if it is encrypted\n",
" -cert file      - The CA certificate\n",
" -in file        - The input PEM encoded certificate request(s)\n",
" -out file       - Where to put the output file(s)\n",
" -outdir dir     - Where to put output certificates\n",
" -infiles ....   - The last argument, requests to process\n",
" -spkac file     - File contains DN and signed public key and challenge\n",
" -ss_cert file   - File contains a self signed cert to sign\n",
" -preserveDN     - Don't re-order the DN\n",
" -batch          - Don't ask questions\n",
" -msie_hack      - msie modifications to handle all those universal strings\n",
" -revoke file    - Revoke a certificate (given in file)\n",
" -extensions ..  - Extension section (override value in config file)\n",
" -crlexts ..     - CRL extension section (override value in config file)\n",
NULL
};

#ifdef EFENCE
extern int EF_PROTECT_FREE;
extern int EF_PROTECT_BELOW;
extern int EF_ALIGNMENT;
#endif

static void lookup_fail(char *name,char *tag);
static unsigned long index_serial_hash(char **a);
static int index_serial_cmp(char **a, char **b);
static unsigned long index_name_hash(char **a);
static int index_name_qual(char **a);
static int index_name_cmp(char **a,char **b);
static BIGNUM *load_serial(char *serialfile);
static int save_serial(char *serialfile, BIGNUM *serial);
static int certify(X509 **xret, char *infile,EVP_PKEY *pkey,X509 *x509,
		   const EVP_MD *dgst,STACK_OF(CONF_VALUE) *policy,TXT_DB *db,
		   BIGNUM *serial, char *startdate,char *enddate, int days,
		   int batch, char *ext_sect, LHASH *conf,int verbose);
static int certify_cert(X509 **xret, char *infile,EVP_PKEY *pkey,X509 *x509,
			const EVP_MD *dgst,STACK_OF(CONF_VALUE) *policy,
			TXT_DB *db, BIGNUM *serial,char *startdate,
			char *enddate, int days, int batch, char *ext_sect,
			LHASH *conf,int verbose);
static int certify_spkac(X509 **xret, char *infile,EVP_PKEY *pkey,X509 *x509,
			 const EVP_MD *dgst,STACK_OF(CONF_VALUE) *policy,
			 TXT_DB *db, BIGNUM *serial,char *startdate,
			 char *enddate, int days, char *ext_sect,LHASH *conf,
				int verbose);
static int fix_data(int nid, int *type);
static void write_new_certificate(BIO *bp, X509 *x, int output_der, int notext);
static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509, const EVP_MD *dgst,
	STACK_OF(CONF_VALUE) *policy, TXT_DB *db, BIGNUM *serial,
	char *startdate, char *enddate, int days, int batch, int verbose,
	X509_REQ *req, char *ext_sect, LHASH *conf);
static int do_revoke(X509 *x509, TXT_DB *db);
static int check_time_format(char *str);
static LHASH *conf=NULL;
static char *section=NULL;

static int preserve=0;
static int msie_hack=0;

int MAIN(int, char **);

int MAIN(int argc, char **argv)
	{
	char *key=NULL,*passargin=NULL;
	int total=0;
	int total_done=0;
	int badops=0;
	int ret=1;
	int req=0;
	int verbose=0;
	int gencrl=0;
	int dorevoke=0;
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
	char *crl_ext=NULL;
	BIGNUM *serial=NULL;
	char *startdate=NULL;
	char *enddate=NULL;
	int days=0;
	int batch=0;
	int notext=0;
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
	const EVP_MD *dgst=NULL;
	STACK_OF(CONF_VALUE) *attribs=NULL;
	STACK_OF(X509) *cert_sk=NULL;
	BIO *hex=NULL;
#undef BSIZE
#define BSIZE 256
	MS_STATIC char buf[3][BSIZE];
	char *randfile=NULL;

#ifdef EFENCE
EF_PROTECT_FREE=1;
EF_PROTECT_BELOW=1;
EF_ALIGNMENT=0;
#endif

	apps_startup();

	conf = NULL;
	key = NULL;
	section = NULL;

	preserve=0;
	msie_hack=0;
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
		else if (strcmp(*argv,"-enddate") == 0)
			{
			if (--argc < 1) goto bad;
			enddate= *(++argv);
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
		else if (strcmp(*argv,"-passin") == 0)
			{
			if (--argc < 1) goto bad;
			passargin= *(++argv);
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
		else if (strcmp(*argv,"-notext") == 0)
			notext=1;
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
		else if (strcmp(*argv,"-revoke") == 0)
			{
			if (--argc < 1) goto bad;
			infile= *(++argv);
			dorevoke=1;
			}
		else if (strcmp(*argv,"-extensions") == 0)
			{
			if (--argc < 1) goto bad;
			extensions= *(++argv);
			}
		else if (strcmp(*argv,"-crlexts") == 0)
			{
			if (--argc < 1) goto bad;
			crl_ext= *(++argv);
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
	if (configfile == NULL) configfile = getenv("OPENSSL_CONF");
	if (configfile == NULL) configfile = getenv("SSLEAY_CONF");
	if (configfile == NULL)
		{
		/* We will just use 'buf[0]' as a temporary buffer.  */
#ifdef VMS
		strncpy(buf[0],X509_get_default_cert_area(),
			sizeof(buf[0])-1-sizeof(CONFIG_FILE));
#else
		strncpy(buf[0],X509_get_default_cert_area(),
			sizeof(buf[0])-2-sizeof(CONFIG_FILE));
		strcat(buf[0],"/");
#endif
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

	if (conf != NULL)
		{
		p=CONF_get_string(conf,NULL,"oid_file");
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
				ERR_clear_error();
				}
			else
				{
				OBJ_create_objects(oid_bio);
				BIO_free(oid_bio);
				}
			}
		if(!add_oid_section(bio_err,conf)) 
			{
			ERR_print_errors(bio_err);
			goto err;
			}
		}

	randfile = CONF_get_string(conf, BASE_SECTION, "RANDFILE");
	app_RAND_load_file(randfile, bio_err, 0);
	
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
	/* we definitely need an public key, so lets get it */

	if ((keyfile == NULL) && ((keyfile=CONF_get_string(conf,
		section,ENV_PRIVATE_KEY)) == NULL))
		{
		lookup_fail(section,ENV_PRIVATE_KEY);
		goto err;
		}
	if(!key && !app_passwd(bio_err, passargin, NULL, &key, NULL))
		{
		BIO_printf(bio_err,"Error getting password\n");
		goto err;
		}
	if (BIO_read_filename(in,keyfile) <= 0)
		{
		perror(keyfile);
		BIO_printf(bio_err,"trying to load CA private key\n");
		goto err;
		}
		pkey=PEM_read_bio_PrivateKey(in,NULL,NULL,key);
		if(key) memset(key,0,strlen(key));
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
	x509=PEM_read_bio_X509(in,NULL,NULL,NULL);
	if (x509 == NULL)
		{
		BIO_printf(bio_err,"unable to load CA certificate\n");
		goto err;
		}

	if (!X509_check_private_key(x509,pkey))
		{
		BIO_printf(bio_err,"CA certificate and CA private key do not match\n");
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
#ifndef VMS /* outdir is a directory spec, but access() for VMS demands a
	       filename.  In any case, stat(), below, will catch the problem
	       if outdir is not a directory spec, and the fopen() or open()
	       will catch an error if there is no write access.

	       Presumably, this problem could also be solved by using the DEC
	       C routines to convert the directory syntax to Unixly, and give
	       that to access().  However, time's too short to do that just
	       now.
            */
		if (access(outdir,R_OK|W_OK|X_OK) != 0)
			{
			BIO_printf(bio_err,"I am unable to access the %s directory\n",outdir);
			perror(outdir);
			goto err;
			}

		if (stat(outdir,&sb) != 0)
			{
			BIO_printf(bio_err,"unable to stat(%s)\n",outdir);
			perror(outdir);
			goto err;
			}
#ifdef S_IFDIR
		if (!(sb.st_mode & S_IFDIR))
			{
			BIO_printf(bio_err,"%s need to be a directory\n",outdir);
			perror(outdir);
			goto err;
			}
#endif
#endif
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
			BIO_printf(bio_err,"entry %d: not revoked yet, but has a revocation date\n",i+1);
			goto err;
			}
		if ((pp[DB_type][0] == DB_TYPE_REV) &&
			!check_time_format(pp[DB_rev_date]))
			{
			BIO_printf(bio_err,"entry %d: invalid revocation date\n",
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
#ifdef VMS
		{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
		}
#endif
		TXT_DB_write(out,db);
		BIO_printf(bio_err,"%d entries loaded from the database\n",
			db->data->num);
		BIO_printf(bio_err,"generating index\n");
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
			{
			BIO_set_fp(Sout,stdout,BIO_NOCLOSE|BIO_FP_TEXT);
#ifdef VMS
			{
			BIO *tmpbio = BIO_new(BIO_f_linebuffer());
			Sout = BIO_push(tmpbio, Sout);
			}
#endif
			}
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
		if(!extensions)
			extensions=CONF_get_string(conf,section,ENV_EXTENSIONS);
		if(extensions) {
			/* Check syntax of file */
			X509V3_CTX ctx;
			X509V3_set_ctx_test(&ctx);
			X509V3_set_conf_lhash(&ctx, conf);
			if(!X509V3_EXT_add_conf(conf, &ctx, extensions, NULL)) {
				BIO_printf(bio_err,
				 "Error Loading extension section %s\n",
								 extensions);
				ret = 1;
				goto err;
			}
		}

		if (startdate == NULL)
			{
			startdate=CONF_get_string(conf,section,
				ENV_DEFAULT_STARTDATE);
			}
		if (startdate && !ASN1_UTCTIME_set_string(NULL,startdate))
			{
			BIO_printf(bio_err,"start date is invalid, it should be YYMMDDHHMMSSZ\n");
			goto err;
			}
		if (startdate == NULL) startdate="today";

		if (enddate == NULL)
			{
			enddate=CONF_get_string(conf,section,
				ENV_DEFAULT_ENDDATE);
			}
		if (enddate && !ASN1_UTCTIME_set_string(NULL,enddate))
			{
			BIO_printf(bio_err,"end date is invalid, it should be YYMMDDHHMMSSZ\n");
			goto err;
			}

		if (days == 0)
			{
			days=(int)CONF_get_number(conf,section,
				ENV_DEFAULT_DAYS);
			}
		if (!enddate && (days == 0))
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
			if ((f=BN_bn2hex(serial)) == NULL) goto err;
			BIO_printf(bio_err,"next serial number is %s\n",f);
			OPENSSL_free(f);
			}

		if ((attribs=CONF_get_section(conf,policy)) == NULL)
			{
			BIO_printf(bio_err,"unable to find 'section' for %s\n",policy);
			goto err;
			}

		if ((cert_sk=sk_X509_new_null()) == NULL)
			{
			BIO_printf(bio_err,"Memory allocation failure\n");
			goto err;
			}
		if (spkac_file != NULL)
			{
			total++;
			j=certify_spkac(&x,spkac_file,pkey,x509,dgst,attribs,db,
				serial,startdate,enddate, days,extensions,conf,
				verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_X509_push(cert_sk,x))
					{
					BIO_printf(bio_err,"Memory allocation failure\n");
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
				db,serial,startdate,enddate,days,batch,
				extensions,conf,verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_X509_push(cert_sk,x))
					{
					BIO_printf(bio_err,"Memory allocation failure\n");
					goto err;
					}
				}
			}
		if (infile != NULL)
			{
			total++;
			j=certify(&x,infile,pkey,x509,dgst,attribs,db,
				serial,startdate,enddate,days,batch,
				extensions,conf,verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_X509_push(cert_sk,x))
					{
					BIO_printf(bio_err,"Memory allocation failure\n");
					goto err;
					}
				}
			}
		for (i=0; i<argc; i++)
			{
			total++;
			j=certify(&x,argv[i],pkey,x509,dgst,attribs,db,
				serial,startdate,enddate,days,batch,
				extensions,conf,verbose);
			if (j < 0) goto err;
			if (j > 0)
				{
				total_done++;
				BIO_printf(bio_err,"\n");
				if (!BN_add_word(serial,1)) goto err;
				if (!sk_X509_push(cert_sk,x))
					{
					BIO_printf(bio_err,"Memory allocation failure\n");
					goto err;
					}
				}
			}	
		/* we have a stack of newly certified certificates
		 * and a data base and serial number that need
		 * updating */

		if (sk_X509_num(cert_sk) > 0)
			{
			if (!batch)
				{
				BIO_printf(bio_err,"\n%d out of %d certificate requests certified, commit? [y/n]",total_done,total);
				(void)BIO_flush(bio_err);
				buf[0][0]='\0';
				fgets(buf[0],10,stdin);
				if ((buf[0][0] != 'y') && (buf[0][0] != 'Y'))
					{
					BIO_printf(bio_err,"CERTIFICATION CANCELED\n"); 
					ret=0;
					goto err;
					}
				}

			BIO_printf(bio_err,"Write out database with %d new entries\n",sk_X509_num(cert_sk));

			strncpy(buf[0],serialfile,BSIZE-4);

#ifdef VMS
			strcat(buf[0],"-new");
#else
			strcat(buf[0],".new");
#endif

			if (!save_serial(buf[0],serial)) goto err;

			strncpy(buf[1],dbfile,BSIZE-4);

#ifdef VMS
			strcat(buf[1],"-new");
#else
			strcat(buf[1],".new");
#endif

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
		for (i=0; i<sk_X509_num(cert_sk); i++)
			{
			int k;
			unsigned char *n;

			x=sk_X509_value(cert_sk,i);

			j=x->cert_info->serialNumber->length;
			p=(char *)x->cert_info->serialNumber->data;
			
			strncpy(buf[2],outdir,BSIZE-(j*2)-6);

#ifndef VMS
			strcat(buf[2],"/");
#endif

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
			write_new_certificate(Cout,x, 0, notext);
			write_new_certificate(Sout,x, output_der, notext);
			}

		if (sk_X509_num(cert_sk))
			{
			/* Rename the database and the serial file */
			strncpy(buf[2],serialfile,BSIZE-4);

#ifdef VMS
			strcat(buf[2],"-old");
#else
			strcat(buf[2],".old");
#endif

			BIO_free(in);
			BIO_free_all(out);
			in=NULL;
			out=NULL;
			if (rename(serialfile,buf[2]) < 0)
				{
				BIO_printf(bio_err,"unable to rename %s to %s\n",
					serialfile,buf[2]);
				perror("reason");
				goto err;
				}
			if (rename(buf[0],serialfile) < 0)
				{
				BIO_printf(bio_err,"unable to rename %s to %s\n",
					buf[0],serialfile);
				perror("reason");
				rename(buf[2],serialfile);
				goto err;
				}

			strncpy(buf[2],dbfile,BSIZE-4);

#ifdef VMS
			strcat(buf[2],"-old");
#else
			strcat(buf[2],".old");
#endif

			if (rename(dbfile,buf[2]) < 0)
				{
				BIO_printf(bio_err,"unable to rename %s to %s\n",
					dbfile,buf[2]);
				perror("reason");
				goto err;
				}
			if (rename(buf[1],dbfile) < 0)
				{
				BIO_printf(bio_err,"unable to rename %s to %s\n",
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
		if(!crl_ext) crl_ext=CONF_get_string(conf,section,ENV_CRLEXT);
		if(crl_ext) {
			/* Check syntax of file */
			X509V3_CTX ctx;
			X509V3_set_ctx_test(&ctx);
			X509V3_set_conf_lhash(&ctx, conf);
			if(!X509V3_EXT_add_conf(conf, &ctx, crl_ext, NULL)) {
				BIO_printf(bio_err,
				 "Error Loading CRL extension section %s\n",
								 crl_ext);
				ret = 1;
				goto err;
			}
		}
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

				(void)BIO_reset(hex);
				if (!BIO_puts(hex,pp[DB_serial]))
					goto err;
				if (!a2i_ASN1_INTEGER(hex,r->serialNumber,
					buf[0],BSIZE)) goto err;

				sk_X509_REVOKED_push(ci->revoked,r);
				}
			}
		/* sort the data so it will be written in serial
		 * number order */
		sk_X509_REVOKED_sort(ci->revoked);
		for (i=0; i<sk_X509_REVOKED_num(ci->revoked); i++)
			{
			r=sk_X509_REVOKED_value(ci->revoked,i);
			r->sequence=i;
			}

		/* we now have a CRL */
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
		    {
#ifndef NO_DSA
		    if (pkey->type == EVP_PKEY_DSA) 
			dgst=EVP_dss1();
		    else
#endif
			dgst=EVP_md5();
		    }

		/* Add any extensions asked for */

		if(crl_ext) {
		    X509V3_CTX crlctx;
		    if (ci->version == NULL)
		    if ((ci->version=ASN1_INTEGER_new()) == NULL) goto err;
		    ASN1_INTEGER_set(ci->version,1); /* version 2 CRL */
		    X509V3_set_ctx(&crlctx, x509, NULL, NULL, crl, 0);
		    X509V3_set_conf_lhash(&crlctx, conf);

		    if(!X509V3_EXT_CRL_add_conf(conf, &crlctx,
						 crl_ext, crl)) goto err;
		}

		if (!X509_CRL_sign(crl,pkey,dgst)) goto err;

		PEM_write_bio_X509_CRL(Sout,crl);
		}
	/*****************************************************************/
	if (dorevoke)
		{
		if (infile == NULL) 
			{
			BIO_printf(bio_err,"no input files\n");
			goto err;
			}
		else
			{
			X509 *revcert;
			if (BIO_read_filename(in,infile) <= 0)
				{
				perror(infile);
				BIO_printf(bio_err,"error trying to load '%s' certificate\n",infile);
				goto err;
				}
			revcert=PEM_read_bio_X509(in,NULL,NULL,NULL);
			if (revcert == NULL)
				{
				BIO_printf(bio_err,"unable to load '%s' certificate\n",infile);
				goto err;
				}
			j=do_revoke(revcert,db);
			if (j <= 0) goto err;
			X509_free(revcert);

			strncpy(buf[0],dbfile,BSIZE-4);
#ifndef VMS
			strcat(buf[0],".new");
#else
			strcat(buf[0],"-new");
#endif
			if (BIO_write_filename(out,buf[0]) <= 0)
				{
				perror(dbfile);
				BIO_printf(bio_err,"unable to open '%s'\n",dbfile);
				goto err;
				}
			j=TXT_DB_write(out,db);
			if (j <= 0) goto err;
			strncpy(buf[1],dbfile,BSIZE-4);
#ifndef VMS
			strcat(buf[1],".old");
#else
			strcat(buf[1],"-old");
#endif
			if (rename(dbfile,buf[1]) < 0)
				{
				BIO_printf(bio_err,"unable to rename %s to %s\n", dbfile, buf[1]);
				perror("reason");
				goto err;
				}
			if (rename(buf[0],dbfile) < 0)
				{
				BIO_printf(bio_err,"unable to rename %s to %s\n", buf[0],dbfile);
				perror("reason");
				rename(buf[1],dbfile);
				goto err;
				}
			BIO_printf(bio_err,"Data Base Updated\n"); 
			}
		}
	/*****************************************************************/
	ret=0;
err:
	BIO_free(hex);
	BIO_free_all(Cout);
	BIO_free_all(Sout);
	BIO_free_all(out);
	BIO_free(in);

	sk_X509_pop_free(cert_sk,X509_free);

	if (ret) ERR_print_errors(bio_err);
	app_RAND_write_file(randfile, bio_err);
	BN_free(serial);
	TXT_DB_free(db);
	EVP_PKEY_free(pkey);
	X509_free(x509);
	X509_CRL_free(crl);
	CONF_free(conf);
	OBJ_cleanup();
	EXIT(ret);
	}

static void lookup_fail(char *name, char *tag)
	{
	BIO_printf(bio_err,"variable lookup failed for %s::%s\n",name,tag);
	}

static unsigned long index_serial_hash(char **a)
	{
	char *n;

	n=a[DB_serial];
	while (*n == '0') n++;
	return(lh_strhash(n));
	}

static int index_serial_cmp(char **a, char **b)
	{
	char *aa,*bb;

	for (aa=a[DB_serial]; *aa == '0'; aa++);
	for (bb=b[DB_serial]; *bb == '0'; bb++);
	return(strcmp(aa,bb));
	}

static unsigned long index_name_hash(char **a)
	{ return(lh_strhash(a[DB_name])); }

static int index_name_qual(char **a)
	{ return(a[0][0] == 'V'); }

static int index_name_cmp(char **a, char **b)
	{ return(strcmp(a[DB_name],
	     b[DB_name])); }

static BIGNUM *load_serial(char *serialfile)
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

static int save_serial(char *serialfile, BIGNUM *serial)
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
	if (out != NULL) BIO_free_all(out);
	if (ai != NULL) ASN1_INTEGER_free(ai);
	return(ret);
	}

static int certify(X509 **xret, char *infile, EVP_PKEY *pkey, X509 *x509,
	     const EVP_MD *dgst, STACK_OF(CONF_VALUE) *policy, TXT_DB *db,
	     BIGNUM *serial, char *startdate, char *enddate, int days,
	     int batch, char *ext_sect, LHASH *lconf, int verbose)
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
	if ((req=PEM_read_bio_X509_REQ(in,NULL,NULL,NULL)) == NULL)
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
	EVP_PKEY_free(pktmp);
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

	ok=do_body(xret,pkey,x509,dgst,policy,db,serial,startdate, enddate,
		days,batch,verbose,req,ext_sect,lconf);

err:
	if (req != NULL) X509_REQ_free(req);
	if (in != NULL) BIO_free(in);
	return(ok);
	}

static int certify_cert(X509 **xret, char *infile, EVP_PKEY *pkey, X509 *x509,
	     const EVP_MD *dgst, STACK_OF(CONF_VALUE) *policy, TXT_DB *db,
	     BIGNUM *serial, char *startdate, char *enddate, int days,
	     int batch, char *ext_sect, LHASH *lconf, int verbose)
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
	if ((req=PEM_read_bio_X509(in,NULL,NULL,NULL)) == NULL)
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
	EVP_PKEY_free(pktmp);
	if (i < 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature verification problems....\n");
		goto err;
		}
	if (i == 0)
		{
		ok=0;
		BIO_printf(bio_err,"Signature did not match the certificate\n");
		goto err;
		}
	else
		BIO_printf(bio_err,"Signature ok\n");

	if ((rreq=X509_to_X509_REQ(req,NULL,EVP_md5())) == NULL)
		goto err;

	ok=do_body(xret,pkey,x509,dgst,policy,db,serial,startdate,enddate,days,
		batch,verbose,rreq,ext_sect,lconf);

err:
	if (rreq != NULL) X509_REQ_free(rreq);
	if (req != NULL) X509_free(req);
	if (in != NULL) BIO_free(in);
	return(ok);
	}

static int do_body(X509 **xret, EVP_PKEY *pkey, X509 *x509, const EVP_MD *dgst,
	     STACK_OF(CONF_VALUE) *policy, TXT_DB *db, BIGNUM *serial,
	     char *startdate, char *enddate, int days, int batch, int verbose,
	     X509_REQ *req, char *ext_sect, LHASH *lconf)
	{
	X509_NAME *name=NULL,*CAname=NULL,*subject=NULL;
	ASN1_UTCTIME *tm,*tmptm;
	ASN1_STRING *str,*str2;
	ASN1_OBJECT *obj;
	X509 *ret=NULL;
	X509_CINF *ci;
	X509_NAME_ENTRY *ne;
	X509_NAME_ENTRY *tne,*push;
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
		BIO_printf(bio_err,"Memory allocation failure\n");
		goto err;
		}

	/* take a copy of the issuer name before we mess with it. */
	CAname=X509_NAME_dup(x509->cert_info->subject);
	if (CAname == NULL) goto err;
	str=str2=NULL;

	for (i=0; i<sk_CONF_VALUE_num(policy); i++)
		{
		cv=sk_CONF_VALUE_value(policy,i); /* get the object id */
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
					BIO_printf(bio_err,"The %s field needed to be the same in the\nCA certificate (%s) and the request (%s)\n",cv->name,((str2 == NULL)?"NULL":(char *)str2->data),((str == NULL)?"NULL":(char *)str->data));
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
				if (!X509_NAME_add_entry(subject,push, -1, 0))
					{
					if (push != NULL)
						X509_NAME_ENTRY_free(push);
					BIO_printf(bio_err,"Memory allocation failure\n");
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
		BIO_printf(bio_err,"The subject name appears to be ok, checking data base for clashes\n");

	row[DB_name]=X509_NAME_oneline(subject,NULL,0);
	row[DB_serial]=BN_bn2hex(serial);
	if ((row[DB_name] == NULL) || (row[DB_serial] == NULL))
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
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
		BIO_printf(bio_err,"Type	  :%s\n",p);;
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

	/* We are now totally happy, lets make and sign the certificate */
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
		X509_gmtime_adj(X509_get_notBefore(ret),0);
	else ASN1_UTCTIME_set_string(X509_get_notBefore(ret),startdate);

	if (enddate == NULL)
		X509_gmtime_adj(X509_get_notAfter(ret),(long)60*60*24*days);
	else ASN1_UTCTIME_set_string(X509_get_notAfter(ret),enddate);

	ASN1_UTCTIME_print(bio_err,X509_get_notAfter(ret));
	if(days) BIO_printf(bio_err," (%d days)",days);
	BIO_printf(bio_err, "\n");

	if (!X509_set_subject_name(ret,subject)) goto err;

	pktmp=X509_REQ_get_pubkey(req);
	i = X509_set_pubkey(ret,pktmp);
	EVP_PKEY_free(pktmp);
	if (!i) goto err;

	/* Lets add the extensions, if there are any */
	if (ext_sect)
		{
		X509V3_CTX ctx;
		if (ci->version == NULL)
			if ((ci->version=ASN1_INTEGER_new()) == NULL)
				goto err;
		ASN1_INTEGER_set(ci->version,2); /* version 3 certificate */

		/* Free the current entries if any, there should not
		 * be any I believe */
		if (ci->extensions != NULL)
			sk_X509_EXTENSION_pop_free(ci->extensions,
						   X509_EXTENSION_free);

		ci->extensions = NULL;

		X509V3_set_ctx(&ctx, x509, ret, req, NULL, 0);
		X509V3_set_conf_lhash(&ctx, lconf);

		if(!X509V3_EXT_add_conf(lconf, &ctx, ext_sect, ret)) goto err;

		}


	if (!batch)
		{
		BIO_printf(bio_err,"Sign the certificate? [y/n]:");
		(void)BIO_flush(bio_err);
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
	if (pkey->type == EVP_PKEY_DSA) dgst=EVP_dss1();
	pktmp=X509_get_pubkey(ret);
	if (EVP_PKEY_missing_parameters(pktmp) &&
		!EVP_PKEY_missing_parameters(pkey))
		EVP_PKEY_copy_parameters(pktmp,pkey);
	EVP_PKEY_free(pktmp);
#endif

	if (!X509_sign(ret,pkey,dgst))
		goto err;

	/* We now just add it to the database */
	row[DB_type]=(char *)OPENSSL_malloc(2);

	tm=X509_get_notAfter(ret);
	row[DB_exp_date]=(char *)OPENSSL_malloc(tm->length+1);
	memcpy(row[DB_exp_date],tm->data,tm->length);
	row[DB_exp_date][tm->length]='\0';

	row[DB_rev_date]=NULL;

	/* row[DB_serial] done already */
	row[DB_file]=(char *)OPENSSL_malloc(8);
	/* row[DB_name] done already */

	if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
		(row[DB_file] == NULL))
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
		goto err;
		}
	strcpy(row[DB_file],"unknown");
	row[DB_type][0]='V';
	row[DB_type][1]='\0';

	if ((irow=(char **)OPENSSL_malloc(sizeof(char *)*(DB_NUMBER+1))) == NULL)
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
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
		if (row[i] != NULL) OPENSSL_free(row[i]);

	if (CAname != NULL)
		X509_NAME_free(CAname);
	if (subject != NULL)
		X509_NAME_free(subject);
	if (tmptm != NULL)
		ASN1_UTCTIME_free(tmptm);
	if (ok <= 0)
		{
		if (ret != NULL) X509_free(ret);
		ret=NULL;
		}
	else
		*xret=ret;
	return(ok);
	}

static void write_new_certificate(BIO *bp, X509 *x, int output_der, int notext)
	{

	if (output_der)
		{
		(void)i2d_X509_bio(bp,x);
		return;
		}
#if 0
	/* ??? Not needed since X509_print prints all this stuff anyway */
	f=X509_NAME_oneline(X509_get_issuer_name(x),buf,256);
	BIO_printf(bp,"issuer :%s\n",f);

	f=X509_NAME_oneline(X509_get_subject_name(x),buf,256);
	BIO_printf(bp,"subject:%s\n",f);

	BIO_puts(bp,"serial :");
	i2a_ASN1_INTEGER(bp,x->cert_info->serialNumber);
	BIO_puts(bp,"\n\n");
#endif
	if(!notext)X509_print(bp,x);
	PEM_write_bio_X509(bp,x);
	}

static int certify_spkac(X509 **xret, char *infile, EVP_PKEY *pkey, X509 *x509,
	     const EVP_MD *dgst, STACK_OF(CONF_VALUE) *policy, TXT_DB *db,
	     BIGNUM *serial, char *startdate, char *enddate, int days,
	     char *ext_sect, LHASH *lconf, int verbose)
	{
	STACK_OF(CONF_VALUE) *sk=NULL;
	LHASH *parms=NULL;
	X509_REQ *req=NULL;
	CONF_VALUE *cv=NULL;
	NETSCAPE_SPKI *spki = NULL;
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
	if (sk_CONF_VALUE_num(sk) == 0)
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
		if (sk_CONF_VALUE_num(sk) <= i) break;

		cv=sk_CONF_VALUE_value(sk,i);
		type=cv->name;
		/* Skip past any leading X. X: X, etc to allow for
		 * multiple instances
		 */
		for(buf = cv->name; *buf ; buf++)
			if ((*buf == ':') || (*buf == ',') || (*buf == '.')) {
					buf++;
					if(*buf) type = buf;
					break;
		}

		buf=cv->value;
		if ((nid=OBJ_txt2nid(type)) == NID_undef)
			{
			if (strcmp(type, "SPKAC") == 0)
				{
				spki = NETSCAPE_SPKI_b64_decode(cv->value, -1);
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

		if (!X509_NAME_add_entry(n,ne,-1, 0)) goto err;
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

	if ((pktmp=NETSCAPE_SPKI_get_pubkey(spki)) == NULL)
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
	EVP_PKEY_free(pktmp);
	ok=do_body(xret,pkey,x509,dgst,policy,db,serial,startdate,enddate,
		   days,1,verbose,req,ext_sect,lconf);
err:
	if (req != NULL) X509_REQ_free(req);
	if (parms != NULL) CONF_free(parms);
	if (spki != NULL) NETSCAPE_SPKI_free(spki);
	if (ne != NULL) X509_NAME_ENTRY_free(ne);

	return(ok);
	}

static int fix_data(int nid, int *type)
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

static int check_time_format(char *str)
	{
	ASN1_UTCTIME tm;

	tm.data=(unsigned char *)str;
	tm.length=strlen(str);
	tm.type=V_ASN1_UTCTIME;
	return(ASN1_UTCTIME_check(&tm));
	}

static int do_revoke(X509 *x509, TXT_DB *db)
{
	ASN1_UTCTIME *tm=NULL, *revtm=NULL;
	char *row[DB_NUMBER],**rrow,**irow;
	BIGNUM *bn = NULL;
	int ok=-1,i;

	for (i=0; i<DB_NUMBER; i++)
		row[i]=NULL;
	row[DB_name]=X509_NAME_oneline(X509_get_subject_name(x509),NULL,0);
	bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x509),NULL);
	row[DB_serial]=BN_bn2hex(bn);
	BN_free(bn);
	if ((row[DB_name] == NULL) || (row[DB_serial] == NULL))
		{
		BIO_printf(bio_err,"Memory allocation failure\n");
		goto err;
		}
	/* We have to lookup by serial number because name lookup
	 * skips revoked certs
 	 */
	rrow=TXT_DB_get_by_index(db,DB_serial,row);
	if (rrow == NULL)
		{
		BIO_printf(bio_err,"Adding Entry to DB for %s\n", row[DB_name]);

		/* We now just add it to the database */
		row[DB_type]=(char *)OPENSSL_malloc(2);

		tm=X509_get_notAfter(x509);
		row[DB_exp_date]=(char *)OPENSSL_malloc(tm->length+1);
		memcpy(row[DB_exp_date],tm->data,tm->length);
		row[DB_exp_date][tm->length]='\0';

		row[DB_rev_date]=NULL;

		/* row[DB_serial] done already */
		row[DB_file]=(char *)OPENSSL_malloc(8);

		/* row[DB_name] done already */

		if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
			(row[DB_file] == NULL))
			{
			BIO_printf(bio_err,"Memory allocation failure\n");
			goto err;
			}
		strcpy(row[DB_file],"unknown");
		row[DB_type][0]='V';
		row[DB_type][1]='\0';

		if ((irow=(char **)OPENSSL_malloc(sizeof(char *)*(DB_NUMBER+1))) == NULL)
			{
			BIO_printf(bio_err,"Memory allocation failure\n");
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

		/* Revoke Certificate */
		ok = do_revoke(x509,db);

		goto err;

		}
	else if (index_name_cmp(row,rrow))
		{
		BIO_printf(bio_err,"ERROR:name does not match %s\n",
			   row[DB_name]);
		goto err;
		}
	else if (rrow[DB_type][0]=='R')
		{
		BIO_printf(bio_err,"ERROR:Already revoked, serial number %s\n",
			   row[DB_serial]);
		goto err;
		}
	else
		{
		BIO_printf(bio_err,"Revoking Certificate %s.\n", rrow[DB_serial]);
		revtm = ASN1_UTCTIME_new();
		revtm=X509_gmtime_adj(revtm,0);
		rrow[DB_type][0]='R';
		rrow[DB_type][1]='\0';
		rrow[DB_rev_date]=(char *)OPENSSL_malloc(revtm->length+1);
		memcpy(rrow[DB_rev_date],revtm->data,revtm->length);
		rrow[DB_rev_date][revtm->length]='\0';
		ASN1_UTCTIME_free(revtm);
		}
	ok=1;
err:
	for (i=0; i<DB_NUMBER; i++)
		{
		if (row[i] != NULL) 
			OPENSSL_free(row[i]);
		}
	return(ok);
}

