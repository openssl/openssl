/* apps/apps.c */
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
#include <sys/types.h>
#include <sys/stat.h>
#define NON_MAIN
#include "apps.h"
#undef NON_MAIN
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>

#ifdef WINDOWS
#  include "bss_file.c"
#endif

int app_init(long mesgwin);
#ifdef undef /* never finished - probably never will be :-) */
int args_from_file(char *file, int *argc, char **argv[])
	{
	FILE *fp;
	int num,i;
	unsigned int len;
	static char *buf=NULL;
	static char **arg=NULL;
	char *p;
	struct stat stbuf;

	if (stat(file,&stbuf) < 0) return(0);

	fp=fopen(file,"r");
	if (fp == NULL)
		return(0);

	*argc=0;
	*argv=NULL;

	len=(unsigned int)stbuf.st_size;
	if (buf != NULL) OPENSSL_free(buf);
	buf=(char *)OPENSSL_malloc(len+1);
	if (buf == NULL) return(0);

	len=fread(buf,1,len,fp);
	if (len <= 1) return(0);
	buf[len]='\0';

	i=0;
	for (p=buf; *p; p++)
		if (*p == '\n') i++;
	if (arg != NULL) OPENSSL_free(arg);
	arg=(char **)OPENSSL_malloc(sizeof(char *)*(i*2));

	*argv=arg;
	num=0;
	p=buf;
	for (;;)
		{
		if (!*p) break;
		if (*p == '#') /* comment line */
			{
			while (*p && (*p != '\n')) p++;
			continue;
			}
		/* else we have a line */
		*(arg++)=p;
		num++;
		while (*p && ((*p != ' ') && (*p != '\t') && (*p != '\n')))
			p++;
		if (!*p) break;
		if (*p == '\n')
			{
			*(p++)='\0';
			continue;
			}
		/* else it is a tab or space */
		p++;
		while (*p && ((*p == ' ') || (*p == '\t') || (*p == '\n')))
			p++;
		if (!*p) break;
		if (*p == '\n')
			{
			p++;
			continue;
			}
		*(arg++)=p++;
		num++;
		while (*p && (*p != '\n')) p++;
		if (!*p) break;
		/* else *p == '\n' */
		*(p++)='\0';
		}
	*argc=num;
	return(1);
	}
#endif

int str2fmt(char *s)
	{
	if 	((*s == 'D') || (*s == 'd'))
		return(FORMAT_ASN1);
	else if ((*s == 'T') || (*s == 't'))
		return(FORMAT_TEXT);
	else if ((*s == 'P') || (*s == 'p'))
		return(FORMAT_PEM);
	else if ((*s == 'N') || (*s == 'n'))
		return(FORMAT_NETSCAPE);
	else if ((*s == 'S') || (*s == 's'))
		return(FORMAT_SMIME);
	else if ((*s == '1')
		|| (strcmp(s,"PKCS12") == 0) || (strcmp(s,"pkcs12") == 0)
		|| (strcmp(s,"P12") == 0) || (strcmp(s,"p12") == 0))
		return(FORMAT_PKCS12);
	else
		return(FORMAT_UNDEF);
	}

#if defined(MSDOS) || defined(WIN32) || defined(WIN16)
void program_name(char *in, char *out, int size)
	{
	int i,n;
	char *p=NULL;

	n=strlen(in);
	/* find the last '/', '\' or ':' */
	for (i=n-1; i>0; i--)
		{
		if ((in[i] == '/') || (in[i] == '\\') || (in[i] == ':'))
			{
			p= &(in[i+1]);
			break;
			}
		}
	if (p == NULL)
		p=in;
	n=strlen(p);
	/* strip off trailing .exe if present. */
	if ((n > 4) && (p[n-4] == '.') &&
		((p[n-3] == 'e') || (p[n-3] == 'E')) &&
		((p[n-2] == 'x') || (p[n-2] == 'X')) &&
		((p[n-1] == 'e') || (p[n-1] == 'E')))
		n-=4;
	if (n > size-1)
		n=size-1;

	for (i=0; i<n; i++)
		{
		if ((p[i] >= 'A') && (p[i] <= 'Z'))
			out[i]=p[i]-'A'+'a';
		else
			out[i]=p[i];
		}
	out[n]='\0';
	}
#else
#ifdef VMS
void program_name(char *in, char *out, int size)
	{
	char *p=in, *q;
	char *chars=":]>";

	while(*chars != '\0')
		{
		q=strrchr(p,*chars);
		if (q > p)
			p = q + 1;
		chars++;
		}

	q=strrchr(p,'.');
	if (q == NULL)
		q = in+size;
	strncpy(out,p,q-p);
	out[q-p]='\0';
	}
#else
void program_name(char *in, char *out, int size)
	{
	char *p;

	p=strrchr(in,'/');
	if (p != NULL)
		p++;
	else
		p=in;
	strncpy(out,p,size-1);
	out[size-1]='\0';
	}
#endif
#endif

#ifdef WIN32
int WIN32_rename(char *from, char *to)
	{
#ifdef WINNT
	int ret;
/* Note: MoveFileEx() doesn't work under Win95, Win98 */

	ret=MoveFileEx(from,to,MOVEFILE_REPLACE_EXISTING|MOVEFILE_COPY_ALLOWED);
	return(ret?0:-1);
#else
	unlink(to);
	return MoveFile(from, to);
#endif
	}
#endif

int chopup_args(ARGS *arg, char *buf, int *argc, char **argv[])
	{
	int num,len,i;
	char *p;

	*argc=0;
	*argv=NULL;

	len=strlen(buf);
	i=0;
	if (arg->count == 0)
		{
		arg->count=20;
		arg->data=(char **)OPENSSL_malloc(sizeof(char *)*arg->count);
		}
	for (i=0; i<arg->count; i++)
		arg->data[i]=NULL;

	num=0;
	p=buf;
	for (;;)
		{
		/* first scan over white space */
		if (!*p) break;
		while (*p && ((*p == ' ') || (*p == '\t') || (*p == '\n')))
			p++;
		if (!*p) break;

		/* The start of something good :-) */
		if (num >= arg->count)
			{
			arg->count+=20;
			arg->data=(char **)OPENSSL_realloc(arg->data,
				sizeof(char *)*arg->count);
			if (argc == 0) return(0);
			}
		arg->data[num++]=p;

		/* now look for the end of this */
		if ((*p == '\'') || (*p == '\"')) /* scan for closing quote */
			{
			i= *(p++);
			arg->data[num-1]++; /* jump over quote */
			while (*p && (*p != i))
				p++;
			*p='\0';
			}
		else
			{
			while (*p && ((*p != ' ') &&
				(*p != '\t') && (*p != '\n')))
				p++;

			if (*p == '\0')
				p--;
			else
				*p='\0';
			}
		p++;
		}
	*argc=num;
	*argv=arg->data;
	return(1);
	}

#ifndef APP_INIT
int app_init(long mesgwin)
	{
	return(1);
	}
#endif


int dump_cert_text (BIO *out, X509 *x)
{
	char buf[256];
	X509_NAME_oneline(X509_get_subject_name(x),buf,256);
	BIO_puts(out,"subject=");
	BIO_puts(out,buf);

	X509_NAME_oneline(X509_get_issuer_name(x),buf,256);
	BIO_puts(out,"\nissuer= ");
	BIO_puts(out,buf);
	BIO_puts(out,"\n");
        return 0;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio);

int app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2)
{
	int same;
	if(!arg2 || !arg1 || strcmp(arg1, arg2)) same = 0;
	else same = 1;
	if(arg1) {
		*pass1 = app_get_pass(err, arg1, same);
		if(!*pass1) return 0;
	} else if(pass1) *pass1 = NULL;
	if(arg2) {
		*pass2 = app_get_pass(err, arg2, same ? 2 : 0);
		if(!*pass2) return 0;
	} else if(pass2) *pass2 = NULL;
	return 1;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio)
{
	char *tmp, tpass[APP_PASS_LEN];
	static BIO *pwdbio = NULL;
	int i;
	if(!strncmp(arg, "pass:", 5)) return BUF_strdup(arg + 5);
	if(!strncmp(arg, "env:", 4)) {
		tmp = getenv(arg + 4);
		if(!tmp) {
			BIO_printf(err, "Can't read environment variable %s\n", arg + 4);
			return NULL;
		}
		return BUF_strdup(tmp);
	}
	if(!keepbio || !pwdbio) {
		if(!strncmp(arg, "file:", 5)) {
			pwdbio = BIO_new_file(arg + 5, "r");
			if(!pwdbio) {
				BIO_printf(err, "Can't open file %s\n", arg + 5);
				return NULL;
			}
		} else if(!strncmp(arg, "fd:", 3)) {
			BIO *btmp;
			i = atoi(arg + 3);
			if(i >= 0) pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
			if((i < 0) || !pwdbio) {
				BIO_printf(err, "Can't access file descriptor %s\n", arg + 3);
				return NULL;
			}
			/* Can't do BIO_gets on an fd BIO so add a buffering BIO */
			btmp = BIO_new(BIO_f_buffer());
			pwdbio = BIO_push(btmp, pwdbio);
		} else if(!strcmp(arg, "stdin")) {
			pwdbio = BIO_new_fp(stdin, BIO_NOCLOSE);
			if(!pwdbio) {
				BIO_printf(err, "Can't open BIO for stdin\n");
				return NULL;
			}
		} else {
			BIO_printf(err, "Invalid password argument \"%s\"\n", arg);
			return NULL;
		}
	}
	i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
	if(keepbio != 1) {
		BIO_free_all(pwdbio);
		pwdbio = NULL;
	}
	if(i <= 0) {
		BIO_printf(err, "Error reading password from BIO\n");
		return NULL;
	}
	tmp = strchr(tpass, '\n');
	if(tmp) *tmp = 0;
	return BUF_strdup(tpass);
}

int add_oid_section(BIO *err, LHASH *conf)
{	
	char *p;
	STACK_OF(CONF_VALUE) *sktmp;
	CONF_VALUE *cnf;
	int i;
	if(!(p=CONF_get_string(conf,NULL,"oid_section"))) return 1;
	if(!(sktmp = CONF_get_section(conf, p))) {
		BIO_printf(err, "problem loading oid section %s\n", p);
		return 0;
	}
	for(i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
		cnf = sk_CONF_VALUE_value(sktmp, i);
		if(OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
			BIO_printf(err, "problem creating object %s=%s\n",
							 cnf->name, cnf->value);
			return 0;
		}
	}
	return 1;
}

X509 *load_cert(BIO *err, char *file, int format)
	{
	ASN1_HEADER *ah=NULL;
	BUF_MEM *buf=NULL;
	X509 *x=NULL;
	BIO *cert;

	if ((cert=BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(err);
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
			(strncmp(NETSCAPE_CERT_HDR,(char *)ah->header->data,
			ah->header->length) != 0))
			{
			BIO_printf(err,"Error reading header on certificate\n");
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
		x=PEM_read_bio_X509_AUX(cert,NULL,NULL,NULL);
	else if (format == FORMAT_PKCS12)
		{
		PKCS12 *p12 = d2i_PKCS12_bio(cert, NULL);

		PKCS12_parse(p12, NULL, NULL, &x, NULL);
		PKCS12_free(p12);
		p12 = NULL;
		}
	else	{
		BIO_printf(err,"bad input format specified for input cert\n");
		goto end;
		}
end:
	if (x == NULL)
		{
		BIO_printf(err,"unable to load certificate\n");
		ERR_print_errors(err);
		}
	if (ah != NULL) ASN1_HEADER_free(ah);
	if (cert != NULL) BIO_free(cert);
	if (buf != NULL) BUF_MEM_free(buf);
	return(x);
	}

EVP_PKEY *load_key(BIO *err, char *file, int format, char *pass)
	{
	BIO *key=NULL;
	EVP_PKEY *pkey=NULL;

	if (file == NULL)
		{
		BIO_printf(err,"no keyfile specified\n");
		goto end;
		}
	key=BIO_new(BIO_s_file());
	if (key == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}
	if (BIO_read_filename(key,file) <= 0)
		{
		perror(file);
		goto end;
		}
	if (format == FORMAT_ASN1)
		{
		pkey=d2i_PrivateKey_bio(key, NULL);
		}
	else if (format == FORMAT_PEM)
		{
		pkey=PEM_read_bio_PrivateKey(key,NULL,NULL,pass);
		}
	else if (format == FORMAT_PKCS12)
		{
		PKCS12 *p12 = d2i_PKCS12_bio(key, NULL);

		PKCS12_parse(p12, pass, &pkey, NULL, NULL);
		PKCS12_free(p12);
		p12 = NULL;
		}
	else
		{
		BIO_printf(err,"bad input format specified for key\n");
		goto end;
		}
 end:
	if (key != NULL) BIO_free(key);
	if (pkey == NULL)
		BIO_printf(err,"unable to load Private Key\n");
	return(pkey);
	}

EVP_PKEY *load_pubkey(BIO *err, char *file, int format)
	{
	BIO *key=NULL;
	EVP_PKEY *pkey=NULL;

	if (file == NULL)
		{
		BIO_printf(err,"no keyfile specified\n");
		goto end;
		}
	key=BIO_new(BIO_s_file());
	if (key == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}
	if (BIO_read_filename(key,file) <= 0)
		{
		perror(file);
		goto end;
		}
	if (format == FORMAT_ASN1)
		{
		pkey=d2i_PUBKEY_bio(key, NULL);
		}
	else if (format == FORMAT_PEM)
		{
		pkey=PEM_read_bio_PUBKEY(key,NULL,NULL,NULL);
		}
	else
		{
		BIO_printf(err,"bad input format specified for key\n");
		goto end;
		}
 end:
	if (key != NULL) BIO_free(key);
	if (pkey == NULL)
		BIO_printf(err,"unable to load Public Key\n");
	return(pkey);
	}

STACK_OF(X509) *load_certs(BIO *err, char *file, int format)
	{
	BIO *certs;
	int i;
	STACK_OF(X509) *othercerts = NULL;
	STACK_OF(X509_INFO) *allcerts = NULL;
	X509_INFO *xi;

	if((certs = BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}

	if (file == NULL)
		BIO_set_fp(certs,stdin,BIO_NOCLOSE);
	else
		{
		if (BIO_read_filename(certs,file) <= 0)
			{
			perror(file);
			goto end;
			}
		}

	if      (format == FORMAT_PEM)
		{
		othercerts = sk_X509_new_null();
		if(!othercerts)
			{
			sk_X509_free(othercerts);
			othercerts = NULL;
			goto end;
			}
		allcerts = PEM_X509_INFO_read_bio(certs, NULL, NULL, NULL);
		for(i = 0; i < sk_X509_INFO_num(allcerts); i++)
			{
			xi = sk_X509_INFO_value (allcerts, i);
			if (xi->x509)
				{
				sk_X509_push(othercerts, xi->x509);
				xi->x509 = NULL;
				}
			}
		goto end;
		}
	else	{
		BIO_printf(err,"bad input format specified for input cert\n");
		goto end;
		}
end:
	if (othercerts == NULL)
		{
		BIO_printf(err,"unable to load certificates\n");
		ERR_print_errors(err);
		}
	if (allcerts) sk_X509_INFO_pop_free(allcerts, X509_INFO_free);
	if (certs != NULL) BIO_free(certs);
	return(othercerts);
	}

typedef struct {
	char *name;
	unsigned long flag;
	unsigned long mask;
} NAME_EX_TBL;

int set_name_ex(unsigned long *flags, const char *arg)
{
	char c;
	const NAME_EX_TBL *ptbl, ex_tbl[] = {
		{ "esc_2253", ASN1_STRFLGS_ESC_2253, 0},
		{ "esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
		{ "esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
		{ "use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
		{ "utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
		{ "ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
		{ "show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
		{ "dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
		{ "dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
		{ "dump_der", ASN1_STRFLGS_DUMP_DER, 0},
		{ "compat", XN_FLAG_COMPAT, 0xffffffffL},
		{ "sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
		{ "sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
		{ "sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
		{ "sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
		{ "dn_rev", XN_FLAG_DN_REV, 0},
		{ "nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
		{ "sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
		{ "lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
		{ "oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
		{ "space_eq", XN_FLAG_SPC_EQ, 0},
		{ "dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
		{ "RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
		{ "oneline", XN_FLAG_ONELINE, 0xffffffffL},
		{ "multiline", XN_FLAG_MULTILINE, 0xffffffffL},
		{ NULL, 0, 0}
	};

	c = arg[0];

	if(c == '-') {
		c = 0;
		arg++;
	} else if (c == '+') {
		c = 1;
		arg++;
	} else c = 1;

	for(ptbl = ex_tbl; ptbl->name; ptbl++) {
		if(!strcmp(arg, ptbl->name)) {
			*flags &= ~ptbl->mask;
			if(c) *flags |= ptbl->flag;
			else *flags &= ~ptbl->flag;
			return 1;
		}
	}
	return 0;
}

void print_name(BIO *out, char *title, X509_NAME *nm, unsigned long lflags)
{
	char buf[256];
	char mline = 0;
	int indent = 0;
	if(title) BIO_puts(out, title);
	if((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
		mline = 1;
		indent = 4;
	}
	if(lflags == XN_FLAG_COMPAT) {
		X509_NAME_oneline(nm,buf,256);
		BIO_puts(out,buf);
		BIO_puts(out, "\n");
	} else {
		if(mline) BIO_puts(out, "\n");
		X509_NAME_print_ex(out, nm, indent, lflags);
		BIO_puts(out, "\n");
	}
}

