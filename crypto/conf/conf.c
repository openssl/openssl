/* crypto/conf/conf.c */
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
#include <errno.h>
#include "cryptlib.h"
#include "stack.h"
#include "lhash.h"
#include "conf.h"
#include "buffer.h"
#include "err.h"

#include "conf_lcl.h"

#ifndef NOPROTO
static void value_free_hash(CONF_VALUE *a, LHASH *conf);
static void value_free_stack(CONF_VALUE *a,LHASH *conf);
static unsigned long hash(CONF_VALUE *v);
static int cmp(CONF_VALUE *a,CONF_VALUE *b);
static char *eat_ws(char *p);
static char *eat_alpha_numeric(char *p);
static void clear_comments(char *p);
static int str_copy(LHASH *conf,char *section,char **to, char *from);
static char *scan_quote(char *p);
static CONF_VALUE *new_section(LHASH *conf,char *section);
static CONF_VALUE *get_section(LHASH *conf,char *section);
#else
static void value_free_hash();
static void value_free_stack();
static unsigned long hash();
static int cmp();
static char *eat_ws();
static char *eat_alpha_numeric();
static void clear_comments();
static int str_copy();
static char *scan_quote();
static CONF_VALUE *new_section();
static CONF_VALUE *get_section();
#endif

#define scan_esc(p)	((*(++p) == '\0')?(p):(++p))

char *CONF_version="CONF part of SSLeay 0.9.0b 29-Jun-1998";

LHASH *CONF_load(h,file,line)
LHASH *h;
char *file;
long *line;
	{
	LHASH *ret=NULL;
	FILE *in=NULL;
#define BUFSIZE	512
	int bufnum=0,i,ii;
	BUF_MEM *buff=NULL;
	char *s,*p,*end;
	int again,n,eline=0;
	CONF_VALUE *v=NULL,*vv,*tv;
	CONF_VALUE *sv=NULL;
	char *section=NULL,*buf;
	STACK *section_sk=NULL,*ts;
	char *start,*psection,*pname;

	if ((buff=BUF_MEM_new()) == NULL)
		{
		CONFerr(CONF_F_CONF_LOAD,ERR_R_BUF_LIB);
		goto err;
		}

	in=fopen(file,"rb");
	if (in == NULL)
		{
		SYSerr(SYS_F_FOPEN,get_last_sys_error());
		ERR_set_error_data(BUF_strdup(file),
			ERR_TXT_MALLOCED|ERR_TXT_STRING);
		CONFerr(CONF_F_CONF_LOAD,ERR_R_SYS_LIB);
		goto err;
		}

	section=(char *)Malloc(10);
	if (section == NULL)
		{
		CONFerr(CONF_F_CONF_LOAD,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	strcpy(section,"default");

	if (h == NULL)
		{
		if ((ret=lh_new(hash,cmp)) == NULL)
			{
			CONFerr(CONF_F_CONF_LOAD,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		}
	else
		ret=h;

	sv=new_section(ret,section);
	if (sv == NULL)
		{
		CONFerr(CONF_F_CONF_LOAD,CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
		goto err;
		}
	section_sk=(STACK *)sv->value;

	bufnum=0;
	for (;;)
		{
		again=0;
		if (!BUF_MEM_grow(buff,bufnum+BUFSIZE))
			{
			CONFerr(CONF_F_CONF_LOAD,ERR_R_BUF_LIB);
			goto err;
			}
		p= &(buff->data[bufnum]);
		*p='\0';
		fgets(p,BUFSIZE-1,in);
		p[BUFSIZE-1]='\0';
		ii=i=strlen(p);
		if (i == 0) break;
		while (i > 0)
			{
			if ((p[i-1] != '\r') && (p[i-1] != '\n'))
				break;
			else
				i--;
			}
		/* we removed some trailing stuff so there is a new
		 * line on the end. */
		if (i == ii)
			again=1; /* long line */
		else
			{
			p[i]='\0';
			eline++; /* another input line */
			}

		/* we now have a line with trailing \r\n removed */

		/* i is the number of bytes */
		bufnum+=i;

		v=NULL;
		/* check for line continuation */
		if (bufnum >= 1)
			{
			/* If we have bytes and the last char '\\' and
			 * second last char is not '\\' */
			p= &(buff->data[bufnum-1]);
			if (	IS_ESC(p[0]) &&
				((bufnum <= 1) || !IS_ESC(p[-1])))
				{
				bufnum--;
				again=1;
				}
			}
		if (again) continue;
		bufnum=0;
		buf=buff->data;

		clear_comments(buf);
		n=strlen(buf);
		s=eat_ws(buf);
		if (IS_EOF(*s)) continue; /* blank line */
		if (*s == '[')
			{
			s++;
			start=eat_ws(s);
			end=eat_alpha_numeric(start);
			p=eat_ws(end);
			if (*p != ']')
				{
				CONFerr(CONF_F_CONF_LOAD,CONF_R_MISSING_CLOSE_SQUARE_BRACKET);
				goto err;
				}
			*end='\0';
			if (!str_copy(ret,NULL,&section,start)) goto err;
			if ((sv=get_section(ret,section)) == NULL)
				sv=new_section(ret,section);
			if (sv == NULL)
				{
				CONFerr(CONF_F_CONF_LOAD,CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
				goto err;
				}
			section_sk=(STACK *)sv->value;
			continue;
			}
		else
			{
			pname=s;
			psection=NULL;
			end=eat_alpha_numeric(s);
			if ((end[0] == ':') && (end[1] == ':'))
				{
				*end='\0';
				end+=2;
				psection=pname;
				pname=end;
				end=eat_alpha_numeric(end);
				}
			p=eat_ws(end);
			if (*p != '=')
				{
				CONFerr(CONF_F_CONF_LOAD,CONF_R_MISSING_EQUAL_SIGN);
				goto err;
				}
			*end='\0';
			p++;
			start=eat_ws(p);
			while (!IS_EOF(*p))
				p++;
			p--;
			while ((p != start) && (IS_WS(*p)))
				p--;
			p++;
			*p='\0';

			if ((v=(CONF_VALUE *)Malloc(sizeof(CONF_VALUE))) == NULL)
				{
				CONFerr(CONF_F_CONF_LOAD,ERR_R_MALLOC_FAILURE);
				goto err;
				}
			if (psection == NULL) psection=section;
			v->name=(char *)Malloc(strlen(pname)+1);
			v->value=NULL;
			if (v->name == NULL)
				{
				CONFerr(CONF_F_CONF_LOAD,ERR_R_MALLOC_FAILURE);
				goto err;
				}
			strcpy(v->name,pname);
			if (!str_copy(ret,psection,&(v->value),start)) goto err;

			if (strcmp(psection,section) != 0)
				{
				if ((tv=get_section(ret,psection))
					== NULL)
					tv=new_section(ret,psection);
				if (tv == NULL)
					{
					CONFerr(CONF_F_CONF_LOAD,CONF_R_UNABLE_TO_CREATE_NEW_SECTION);
					goto err;
					}
				ts=(STACK *)tv->value;
				}
			else
				{
				tv=sv;
				ts=section_sk;
				}
			v->section=tv->section;	
			if (!sk_push(ts,(char *)v))
				{
				CONFerr(CONF_F_CONF_LOAD,ERR_R_MALLOC_FAILURE);
				goto err;
				}
			vv=(CONF_VALUE *)lh_insert(ret,(char *)v);
			if (vv != NULL)
				{
				sk_delete_ptr(ts,(char *)vv);
				Free(vv->name);
				Free(vv->value);
				Free(vv);
				}
			v=NULL;
			}
		}
	if (buff != NULL) BUF_MEM_free(buff);
	if (section != NULL) Free(section);
	if (in != NULL) fclose(in);
	return(ret);
err:
	if (buff != NULL) BUF_MEM_free(buff);
	if (section != NULL) Free(section);
	if (line != NULL) *line=eline;
	if (in != NULL) fclose(in);
	if ((h != ret) && (ret != NULL)) CONF_free(ret);
	if (v != NULL)
		{
		if (v->name != NULL) Free(v->name);
		if (v->value != NULL) Free(v->value);
		if (v != NULL) Free(v);
		}
	return(NULL);
	}
		
char *CONF_get_string(conf,section,name)
LHASH *conf;
char *section;
char *name;
	{
	CONF_VALUE *v,vv;
	char *p;

	if (name == NULL) return(NULL);
	if (conf != NULL)
		{
		if (section != NULL)
			{
			vv.name=name;
			vv.section=section;
			v=(CONF_VALUE *)lh_retrieve(conf,(char *)&vv);
			if (v != NULL) return(v->value);
			if (strcmp(section,"ENV") == 0)
				{
				p=Getenv(name);
				if (p != NULL) return(p);
				}
			}
		vv.section="default";
		vv.name=name;
		v=(CONF_VALUE *)lh_retrieve(conf,(char *)&vv);
		if (v != NULL)
			return(v->value);
		else
			return(NULL);
		}
	else
		return(Getenv(name));
	}

static CONF_VALUE *get_section(conf,section)
LHASH *conf;
char *section;
	{
	CONF_VALUE *v,vv;

	if ((conf == NULL) || (section == NULL)) return(NULL);
	vv.name=NULL;
	vv.section=section;
	v=(CONF_VALUE *)lh_retrieve(conf,(char *)&vv);
	return(v);
	}

STACK *CONF_get_section(conf,section)
LHASH *conf;
char *section;
	{
	CONF_VALUE *v;

	v=get_section(conf,section);
	if (v != NULL)
		return((STACK *)v->value);
	else
		return(NULL);
	}

long CONF_get_number(conf,section,name)
LHASH *conf;
char *section;
char *name;
	{
	char *str;
	long ret=0;

	str=CONF_get_string(conf,section,name);
	if (str == NULL) return(0);
	for (;;)
		{
		if (IS_NUMER(*str))
			ret=ret*10+(*str -'0');
		else
			return(ret);
		str++;
		}
	}

void CONF_free(conf)
LHASH *conf;
	{
	if (conf == NULL) return;

	conf->down_load=0; 	/* evil thing to make sure the 'Free()'
				 * works as expected */
	lh_doall_arg(conf,(void (*)())value_free_hash,(char *)conf);

	/* We now have only 'section' entries in the hash table.
	 * Due to problems with */

	lh_doall_arg(conf,(void (*)())value_free_stack,(char *)conf);
	lh_free(conf);
	}

static void value_free_hash(a,conf)
CONF_VALUE *a;
LHASH *conf;
	{
	if (a->name != NULL)
		{
		a=(CONF_VALUE *)lh_delete(conf,(char *)a);
		}
	}

static void value_free_stack(a,conf)
CONF_VALUE *a;
LHASH *conf;
	{
	CONF_VALUE *vv;
	STACK *sk;
	int i;

	if (a->name != NULL) return;

	sk=(STACK *)a->value;
	for (i=sk_num(sk)-1; i>=0; i--)
		{
		vv=(CONF_VALUE *)sk_value(sk,i);
		Free(vv->value);
		Free(vv->name);
		Free(vv);
		}
	if (sk != NULL) sk_free(sk);
	Free(a->section);
	Free(a);
	}

static void clear_comments(p)
char *p;
	{
	char *to;

	to=p;
	for (;;)
		{
		if (IS_COMMENT(*p))
			{
			*p='\0';
			return;
			}
		if (IS_QUOTE(*p))
			{
			p=scan_quote(p);
			continue;
			}
		if (IS_ESC(*p))
			{
			p=scan_esc(p);
			continue;
			}
		if (IS_EOF(*p))
			return;
		else
			p++;
		}
	}

static int str_copy(conf,section,pto,from)
LHASH *conf;
char *section;
char **pto,*from;
	{
	int q,r,rr=0,to=0,len=0;
	char *s,*e,*rp,*p,*rrp,*np,*cp,v;
	BUF_MEM *buf;

	if ((buf=BUF_MEM_new()) == NULL) return(0);

	len=strlen(from)+1;
	if (!BUF_MEM_grow(buf,len)) goto err;

	for (;;)
		{
		if (IS_QUOTE(*from))
			{
			q= *from;
			from++;
			while ((*from != '\0') && (*from != q))
				{
				if (*from == '\\')
					{
					from++;
					if (*from == '\0') break;
					}
				buf->data[to++]= *(from++);
				}
			}
		else if (*from == '\\')
			{
			from++;
			v= *(from++);
			if (v == '\0') break;
			else if (v == 'r') v='\r';
			else if (v == 'n') v='\n';
			else if (v == 'b') v='\b';
			else if (v == 't') v='\t';
			buf->data[to++]= v;
			}
		else if (*from == '\0')
			break;
		else if (*from == '$')
			{
			/* try to expand it */
			rrp=NULL;
			s= &(from[1]);
			if (*s == '{')
				q='}';
			else if (*s == '(')
				q=')';
			else q=0;

			if (q) s++;
			cp=section;
			e=np=s;
			while (IS_ALPHA_NUMERIC(*e))
				e++;
			if ((e[0] == ':') && (e[1] == ':'))
				{
				cp=np;
				rrp=e;
				rr= *e;
				*rrp='\0';
				e+=2;
				np=e;
				while (IS_ALPHA_NUMERIC(*e))
					e++;
				}
			r= *e;
			*e='\0';
			rp=e;
			if (q)
				{
				if (r != q)
					{
					CONFerr(CONF_F_STR_COPY,CONF_R_NO_CLOSE_BRACE);
					goto err;
					}
				e++;
				}
			/* So at this point we have
			 * ns which is the start of the name string which is
			 *   '\0' terminated. 
			 * cs which is the start of the section string which is
			 *   '\0' terminated.
			 * e is the 'next point after'.
			 * r and s are the chars replaced by the '\0'
			 * rp and sp is where 'r' and 's' came from.
			 */
			p=CONF_get_string(conf,cp,np);
			if (rrp != NULL) *rrp=rr;
			*rp=r;
			if (p == NULL)
				{
				CONFerr(CONF_F_STR_COPY,CONF_R_VARIABLE_HAS_NO_VALUE);
				goto err;
				}
			BUF_MEM_grow(buf,(strlen(p)+len-(e-from)));
			while (*p)
				buf->data[to++]= *(p++);
			from=e;
			}
		else
			buf->data[to++]= *(from++);
		}
	buf->data[to]='\0';
	if (*pto != NULL) Free(*pto);
	*pto=buf->data;
	Free(buf);
	return(1);
err:
	if (buf != NULL) BUF_MEM_free(buf);
	return(0);
	}

static char *eat_ws(p)
char *p;
	{
	while (IS_WS(*p) && (!IS_EOF(*p)))
		p++;
	return(p);
	}

static char *eat_alpha_numeric(p)
char *p;
	{
	for (;;)
		{
		if (IS_ESC(*p))
			{
			p=scan_esc(p);
			continue;
			}
		if (!IS_ALPHA_NUMERIC_PUNCT(*p))
			return(p);
		p++;
		}
	}

static unsigned long hash(v)
CONF_VALUE *v;
	{
	return((lh_strhash(v->section)<<2)^lh_strhash(v->name));
	}

static int cmp(a,b)
CONF_VALUE *a,*b;
	{
	int i;

	if (a->section != b->section)
		{
		i=strcmp(a->section,b->section);
		if (i) return(i);
		}

	if ((a->name != NULL) && (b->name != NULL))
		{
		i=strcmp(a->name,b->name);
		return(i);
		}
	else if (a->name == b->name)
		return(0);
	else
		return((a->name == NULL)?-1:1);
	}

static char *scan_quote(p)
char *p;
	{
	int q= *p;

	p++;
	while (!(IS_EOF(*p)) && (*p != q))
		{
		if (IS_ESC(*p))
			{
			p++;
			if (IS_EOF(*p)) return(p);
			}
		p++;
		}
	if (*p == q) p++;
	return(p);
	}

static CONF_VALUE *new_section(conf,section)
LHASH *conf;
char *section;
	{
	STACK *sk=NULL;
	int ok=0,i;
	CONF_VALUE *v=NULL,*vv;

	if ((sk=sk_new_null()) == NULL)
		goto err;
	if ((v=(CONF_VALUE *)Malloc(sizeof(CONF_VALUE))) == NULL)
		goto err;
	i=strlen(section)+1;
	if ((v->section=(char *)Malloc(i)) == NULL)
		goto err;

	memcpy(v->section,section,i);
	v->name=NULL;
	v->value=(char *)sk;
	
	vv=(CONF_VALUE *)lh_insert(conf,(char *)v);
	if (vv != NULL)
		{
#if !defined(NO_STDIO) && !defined(WIN16)
		fprintf(stderr,"internal fault\n");
#endif
		abort();
		}
	ok=1;
err:
	if (!ok)
		{
		if (sk != NULL) sk_free(sk);
		if (v != NULL) Free(v);
		v=NULL;
		}
	return(v);
	}
