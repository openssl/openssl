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
	if (buf != NULL) Free(buf);
	buf=(char *)Malloc(len+1);
	if (buf == NULL) return(0);

	len=fread(buf,1,len,fp);
	if (len <= 1) return(0);
	buf[len]='\0';

	i=0;
	for (p=buf; *p; p++)
		if (*p == '\n') i++;
	if (arg != NULL) Free(arg);
	arg=(char **)Malloc(sizeof(char *)*(i*2));

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
		arg->data=(char **)Malloc(sizeof(char *)*arg->count);
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
			arg->data=(char **)Realloc(arg->data,
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
