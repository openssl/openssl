/* crypto/bio/bss_log.c */
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

/*
	Why BIO_s_log?

	BIO_s_log is useful for system daemons (or services under NT).
	It is one-way BIO, it sends all stuff to syslogd (or event log
	under NT).

*/


#include <stdio.h>
#include <errno.h>

#ifndef WIN32
#ifdef __ultrix
#include <sys/syslog.h>
#else
#include <syslog.h>
#endif
#else
#include <process.h>
#endif

#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/err.h>
#ifndef NO_SYSLOG


static int MS_CALLBACK slg_write(BIO *h,char *buf,int num);
static int MS_CALLBACK slg_puts(BIO *h,char *str);
static long MS_CALLBACK slg_ctrl(BIO *h,int cmd,long arg1,char *arg2);
static int MS_CALLBACK slg_new(BIO *h);
static int MS_CALLBACK slg_free(BIO *data);
static int xopenlog(BIO* bp, const char* name, int level);
static int xcloselog(BIO* bp);

static BIO_METHOD methods_slg=
	{
	BIO_TYPE_MEM,"syslog",
	slg_write,
	NULL,
	slg_puts,
	NULL,
	slg_ctrl,
	slg_new,
	slg_free,
	NULL,
	};

BIO_METHOD *BIO_s_log(void)
	{
	return(&methods_slg);
	}

static int MS_CALLBACK slg_new(BIO *bi)
	{
	bi->init=1;
	bi->num=0;
	bi->ptr=NULL;
#ifndef WIN32
	xopenlog(bi, "application", LOG_DAEMON);
#else
	xopenlog(bi, "application", 0);
#endif
	return(1);
	}

static int MS_CALLBACK slg_free(BIO *a)
	{
	if (a == NULL) return(0);
	xcloselog(a);
	return(1);
	}
	
static int MS_CALLBACK slg_write(BIO *b, char *in, int inl)
	{
	int ret= inl;
	char* buf= in;
	char* pp;
#if defined(WIN32)
	LPCSTR lpszStrings[2];
	WORD evtype= EVENTLOG_ERROR_TYPE;
	int pid = _getpid();
	char pidbuf[20];
#else
	int priority;
#endif

	if((buf= (char *)Malloc(inl+ 1)) == NULL){
		return(0);
	}
	strncpy(buf, in, inl);
	buf[inl]= '\0';
#if defined(WIN32)
	if(strncmp(buf, "ERR ", 4) == 0){
		evtype= EVENTLOG_ERROR_TYPE;
		pp= buf+ 4;
	}else if(strncmp(buf, "WAR ", 4) == 0){
		evtype= EVENTLOG_WARNING_TYPE;
		pp= buf+ 4;
	}else if(strncmp(buf, "INF ", 4) == 0){
		evtype= EVENTLOG_INFORMATION_TYPE;
		pp= buf+ 4;
	}else{
		evtype= EVENTLOG_ERROR_TYPE;
		pp= buf;
	}

	sprintf(pidbuf, "[%d] ", pid);
	lpszStrings[0] = pidbuf;
	lpszStrings[1] = pp;

	if(b->ptr)
		ReportEvent(b->ptr, evtype, 0, 1024, NULL, 2, 0,
				lpszStrings, NULL);
#else
	if(strncmp(buf, "ERR ", 4) == 0){
		priority= LOG_ERR;
		pp= buf+ 4;
	}else if(strncmp(buf, "WAR ", 4) == 0){
		priority= LOG_WARNING;
		pp= buf+ 4;
	}else if(strncmp(buf, "INF ", 4) == 0){
		priority= LOG_INFO;
		pp= buf+ 4;
	}else{
		priority= LOG_ERR;
		pp= buf;
	}

	syslog(priority, "%s", pp);
#endif
	Free(buf);
	return(ret);
	}

static long MS_CALLBACK slg_ctrl(BIO *b, int cmd, long num, char *ptr)
	{
	switch (cmd)
		{
	case BIO_CTRL_SET:
		xcloselog(b);
		xopenlog(b, ptr, num);
		break;
	default:
		break;
		}
	return(0);
	}

static int MS_CALLBACK slg_puts(BIO *bp, char *str)
	{
	int n,ret;

	n=strlen(str);
	ret=slg_write(bp,str,n);
	return(ret);
	}

static int xopenlog(BIO* bp, const char* name, int level)
{
#if defined(WIN32)
	if((bp->ptr= (char *)RegisterEventSource(NULL, name)) == NULL){
		return(0);
	}
#else
	openlog(name, LOG_PID|LOG_CONS, level);
#endif
	return(1);
}

static int xcloselog(BIO* bp)
{
#if defined(WIN32)
	if(bp->ptr)
		DeregisterEventSource((HANDLE)(bp->ptr));
	bp->ptr= NULL;
#else
	closelog();
#endif
	return(1);
}

#endif
