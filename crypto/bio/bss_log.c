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
	It is one-way BIO, it sends all stuff to syslogd (on system that
	commonly use that), or event log (on NT), or OPCOM (on OpenVMS).

*/


#include <stdio.h>
#include <errno.h>

#if defined(WIN32)
#  include <process.h>
#elif defined(VMS) || defined(__VMS)
#  include <opcdef.h>
#  include <descrip.h>
#  include <lib$routines.h>
#  include <starlet.h>
#elif defined(__ultrix)
#  include <sys/syslog.h>
#elif !defined(MSDOS) /* Unix */
#  include <syslog.h>
#endif

#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/err.h>

#ifndef NO_SYSLOG

#if defined(WIN32)
#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7

#define LOG_DAEMON	(3<<3)
#elif defined(VMS)
/* On VMS, we don't really care about these, but we need them to compile */
#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7

#define LOG_DAEMON	OPC$M_NM_NTWORK
#endif

static int MS_CALLBACK slg_write(BIO *h,char *buf,int num);
static int MS_CALLBACK slg_puts(BIO *h,char *str);
static long MS_CALLBACK slg_ctrl(BIO *h,int cmd,long arg1,char *arg2);
static int MS_CALLBACK slg_new(BIO *h);
static int MS_CALLBACK slg_free(BIO *data);
static void xopenlog(BIO* bp, const char* name, int level);
static void xsyslog(BIO* bp, int priority, const char* string);
static void xcloselog(BIO* bp);

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
	xopenlog(bi, "application", LOG_DAEMON);
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
	int priority;

	if((buf= (char *)Malloc(inl+ 1)) == NULL){
		return(0);
	}
	strncpy(buf, in, inl);
	buf[inl]= '\0';

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

	xsyslog(b, priority, pp);

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

#if defined(WIN32)

static void xopenlog(BIO* bp, const char* name, int level)
{
	bp->ptr= (char *)RegisterEventSource(NULL, name);
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
	LPCSTR lpszStrings[2];
	WORD evtype= EVENTLOG_ERROR_TYPE;
	int pid = _getpid();
	char pidbuf[20];

	switch (priority)
		{
	case LOG_ERR:
		evtype = EVENTLOG_ERROR_TYPE;
		break;
	case LOG_WARNING:
		evtype = EVENTLOG_WARNING_TYPE;
		break;
	case LOG_INFO:
		evtype = EVENTLOG_INFORMATION_TYPE;
		break;
	default:
		evtype = EVENTLOG_ERROR_TYPE;
		break;
		}

	sprintf(pidbuf, "[%d] ", pid);
	lpszStrings[0] = pidbuf;
	lpszStrings[1] = string;

	if(bp->ptr)
		ReportEvent(bp->ptr, evtype, 0, 1024, NULL, 2, 0,
				lpszStrings, NULL);
}
	
static void xcloselog(BIO* bp)
{
	if(bp->ptr)
		DeregisterEventSource((HANDLE)(bp->ptr));
	bp->ptr= NULL;
}

#elif defined(VMS)

static int VMS_OPC_target = LOG_DAEMON;

static void xopenlog(BIO* bp, const char* name, int level)
{
	VMS_OPC_target = level; 
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
	struct dsc$descriptor_s opc_dsc;
	struct opcdef *opcdef_p;
	char buf[10240];
	unsigned int len;
        struct dsc$descriptor_s buf_dsc;
	$DESCRIPTOR(fao_cmd, "!AZ: !AZ");
	char *priority_tag;

	switch (priority)
	  {
	  case LOG_EMERG: priority_tag = "Emergency"; break;
	  case LOG_ALERT: priority_tag = "Alert"; break;
	  case LOG_CRIT: priority_tag = "Critical"; break;
	  case LOG_ERR: priority_tag = "Error"; break;
	  case LOG_WARNING: priority_tag = "Warning"; break;
	  case LOG_NOTICE: priority_tag = "Notice"; break;
	  case LOG_INFO: priority_tag = "Info"; break;
	  case LOG_DEBUG: priority_tag = "DEBUG"; break;
	  }

	buf_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
	buf_dsc.dsc$b_class = DSC$K_CLASS_S;
	buf_dsc.dsc$a_pointer = buf;
	buf_dsc.dsc$w_length = sizeof(buf) - 1;

	lib$sys_fao(&fao_cmd, &len, &buf_dsc, priority_tag, string);

	/* we know there's an 8 byte header.  That's documented */
	opcdef_p = (struct opcdef *) Malloc(8 + len);
	opcdef_p->opc$b_ms_type = OPC$_RQ_RQST;
	memcpy(opcdef_p->opc$z_ms_target_classes, &VMS_OPC_target, 3);
	opcdef_p->opc$l_ms_rqstid = 0;
	memcpy(&opcdef_p->opc$l_ms_text, buf, len);

	opc_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
	opc_dsc.dsc$b_class = DSC$K_CLASS_S;
	opc_dsc.dsc$a_pointer = (char *)opcdef_p;
	opc_dsc.dsc$w_length = len + 8;

	sys$sndopr(opc_dsc, 0);

	Free(opcdef_p);
}

static void xcloselog(BIO* bp)
{
}

#else /* Unix */

static void xopenlog(BIO* bp, const char* name, int level)
{
	openlog(name, LOG_PID|LOG_CONS, level);
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
	syslog(priority, "%s", string);
}

static void xcloselog(BIO* bp)
{
	closelog();
}

#endif /* Unix */

#endif /* NO_SYSLOG */
