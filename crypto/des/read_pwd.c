/* crypto/des/read_pwd.c */
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

/* #define SIGACTION */ /* Define this if you have sigaction() */
#ifdef WIN16TTY
#undef WIN16
#undef _WINDOWS
#include <graph.h>
#endif

/* 06-Apr-92 Luke Brennan    Support for VMS */
#include "des_locl.h"
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <errno.h>

/* There are 5 types of terminal interface supported,
 * TERMIO, TERMIOS, VMS, MSDOS and SGTTY
 */

#if defined(__sgi) && !defined(TERMIOS)
#define TERMIOS
#undef  TERMIO
#undef  SGTTY
#endif

#if defined(linux) && !defined(TERMIO)
#undef  TERMIOS
#define TERMIO
#undef  SGTTY
#endif

#ifdef _LIBC
#undef  TERMIOS
#define TERMIO
#undef  SGTTY
#endif

#if !defined(TERMIO) && !defined(TERMIOS) && !defined(VMS) && !defined(MSDOS)
#undef  TERMIOS
#undef  TERMIO
#define SGTTY
#endif

#ifdef TERMIOS
#include <termios.h>
#define TTY_STRUCT		struct termios
#define TTY_FLAGS		c_lflag
#define	TTY_get(tty,data)	tcgetattr(tty,data)
#define TTY_set(tty,data)	tcsetattr(tty,TCSANOW,data)
#endif

#ifdef TERMIO
#include <termio.h>
#define TTY_STRUCT		struct termio
#define TTY_FLAGS		c_lflag
#define TTY_get(tty,data)	ioctl(tty,TCGETA,data)
#define TTY_set(tty,data)	ioctl(tty,TCSETA,data)
#endif

#ifdef SGTTY
#include <sgtty.h>
#define TTY_STRUCT		struct sgttyb
#define TTY_FLAGS		sg_flags
#define TTY_get(tty,data)	ioctl(tty,TIOCGETP,data)
#define TTY_set(tty,data)	ioctl(tty,TIOCSETP,data)
#endif

#if !defined(_LIBC) && !defined(MSDOS) && !defined(VMS)
#include <sys/ioctl.h>
#endif

#ifdef MSDOS
#include <conio.h>
#define fgets(a,b,c) noecho_fgets(a,b,c)
#endif

#ifdef VMS
#include <ssdef.h>
#include <iodef.h>
#include <ttdef.h>
#include <descrip.h>
struct IOSB {
	short iosb$w_value;
	short iosb$w_count;
	long  iosb$l_info;
	};
#endif

#ifndef NX509_SIG
#define NX509_SIG 32
#endif

#ifndef NOPROTO
static void read_till_nl(FILE *);
static void recsig(int);
static void pushsig(void);
static void popsig(void);
#if defined(MSDOS) && !defined(WIN16)
static int noecho_fgets(char *buf, int size, FILE *tty);
#endif
#else
static void read_till_nl();
static void recsig();
static void pushsig();
static void popsig();
#if defined(MSDOS) && !defined(WIN16)
static int noecho_fgets();
#endif
#endif

#ifdef SIGACTION
 static struct sigaction savsig[NX509_SIG];
#else
# ifndef NOPROTO
  static void (*savsig[NX509_SIG])(int );
# else
  static void (*savsig[NX509_SIG])();
# endif
#endif
static jmp_buf save;

int des_read_pw_string(buf, length, prompt, verify)
char *buf;
int length;
char *prompt;
int verify;
	{
	char buff[BUFSIZ];
	int ret;

	ret=des_read_pw(buf,buff,(length>BUFSIZ)?BUFSIZ:length,prompt,verify);
	memset(buff,0,BUFSIZ);
	return(ret);
	}

#ifndef WIN16

static void read_till_nl(in)
FILE *in;
	{
#define SIZE 4
	char buf[SIZE+1];

	do	{
		fgets(buf,SIZE,in);
		} while (strchr(buf,'\n') == NULL);
	}


/* return 0 if ok, 1 (or -1) otherwise */
int des_read_pw(buf, buff, size, prompt, verify)
char *buf;
char *buff;
int size;
char *prompt;
int verify;
	{
#ifdef VMS
	struct IOSB iosb;
	$DESCRIPTOR(terminal,"TT");
	long tty_orig[3], tty_new[3];
	long status;
	unsigned short channel = 0;
#else
#ifndef MSDOS
	TTY_STRUCT tty_orig,tty_new;
#endif
#endif
	int number=5;
	int ok=0;
	int ps=0;
	int is_a_tty=1;

	FILE *tty=NULL;
	char *p;

#ifndef MSDOS
	if ((tty=fopen("/dev/tty","r")) == NULL)
		tty=stdin;
#else /* MSDOS */
	if ((tty=fopen("con","r")) == NULL)
		tty=stdin;
#endif /* MSDOS */

#if defined(TTY_get) && !defined(VMS)
	if (TTY_get(fileno(tty),&tty_orig) == -1)
		{
#ifdef ENOTTY
		if (errno == ENOTTY)
			is_a_tty=0;
		else
#endif
#ifdef EINVAL
		/* Ariel Glenn ariel@columbia.edu reports that solaris
		 * can return EINVAL instead.  This should be ok */
		if (errno == EINVAL)
			is_a_tty=0;
		else
#endif
			return(-1);
		}
	memcpy(&(tty_new),&(tty_orig),sizeof(tty_orig));
#endif
#ifdef VMS
	status = SYS$ASSIGN(&terminal,&channel,0,0);
	if (status != SS$_NORMAL)
		return(-1);
	status=SYS$QIOW(0,channel,IO$_SENSEMODE,&iosb,0,0,tty_orig,12,0,0,0,0);
	if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
		return(-1);
#endif

	if (setjmp(save))
		{
		ok=0;
		goto error;
		}
	pushsig();
	ps=1;

#ifdef TTY_FLAGS
	tty_new.TTY_FLAGS &= ~ECHO;
#endif

#if defined(TTY_set) && !defined(VMS)
	if (is_a_tty && (TTY_set(fileno(tty),&tty_new) == -1))
		return(-1);
#endif
#ifdef VMS
	tty_new[0] = tty_orig[0];
	tty_new[1] = tty_orig[1] | TT$M_NOECHO;
	tty_new[2] = tty_orig[2];
	status = SYS$QIOW(0,channel,IO$_SETMODE,&iosb,0,0,tty_new,12,0,0,0,0);
	if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
		return(-1);
#endif
	ps=2;

	while ((!ok) && (number--))
		{
		fputs(prompt,stderr);
		fflush(stderr);

		buf[0]='\0';
		fgets(buf,size,tty);
		if (feof(tty)) goto error;
		if (ferror(tty)) goto error;
		if ((p=(char *)strchr(buf,'\n')) != NULL)
			*p='\0';
		else	read_till_nl(tty);
		if (verify)
			{
			fprintf(stderr,"\nVerifying password - %s",prompt);
			fflush(stderr);
			buff[0]='\0';
			fgets(buff,size,tty);
			if (feof(tty)) goto error;
			if ((p=(char *)strchr(buff,'\n')) != NULL)
				*p='\0';
			else	read_till_nl(tty);
				
			if (strcmp(buf,buff) != 0)
				{
				fprintf(stderr,"\nVerify failure");
				fflush(stderr);
				break;
				/* continue; */
				}
			}
		ok=1;
		}

error:
	fprintf(stderr,"\n");
#ifdef DEBUG
	perror("fgets(tty)");
#endif
	/* What can we do if there is an error? */
#if defined(TTY_set) && !defined(VMS) 
	if (ps >= 2) TTY_set(fileno(tty),&tty_orig);
#endif
#ifdef VMS
	if (ps >= 2)
		status = SYS$QIOW(0,channel,IO$_SETMODE,&iosb,0,0
			,tty_orig,12,0,0,0,0);
#endif
	
	if (ps >= 1) popsig();
	if (stdin != tty) fclose(tty);
#ifdef VMS
	status = SYS$DASSGN(channel);
#endif
	return(!ok);
	}

#else /* WIN16 */

int des_read_pw(buf, buff, size, prompt, verify)
char *buf;
char *buff;
int size;
char *prompt;
int verify;
	{ 
	memset(buf,0,size);
	memset(buff,0,size);
	return(0);
	}

#endif

static void pushsig()
	{
	int i;

	for (i=1; i<NX509_SIG; i++)
		{
#ifdef SIGUSR1
		if (i == SIGUSR1)
			continue;
#endif
#ifdef SIGUSR2
		if (i == SIGUSR2)
			continue;
#endif
#ifdef SIGACTION
		sigaction(i,NULL,&savsig[i]);
#else
		savsig[i]=signal(i,recsig);
#endif
		}

#ifdef SIGWINCH
	signal(SIGWINCH,SIG_DFL);
#endif
	}

static void popsig()
	{
	int i;

	for (i=1; i<NX509_SIG; i++)
		{
#ifdef SIGUSR1
		if (i == SIGUSR1)
			continue;
#endif
#ifdef SIGUSR2
		if (i == SIGUSR2)
			continue;
#endif
#ifdef SIGACTION
		sigaction(i,&savsig[i],NULL);
#else
		signal(i,savsig[i]);
#endif
		}
	}

static void recsig(i)
int i;
	{
	longjmp(save,1);
#ifdef LINT
	i=i;
#endif
	}

#if defined(MSDOS) && !defined(WIN16)
static int noecho_fgets(buf,size,tty)
char *buf;
int size;
FILE *tty;
	{
	int i;
	char *p;

	p=buf;
	for (;;)
		{
		if (size == 0)
			{
			*p='\0';
			break;
			}
		size--;
#ifdef WIN16TTY
		i=_inchar();
#else
		i=getch();
#endif
		if (i == '\r') i='\n';
		*(p++)=i;
		if (i == '\n')
			{
			*p='\0';
			break;
			}
		}
	return(strlen(buf));
	}
#endif
