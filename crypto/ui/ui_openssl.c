/* crypto/ui/ui_openssl.c -*- mode:C; c-file-style: "eay" -*- */
/* Written by Richard Levitte (levitte@stacken.kth.se) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

/* The lowest level part of this file was previously in crypto/des/read_pwd.c,
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
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


#include <openssl/e_os2.h>

#if !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_VMS)
# ifdef OPENSSL_UNISTD
#  include OPENSSL_UNISTD
# else
#  include <unistd.h>
# endif
/* If unistd.h defines _POSIX_VERSION, we conclude that we
 * are on a POSIX system and have sigaction and termios. */
# if defined(_POSIX_VERSION)

#  define SIGACTION
#  if !defined(TERMIOS) && !defined(TERMIO) && !defined(SGTTY)
#   define TERMIOS
#  endif

# endif
#endif

#ifdef WIN16TTY
# undef OPENSSL_SYS_WIN16
# undef WIN16
# undef _WINDOWS
# include <graph.h>
#endif

/* 06-Apr-92 Luke Brennan    Support for VMS */
#include "ui_locl.h"
#include "cryptlib.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <errno.h>

#ifdef OPENSSL_SYS_VMS		/* prototypes for sys$whatever */
# include <starlet.h>
# ifdef __DECC
#  pragma message disable DOLLARID
# endif
#endif

#ifdef WIN_CONSOLE_BUG
# include <windows.h>
# include <wincon.h>
#endif


/* There are 5 types of terminal interface supported,
 * TERMIO, TERMIOS, VMS, MSDOS and SGTTY
 */

#if defined(__sgi) && !defined(TERMIOS)
# define TERMIOS
# undef  TERMIO
# undef  SGTTY
#endif

#if defined(linux) && !defined(TERMIO)
# undef  TERMIOS
# define TERMIO
# undef  SGTTY
#endif

#ifdef _LIBC
# undef  TERMIOS
# define TERMIO
# undef  SGTTY
#endif

#if !defined(TERMIO) && !defined(TERMIOS) && !defined(OPENSSL_SYS_VMS) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_MACINTOSH_CLASSIC) && !defined(MAC_OS_GUSI_SOURCE)
# undef  TERMIOS
# undef  TERMIO
# define SGTTY
#endif

#ifdef TERMIOS
# include <termios.h>
# define TTY_STRUCT		struct termios
# define TTY_FLAGS		c_lflag
# define TTY_get(tty,data)	tcgetattr(tty,data)
# define TTY_set(tty,data)	tcsetattr(tty,TCSANOW,data)
#endif

#ifdef TERMIO
# include <termio.h>
# define TTY_STRUCT		struct termio
# define TTY_FLAGS		c_lflag
# define TTY_get(tty,data)	ioctl(tty,TCGETA,data)
# define TTY_set(tty,data)	ioctl(tty,TCSETA,data)
#endif

#ifdef SGTTY
# include <sgtty.h>
# define TTY_STRUCT		struct sgttyb
# define TTY_FLAGS		sg_flags
# define TTY_get(tty,data)	ioctl(tty,TIOCGETP,data)
# define TTY_set(tty,data)	ioctl(tty,TIOCSETP,data)
#endif

#if !defined(_LIBC) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_VMS) && !defined(OPENSSL_SYS_MACINTOSH_CLASSIC)
# include <sys/ioctl.h>
#endif

#ifdef OPENSSL_SYS_MSDOS
# include <conio.h>
#endif

#ifdef OPENSSL_SYS_VMS
# include <ssdef.h>
# include <iodef.h>
# include <ttdef.h>
# include <descrip.h>
struct IOSB {
	short iosb$w_value;
	short iosb$w_count;
	long  iosb$l_info;
	};
#endif

#if defined(OPENSSL_SYS_MACINTOSH_CLASSIC) || defined(MAC_OS_GUSI_SOURCE)
/*
 * This one needs work. As a matter of fact the code is unoperational
 * and this is only a trick to get it compiled.
 *					<appro@fy.chalmers.se>
 */
# define TTY_STRUCT int
#endif

#ifndef NX509_SIG
# define NX509_SIG 32
#endif


/* Define globals.  They are protected by a lock */
#ifdef SIGACTION
static struct sigaction savsig[NX509_SIG];
#else
static void (*savsig[NX509_SIG])(int );
#endif
static jmp_buf save;

#ifdef OPENSSL_SYS_VMS
static struct IOSB iosb;
static $DESCRIPTOR(terminal,"TT");
static long tty_orig[3], tty_new[3];
static long status;
static unsigned short channel = 0;
#else
#ifndef OPENSSL_SYS_MSDOS
static TTY_STRUCT tty_orig,tty_new;
#endif
#endif
static FILE *tty;
static int is_a_tty;

/* Declare static functions */
static void read_till_nl(FILE *);
static void recsig(int);
static void pushsig(void);
static void popsig(void);
#if defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_WIN16)
static int noecho_fgets(char *buf, int size, FILE *tty);
#endif
static int read_string_inner(UI *ui, UI_STRING *uis, int echo);

static int read_string(UI *ui, UI_STRING *uis);

static int open_console(UI *ui);
static int echo_console(UI *ui);
static int noecho_console(UI *ui);
static int close_console(UI *ui);

static UI_METHOD ui_openssl =
	{
	"OpenSSL default user interface",
	open_console,
	read_string,
	NULL,			/* The reader function writes as well */
	close_console,
	};

/* The method with all the built-in thingies */
UI_METHOD *UI_OpenSSL(void)
	{
	return &ui_openssl;
	}

static int read_string(UI *ui, UI_STRING *uis)
	{
	switch (UI_get_string_type(uis))
		{
	case UI_VERIFY_NOECHO:
		fprintf(tty,"Verifying - %s",
			UI_get0_output_string(uis));
		fflush(tty);
		if (read_string_inner(ui, uis, 0) == 0)
			return 0;
		if (strcmp(UI_get0_result_string(uis),
			UI_get0_test_string(uis)) != 0)
			{
			fprintf(tty,"Verify failure\n");
			fflush(tty);
			return 0;
			}
		break;
	case UI_VERIFY_ECHO:
		fprintf(tty,"Verifying - %s",
			UI_get0_output_string(uis));
		fflush(tty);
		if (read_string_inner(ui, uis, 1) == 0)
			return 0;
		if (strcmp(UI_get0_result_string(uis),
			UI_get0_test_string(uis)) != 0)
			{
			fprintf(tty,"Verify failure\n");
			fflush(tty);
			return 0;
			}
		break;
	case UI_STRING_NOECHO:
		fputs(UI_get0_output_string(uis), tty);
		fflush(tty);
		return read_string_inner(ui, uis, 0);
	case UI_STRING_ECHO:
		fputs(UI_get0_output_string(uis), tty);
		fflush(tty);
		return read_string_inner(ui, uis, 1);
	default:
		fputs(UI_get0_output_string(uis), tty);
		fflush(tty);
		break;
		}
	return 1;
	}


/* Internal functions to read a string without echoing */
static void read_till_nl(FILE *in)
	{
#define SIZE 4
	char buf[SIZE+1];

	do	{
		fgets(buf,SIZE,in);
		} while (strchr(buf,'\n') == NULL);
	}

static int read_string_inner(UI *ui, UI_STRING *uis, int echo)
	{
	static int ps;
	int ok;
	char *result = OPENSSL_malloc(BUFSIZ);
	int maxsize = BUFSIZ-1;

#ifndef OPENSSL_SYS_WIN16
	if (setjmp(save))
		{
		ok=0;
		goto error;
		}
	ok=0;
	ps=0;

	pushsig();
	ps=1;

	if (!echo) noecho_console(ui);
	ps=2;

	while (!ok)
		{
		char *p;

		result[0]='\0';
#ifdef OPENSSL_SYS_MSDOS
		if (!echo)
			noecho_fgets(result,maxsize,tty);
		else
#endif
			fgets(result,maxsize,tty);
		if (feof(tty)) goto error;
		if (ferror(tty)) goto error;
		if ((p=(char *)strchr(result,'\n')) != NULL)
			*p='\0';
		else	read_till_nl(tty);
		if (UI_set_result(uis, result) >= 0)
			ok=1;
		}

error:
	if (!echo) fprintf(tty,"\n");
	if (ps >= 2 && !echo)
		echo_console(ui);

	if (ps >= 1)
		popsig();
#else
	memset(result,0,BUFSIZ);
	ok=1;
#endif

	OPENSSL_free(result);
	return ok;
	}


/* Internal functions to open, handle and close a channel to the console.  */
static int open_console(UI *ui)
	{
	CRYPTO_w_lock(CRYPTO_LOCK_UI);
	is_a_tty = 1;

#ifdef OPENSSL_SYS_MSDOS
	if ((tty=fopen("con","w+")) == NULL)
		tty=stdin;
#elif defined(OPENSSL_SYS_MACINTOSH_CLASSIC)
	tty=stdin;
#else
	if ((tty=fopen("/dev/tty","w+")) == NULL)
		tty=stdin;
#endif

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
			return 0;
		}
#endif
#ifdef OPENSSL_SYS_VMS
	status = sys$assign(&terminal,&channel,0,0);
	if (status != SS$_NORMAL)
		return 0;
	status=sys$qiow(0,channel,IO$_SENSEMODE,&iosb,0,0,tty_orig,12,0,0,0,0);
	if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
		return 0;
#endif
	return 1;
	}

static int noecho_console(UI *ui)
	{
#ifdef TTY_FLAGS
	memcpy(&(tty_new),&(tty_orig),sizeof(tty_orig));
	tty_new.TTY_FLAGS &= ~ECHO;
#endif

#if defined(TTY_set) && !defined(OPENSSL_SYS_VMS)
	if (is_a_tty && (TTY_set(fileno(tty),&tty_new) == -1))
		return 0;
#endif
#ifdef OPENSSL_SYS_VMS
	tty_new[0] = tty_orig[0];
	tty_new[1] = tty_orig[1] | TT$M_NOECHO;
	tty_new[2] = tty_orig[2];
	status = sys$qiow(0,channel,IO$_SETMODE,&iosb,0,0,tty_new,12,0,0,0,0);
	if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
		return 0;
#endif
	return 1;
	}

static int echo_console(UI *ui)
	{
#if defined(TTY_set) && !defined(OPENSSL_SYS_VMS)
	memcpy(&(tty_new),&(tty_orig),sizeof(tty_orig));
	tty_new.TTY_FLAGS |= ECHO;
#endif

#if defined(TTY_set) && !defined(OPENSSL_SYS_VMS)
	if (is_a_tty && (TTY_set(fileno(tty),&tty_new) == -1))
		return 0;
#endif
#ifdef OPENSSL_SYS_VMS
	tty_new[0] = tty_orig[0];
	tty_new[1] = tty_orig[1] & ~TT$M_NOECHO;
	tty_new[2] = tty_orig[2];
	status = sys$qiow(0,channel,IO$_SETMODE,&iosb,0,0,tty_new,12,0,0,0,0);
	if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
		return 0;
#endif
	return 1;
	}

static int close_console(UI *ui)
	{
	if (stdin != tty) fclose(tty);
#ifdef OPENSSL_SYS_VMS
	status = sys$dassgn(channel);
#endif
	CRYPTO_w_unlock(CRYPTO_LOCK_UI);

	return 1;
	}


/* Internal functions to handle signals and act on them */
static void pushsig(void)
	{
	int i;
#ifdef SIGACTION
	struct sigaction sa;

	memset(&sa,0,sizeof sa);
	sa.sa_handler=recsig;
#endif

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
#ifdef SIGKILL
		if (i == SIGKILL) /* We can't make any action on that. */
			continue;
#endif
#ifdef SIGACTION
		sigaction(i,&sa,&savsig[i]);
#else
		savsig[i]=signal(i,recsig);
#endif
		}

#ifdef SIGWINCH
	signal(SIGWINCH,SIG_DFL);
#endif
	}

static void popsig(void)
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

static void recsig(int i)
	{
	longjmp(save,1);
#ifdef LINT
	i=i;
#endif
	}


/* Internal functions specific for Windows */
#if defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_WIN16)
static int noecho_fgets(char *buf, int size, FILE *tty)
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
#ifdef WIN_CONSOLE_BUG
/* Win95 has several evil console bugs: one of these is that the
 * last character read using getch() is passed to the next read: this is
 * usually a CR so this can be trouble. No STDIO fix seems to work but
 * flushing the console appears to do the trick.
 */
		{
			HANDLE inh;
			inh = GetStdHandle(STD_INPUT_HANDLE);
			FlushConsoleInputBuffer(inh);
		}
#endif
	return(strlen(buf));
	}
#endif
