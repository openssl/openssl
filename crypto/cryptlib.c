/* crypto/cryptlib.c */
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
#include <string.h>
#include "cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/safestack.h>

#if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WIN16)
static double SSLeay_MSVC5_hack=0.0; /* and for VC1.5 */
#endif

DECLARE_STACK_OF(CRYPTO_dynlock)
IMPLEMENT_STACK_OF(CRYPTO_dynlock)

/* real #defines in crypto.h, keep these upto date */
static const char* lock_names[CRYPTO_NUM_LOCKS] =
	{
	"<<ERROR>>",
	"err",
	"ex_data",
	"x509",
	"x509_info",
	"x509_pkey",
	"x509_crl",
	"x509_req",
	"dsa",
	"rsa",
	"evp_pkey",
	"x509_store",
	"ssl_ctx",
	"ssl_cert",
	"ssl_session",
	"ssl_sess_cert",
	"ssl",
	"ssl_method",
	"rand",
	"rand2",
	"debug_malloc",
	"BIO",
	"gethostbyname",
	"getservbyname",
	"readdir",
	"RSA_blinding",
	"dh",
	"debug_malloc2",
	"dso",
	"dynlock",
	"engine",
	"ui",
	"hwcrhk",		/* This is a HACK which will disappear in 0.9.8 */
	"fips",
	"fips2",
#if CRYPTO_NUM_LOCKS != 35
# error "Inconsistency between crypto.h and cryptlib.c"
#endif
	};

/* This is for applications to allocate new type names in the non-dynamic
   array of lock names.  These are numbered with positive numbers.  */
static STACK *app_locks=NULL;

/* For applications that want a more dynamic way of handling threads, the
   following stack is used.  These are externally numbered with negative
   numbers.  */
static STACK_OF(CRYPTO_dynlock) *dyn_locks=NULL;


static void (MS_FAR *locking_callback)(int mode,int type,
	const char *file,int line)=NULL;
static int (MS_FAR *add_lock_callback)(int *pointer,int amount,
	int type,const char *file,int line)=NULL;
static unsigned long (MS_FAR *id_callback)(void)=NULL;
static struct CRYPTO_dynlock_value *(MS_FAR *dynlock_create_callback)
	(const char *file,int line)=NULL;
static void (MS_FAR *dynlock_lock_callback)(int mode,
	struct CRYPTO_dynlock_value *l, const char *file,int line)=NULL;
static void (MS_FAR *dynlock_destroy_callback)(struct CRYPTO_dynlock_value *l,
	const char *file,int line)=NULL;

int CRYPTO_get_new_lockid(char *name)
	{
	char *str;
	int i;

#if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WIN16)
	/* A hack to make Visual C++ 5.0 work correctly when linking as
	 * a DLL using /MT. Without this, the application cannot use
	 * and floating point printf's.
	 * It also seems to be needed for Visual C 1.5 (win16) */
	SSLeay_MSVC5_hack=(double)name[0]*(double)name[1];
#endif

	if ((app_locks == NULL) && ((app_locks=sk_new_null()) == NULL))
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_LOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	if ((str=BUF_strdup(name)) == NULL)
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_LOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	i=sk_push(app_locks,str);
	if (!i)
		OPENSSL_free(str);
	else
		i+=CRYPTO_NUM_LOCKS; /* gap of one :-) */
	return(i);
	}

int CRYPTO_num_locks(void)
	{
	return CRYPTO_NUM_LOCKS;
	}

int CRYPTO_get_new_dynlockid(void)
	{
	int i = 0;
	CRYPTO_dynlock *pointer = NULL;

	if (dynlock_create_callback == NULL)
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK);
		return(0);
		}
	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);
	if ((dyn_locks == NULL)
		&& ((dyn_locks=sk_CRYPTO_dynlock_new_null()) == NULL))
		{
		CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	pointer = (CRYPTO_dynlock *)OPENSSL_malloc(sizeof(CRYPTO_dynlock));
	if (pointer == NULL)
		{
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	pointer->references = 1;
	pointer->data = dynlock_create_callback(__FILE__,__LINE__);
	if (pointer->data == NULL)
		{
		OPENSSL_free(pointer);
		CRYPTOerr(CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID,ERR_R_MALLOC_FAILURE);
		return(0);
		}

	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);
	/* First, try to find an existing empty slot */
	i=sk_CRYPTO_dynlock_find(dyn_locks,NULL);
	/* If there was none, push, thereby creating a new one */
	if (i == -1)
		/* Since sk_push() returns the number of items on the
		   stack, not the location of the pushed item, we need
		   to transform the returned number into a position,
		   by decreasing it.  */
		i=sk_CRYPTO_dynlock_push(dyn_locks,pointer) - 1;
	else
		/* If we found a place with a NULL pointer, put our pointer
		   in it.  */
		sk_CRYPTO_dynlock_set(dyn_locks,i,pointer);
	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	if (i == -1)
		{
		dynlock_destroy_callback(pointer->data,__FILE__,__LINE__);
		OPENSSL_free(pointer);
		}
	else
		i += 1; /* to avoid 0 */
	return -i;
	}

void CRYPTO_destroy_dynlockid(int i)
	{
	CRYPTO_dynlock *pointer = NULL;
	if (i)
		i = -i-1;
	if (dynlock_destroy_callback == NULL)
		return;

	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);

	if (dyn_locks == NULL || i >= sk_CRYPTO_dynlock_num(dyn_locks))
		{
		CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);
		return;
		}
	pointer = sk_CRYPTO_dynlock_value(dyn_locks, i);
	if (pointer != NULL)
		{
		--pointer->references;
#ifdef REF_CHECK
		if (pointer->references < 0)
			{
			fprintf(stderr,"CRYPTO_destroy_dynlockid, bad reference count\n");
			abort();
			}
		else
#endif
			if (pointer->references <= 0)
				{
				sk_CRYPTO_dynlock_set(dyn_locks, i, NULL);
				}
			else
				pointer = NULL;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	if (pointer)
		{
		dynlock_destroy_callback(pointer->data,__FILE__,__LINE__);
		OPENSSL_free(pointer);
		}
	}

struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i)
	{
	CRYPTO_dynlock *pointer = NULL;
	if (i)
		i = -i-1;

	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);

	if (dyn_locks != NULL && i < sk_CRYPTO_dynlock_num(dyn_locks))
		pointer = sk_CRYPTO_dynlock_value(dyn_locks, i);
	if (pointer)
		pointer->references++;

	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);

	if (pointer)
		return pointer->data;
	return NULL;
	}

struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))
	(const char *file,int line)
	{
	return(dynlock_create_callback);
	}

void (*CRYPTO_get_dynlock_lock_callback(void))(int mode,
	struct CRYPTO_dynlock_value *l, const char *file,int line)
	{
	return(dynlock_lock_callback);
	}

void (*CRYPTO_get_dynlock_destroy_callback(void))
	(struct CRYPTO_dynlock_value *l, const char *file,int line)
	{
	return(dynlock_destroy_callback);
	}

void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*func)
	(const char *file, int line))
	{
	dynlock_create_callback=func;
	}

void CRYPTO_set_dynlock_lock_callback(void (*func)(int mode,
	struct CRYPTO_dynlock_value *l, const char *file, int line))
	{
	dynlock_lock_callback=func;
	}

void CRYPTO_set_dynlock_destroy_callback(void (*func)
	(struct CRYPTO_dynlock_value *l, const char *file, int line))
	{
	dynlock_destroy_callback=func;
	}


void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
		int line)
	{
	return(locking_callback);
	}

int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
					  const char *file,int line)
	{
	return(add_lock_callback);
	}

void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
					      const char *file,int line))
	{
	locking_callback=func;
	}

void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
					      const char *file,int line))
	{
	add_lock_callback=func;
	}

unsigned long (*CRYPTO_get_id_callback(void))(void)
	{
	return(id_callback);
	}

void CRYPTO_set_id_callback(unsigned long (*func)(void))
	{
	id_callback=func;
	}

unsigned long CRYPTO_thread_id(void)
	{
	unsigned long ret=0;

	if (id_callback == NULL)
		{
#ifdef OPENSSL_SYS_WIN16
		ret=(unsigned long)GetCurrentTask();
#elif defined(OPENSSL_SYS_WIN32)
		ret=(unsigned long)GetCurrentThreadId();
#elif defined(GETPID_IS_MEANINGLESS)
		ret=1L;
#else
		ret=(unsigned long)getpid();
#endif
		}
	else
		ret=id_callback();
	return(ret);
	}

void CRYPTO_lock(int mode, int type, const char *file, int line)
	{
#ifdef LOCK_DEBUG
		{
		char *rw_text,*operation_text;

		if (mode & CRYPTO_LOCK)
			operation_text="lock  ";
		else if (mode & CRYPTO_UNLOCK)
			operation_text="unlock";
		else
			operation_text="ERROR ";

		if (mode & CRYPTO_READ)
			rw_text="r";
		else if (mode & CRYPTO_WRITE)
			rw_text="w";
		else
			rw_text="ERROR";

		fprintf(stderr,"lock:%08lx:(%s)%s %-18s %s:%d\n",
			CRYPTO_thread_id(), rw_text, operation_text,
			CRYPTO_get_lock_name(type), file, line);
		}
#endif
	if (type < 0)
		{
		if (dynlock_lock_callback != NULL)
			{
			struct CRYPTO_dynlock_value *pointer
				= CRYPTO_get_dynlock_value(type);

			OPENSSL_assert(pointer != NULL);

			dynlock_lock_callback(mode, pointer, file, line);

			CRYPTO_destroy_dynlockid(type);
			}
		}
	else
		if (locking_callback != NULL)
			locking_callback(mode,type,file,line);
	}

int CRYPTO_add_lock(int *pointer, int amount, int type, const char *file,
	     int line)
	{
	int ret = 0;

	if (add_lock_callback != NULL)
		{
#ifdef LOCK_DEBUG
		int before= *pointer;
#endif

		ret=add_lock_callback(pointer,amount,type,file,line);
#ifdef LOCK_DEBUG
		fprintf(stderr,"ladd:%08lx:%2d+%2d->%2d %-18s %s:%d\n",
			CRYPTO_thread_id(),
			before,amount,ret,
			CRYPTO_get_lock_name(type),
			file,line);
#endif
		}
	else
		{
		CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,file,line);

		ret= *pointer+amount;
#ifdef LOCK_DEBUG
		fprintf(stderr,"ladd:%08lx:%2d+%2d->%2d %-18s %s:%d\n",
			CRYPTO_thread_id(),
			*pointer,amount,ret,
			CRYPTO_get_lock_name(type),
			file,line);
#endif
		*pointer=ret;
		CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,file,line);
		}
	return(ret);
	}

const char *CRYPTO_get_lock_name(int type)
	{
	if (type < 0)
		return("dynamic");
	else if (type < CRYPTO_NUM_LOCKS)
		return(lock_names[type]);
	else if (type-CRYPTO_NUM_LOCKS > sk_num(app_locks))
		return("ERROR");
	else
		return(sk_value(app_locks,type-CRYPTO_NUM_LOCKS));
	}

int OPENSSL_NONPIC_relocated=0;

#if defined(_WIN32) && defined(_WINDLL)

/* All we really need to do is remove the 'error' state when a thread
 * detaches */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason,
	     LPVOID lpvReserved)
	{
	switch(fdwReason)
		{
	case DLL_PROCESS_ATTACH:
#if defined(_WIN32_WINNT)
		{
		IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)hinstDLL;
		IMAGE_NT_HEADERS *nt_headers;

		if (dos_header->e_magic==IMAGE_DOS_SIGNATURE)
			{
			nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
						+ dos_header->e_lfanew);
			if (nt_headers->Signature==IMAGE_NT_SIGNATURE &&
			    hinstDLL!=(HINSTANCE)(nt_headers->OptionalHeader.ImageBase))
				OPENSSL_NONPIC_relocated=1;
			}
		}
#endif
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		ERR_remove_state(0);
		break;
	case DLL_PROCESS_DETACH:
		break;
		}
	return(TRUE);
	}
#endif

#if defined(_WIN32)
#include <tchar.h>

#if defined(_WIN32_WINNT) && _WIN32_WINNT>=0x0333
static int IsService(void)
{ HWINSTA h;
  DWORD len;
  WCHAR *name;

    (void)GetDesktopWindow(); /* return value is ignored */

    h = GetProcessWindowStation();
    if (h==NULL) return -1;

    if (GetUserObjectInformationW (h,UOI_NAME,NULL,0,&len) ||
	GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	return -1;

    if (len>512) return -1;		/* paranoia */
    len++,len&=~1;			/* paranoia */
#ifdef _MSC_VER
    name=(WCHAR *)_alloca(len+sizeof(WCHAR));
#else
    name=(WCHAR *)alloca(len+sizeof(WCHAR));
#endif
    if (!GetUserObjectInformationW (h,UOI_NAME,name,len,&len))
	return -1;

    len++,len&=~1;			/* paranoia */
    name[len/sizeof(WCHAR)]=L'\0';	/* paranoia */
#if 1
    /* This doesn't cover "interactive" services [working with real
     * WinSta0's] nor programs started non-interactively by Task
     * Scheduler [those are working with SAWinSta]. */
    if (wcsstr(name,L"Service-0x"))	return 1;
#else
    /* This covers all non-interactive programs such as services. */
    if (!wcsstr(name,L"WinSta0"))	return 1;
#endif
    else				return 0;
}
#endif

void OPENSSL_showfatal (const char *fmta,...)
{ va_list ap;
  TCHAR buf[256];
  const TCHAR *fmt;
  HANDLE h;

    if ((h=GetStdHandle(STD_ERROR_HANDLE)) != NULL &&
	GetFileType(h)!=FILE_TYPE_UNKNOWN)
    {	/* must be console application */
	va_start (ap,fmta);
	vfprintf (stderr,fmta,ap);
	va_end (ap);
	return;
    }

    if (sizeof(TCHAR)==sizeof(char))
	fmt=(const TCHAR *)fmta;
    else do
    { int    keepgoing;
      size_t len_0=strlen(fmta)+1,i;
      WCHAR *fmtw;

#ifdef _MSC_VER
	fmtw = (WCHAR *)_alloca (len_0*sizeof(WCHAR));
#else
	fmtw = (WCHAR *)alloca (len_0*sizeof(WCHAR));
#endif
	if (fmtw == NULL) { fmt=(const TCHAR *)L"no stack?"; break; }

#ifndef OPENSSL_NO_MULTIBYTE
	if (!MultiByteToWideChar(CP_ACP,0,fmta,len_0,fmtw,len_0))
#endif
	    for (i=0;i<len_0;i++) fmtw[i]=(WCHAR)fmta[i];

	for (i=0;i<len_0;i++)
	{   if (fmtw[i]==L'%') do
	    {	keepgoing=0;
		switch (fmtw[i+1])
		{   case L'0': case L'1': case L'2': case L'3': case L'4':
		    case L'5': case L'6': case L'7': case L'8': case L'9':
		    case L'.': case L'*':
		    case L'-':	i++; keepgoing=1; break;
		    case L's':	fmtw[i+1]=L'S';   break;
		    case L'S':	fmtw[i+1]=L's';   break;
		    case L'c':	fmtw[i+1]=L'C';   break;
		    case L'C':	fmtw[i+1]=L'c';   break;
		}
	    } while (keepgoing);
	}
	fmt = (const TCHAR *)fmtw;
    } while (0);

    va_start (ap,fmta);
    _vsntprintf (buf,sizeof(buf)/sizeof(TCHAR)-1,fmt,ap);
    buf [sizeof(buf)/sizeof(TCHAR)-1] = _T('\0');
    va_end (ap);

#if defined(_WIN32_WINNT) && _WIN32_WINNT>=0x0333
    /* this -------------v--- guards NT-specific calls */
    if (GetVersion() < 0x80000000 && IsService())
    {	HANDLE h = RegisterEventSource(0,_T("OPENSSL"));
	const TCHAR *pmsg=buf;
	ReportEvent(h,EVENTLOG_ERROR_TYPE,0,0,0,1,0,&pmsg,0);
	DeregisterEventSource(h);
    }
    else
#endif
    {	MSGBOXPARAMS         m;

	m.cbSize             = sizeof(m);
	m.hwndOwner          = NULL;
	m.lpszCaption        = _T("OpenSSL: FATAL");
	m.dwStyle            = MB_OK;
	m.hInstance          = NULL;
	m.lpszIcon           = IDI_ERROR;
	m.dwContextHelpId    = 0;
	m.lpfnMsgBoxCallback = NULL;
	m.dwLanguageId       = MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US);
	m.lpszText           = buf;

	MessageBoxIndirect (&m);
    }
}
#else
void OPENSSL_showfatal (const char *fmta,...)
{ va_list ap;

    va_start (ap,fmta);
    vfprintf (stderr,fmta,ap);
    va_end (ap);
}
#endif

void OpenSSLDie(const char *file,int line,const char *assertion)
	{
	OPENSSL_showfatal(
		"%s(%d): OpenSSL internal error, assertion failed: %s\n",
		file,line,assertion);
	abort();
	}

void *OPENSSL_stderr(void)	{ return stderr; }

#ifdef OPENSSL_FIPS

void fips_w_lock(void)		{ CRYPTO_w_lock(CRYPTO_LOCK_FIPS); }
void fips_w_unlock(void)	{ CRYPTO_w_unlock(CRYPTO_LOCK_FIPS); }
void fips_r_lock(void)		{ CRYPTO_r_lock(CRYPTO_LOCK_FIPS); }
void fips_r_unlock(void)	{ CRYPTO_r_unlock(CRYPTO_LOCK_FIPS); }

static int fips_started = 0;
static unsigned long fips_thread = 0;

void fips_set_started(void)
	{
	fips_started = 1;
	}

int fips_is_started(void)
	{
	return fips_started;
	}

int fips_is_owning_thread(void)
	{
	int ret = 0;

	if (fips_is_started())
		{
		CRYPTO_r_lock(CRYPTO_LOCK_FIPS2);
		if (fips_thread != 0 && fips_thread == CRYPTO_thread_id())
			ret = 1;
		CRYPTO_r_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

int fips_set_owning_thread(void)
	{
	int ret = 0;

	if (fips_is_started())
		{
		CRYPTO_w_lock(CRYPTO_LOCK_FIPS2);
		if (fips_thread == 0)
			{
			fips_thread = CRYPTO_thread_id();
			ret = 1;
			}
		CRYPTO_w_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

int fips_clear_owning_thread(void)
	{
	int ret = 0;

	if (fips_is_started())
		{
		CRYPTO_w_lock(CRYPTO_LOCK_FIPS2);
		if (fips_thread == CRYPTO_thread_id())
			{
			fips_thread = 0;
			ret = 1;
			}
		CRYPTO_w_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

unsigned char *fips_signature_witness(void)
	{
	extern unsigned char FIPS_signature[];
	return FIPS_signature;
	}
#endif /* OPENSSL_FIPS */

