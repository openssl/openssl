/* dso.h */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_DSO_H
#define HEADER_DSO_H

#include <openssl/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/* These values are used as commands to DSO_ctrl() */
#define DSO_CTRL_GET_FLAGS	1
#define DSO_CTRL_SET_FLAGS	2
#define DSO_CTRL_OR_FLAGS	3

/* These flags control the translation of file-names from canonical to
 * native. Eg. in the CryptoSwift support, the "dl" and "dlfcn"
 * methods will translate "swift" -> "libswift.so" whereas the "win32"
 * method will translate "swift" -> "swift.dll". NB: Until I can figure
 * out how to be more "conventional" with this, the methods will only
 * honour this flag if it looks like it was passed a file without any
 * path and if the filename is small enough.
 */
#define DSO_FLAG_NAME_TRANSLATION 0x01

/* The following flag controls the translation of symbol names to upper
 * case.  This is currently only being implemented for OpenVMS.
 */
#define DSO_FLAG_UPCASE_SYMBOL    0x02


typedef void (*DSO_FUNC_TYPE)(void);

typedef struct dso_st DSO;

typedef struct dso_meth_st
	{
	const char *name;
	/* Loads a shared library */
	int (*dso_load)(DSO *dso, const char *filename);
	/* Unloads a shared library */
	int (*dso_unload)(DSO *dso);
	/* Binds a variable */
	void *(*dso_bind_var)(DSO *dso, const char *symname);
	/* Binds a function - assumes a return type of DSO_FUNC_TYPE.
	 * This should be cast to the real function prototype by the
	 * caller. Platforms that don't have compatible representations
	 * for different prototypes (this is possible within ANSI C)
	 * are highly unlikely to have shared libraries at all, let
	 * alone a DSO_METHOD implemented for them. */
	DSO_FUNC_TYPE (*dso_bind_func)(DSO *dso, const char *symname);

/* I don't think this would actually be used in any circumstances. */
#if 0
	/* Unbinds a variable */
	int (*dso_unbind_var)(DSO *dso, char *symname, void *symptr);
	/* Unbinds a function */
	int (*dso_unbind_func)(DSO *dso, char *symname, DSO_FUNC_TYPE symptr);
#endif
	/* The generic (yuck) "ctrl()" function. NB: Negative return
	 * values (rather than zero) indicate errors. */
	long (*dso_ctrl)(DSO *dso, int cmd, long larg, void *parg);

	/* [De]Initialisation handlers. */
	int (*init)(DSO *dso);
	int (*finish)(DSO *dso);
	} DSO_METHOD;

/**********************************************************************/
/* The low-level handle type used to refer to a loaded shared library */

struct dso_st
	{
	DSO_METHOD *meth;
	/* Standard dlopen uses a (void *). Win32 uses a HANDLE. VMS
	 * doesn't use anything but will need to cache the filename
	 * for use in the dso_bind handler. All in all, let each
	 * method control its own destiny. "Handles" and such go in
	 * a STACK. */
	STACK *meth_data;
	int references;
	int flags;
	/* For use by applications etc ... use this for your bits'n'pieces,
	 * don't touch meth_data! */
	CRYPTO_EX_DATA ex_data;
	};


DSO *	DSO_new(void);
DSO *	DSO_new_method(DSO_METHOD *method);
int	DSO_free(DSO *dso);
int	DSO_flags(DSO *dso);
int	DSO_up(DSO *dso);
long	DSO_ctrl(DSO *dso, int cmd, long larg, void *parg);

void DSO_set_default_method(DSO_METHOD *meth);
DSO_METHOD *DSO_get_default_method(void);
DSO_METHOD *DSO_get_method(DSO *dso);
DSO_METHOD *DSO_set_method(DSO *dso, DSO_METHOD *meth);

/* The all-singing all-dancing load function, you normally pass NULL
 * for the first and third parameters. Use DSO_up and DSO_free for
 * subsequent reference count handling. Any flags passed in will be set
 * in the constructed DSO after its init() function but before the
 * load operation. This will be done with;
 *    DSO_ctrl(dso, DSO_CTRL_SET_FLAGS, flags, NULL); */
DSO *DSO_load(DSO *dso, const char *filename, DSO_METHOD *meth, int flags);

/* This function binds to a variable inside a shared library. */
void *DSO_bind_var(DSO *dso, const char *symname);

/* This function binds to a function inside a shared library. */
DSO_FUNC_TYPE DSO_bind_func(DSO *dso, const char *symname);

/* This method is the default, but will beg, borrow, or steal whatever
 * method should be the default on any particular platform (including
 * DSO_METH_null() if necessary). */
DSO_METHOD *DSO_METHOD_openssl(void);

/* This method is defined for all platforms - if a platform has no
 * DSO support then this will be the only method! */
DSO_METHOD *DSO_METHOD_null(void);

/* If DSO_DLFCN is defined, the standard dlfcn.h-style functions
 * (dlopen, dlclose, dlsym, etc) will be used and incorporated into
 * this method. If not, this method will return NULL. */
DSO_METHOD *DSO_METHOD_dlfcn(void);

/* If DSO_DL is defined, the standard dl.h-style functions (shl_load, 
 * shl_unload, shl_findsym, etc) will be used and incorporated into
 * this method. If not, this method will return NULL. */
DSO_METHOD *DSO_METHOD_dl(void);

/* If WIN32 is defined, use DLLs. If not, return NULL. */
DSO_METHOD *DSO_METHOD_win32(void);

/* If VMS is defined, use shared images. If not, return NULL. */
DSO_METHOD *DSO_METHOD_vms(void);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_DSO_strings(void);

/* Error codes for the DSO functions. */

/* Function codes. */
#define DSO_F_DLFCN_BIND_FUNC				 100
#define DSO_F_DLFCN_BIND_VAR				 101
#define DSO_F_DLFCN_CTRL				 102
#define DSO_F_DLFCN_LOAD				 103
#define DSO_F_DLFCN_UNLOAD				 104
#define DSO_F_DL_BIND_FUNC				 105
#define DSO_F_DL_BIND_VAR				 106
#define DSO_F_DL_CTRL					 107
#define DSO_F_DL_LOAD					 108
#define DSO_F_DL_UNLOAD					 109
#define DSO_F_DSO_BIND_FUNC				 110
#define DSO_F_DSO_BIND_VAR				 111
#define DSO_F_DSO_CTRL					 112
#define DSO_F_DSO_FREE					 113
#define DSO_F_DSO_LOAD					 114
#define DSO_F_DSO_NEW_METHOD				 115
#define DSO_F_DSO_UP					 116
#define DSO_F_VMS_BIND_VAR				 122
#define DSO_F_VMS_CTRL					 123
#define DSO_F_VMS_LOAD					 124
#define DSO_F_VMS_UNLOAD				 125
#define DSO_F_WIN32_BIND_FUNC				 117
#define DSO_F_WIN32_BIND_VAR				 118
#define DSO_F_WIN32_CTRL				 119
#define DSO_F_WIN32_LOAD				 120
#define DSO_F_WIN32_UNLOAD				 121

/* Reason codes. */
#define DSO_R_CTRL_FAILED				 100
#define DSO_R_FILENAME_TOO_BIG				 109
#define DSO_R_FINISH_FAILED				 101
#define DSO_R_LOAD_FAILED				 102
#define DSO_R_NULL_HANDLE				 103
#define DSO_R_STACK_ERROR				 104
#define DSO_R_SYM_FAILURE				 105
#define DSO_R_UNKNOWN_COMMAND				 106
#define DSO_R_UNLOAD_FAILED				 107
#define DSO_R_UNSUPPORTED				 108

#ifdef  __cplusplus
}
#endif
#endif
