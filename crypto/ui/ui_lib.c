/* crypto/ui/ui_lib.c -*- mode:C; c-file-style: "eay" -*- */
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

#include <openssl/e_os2.h>
/* The following defines enable the declaration of strdup(), which is an
   extended function according to X/Open. */
#ifdef OPENSSL_SYS_VMS_DECC
# define _XOPEN_SOURCE_EXTENDED
#endif
#ifdef OPENSSL_SYS_UNIX
# define __USE_XOPEN_EXTENDED	/* For Linux and probably anything GNU */
#endif
#include <string.h>

#include <openssl/ui.h>
#include <openssl/err.h>
#include "ui_locl.h"

IMPLEMENT_STACK_OF(UI_STRING_ST)

static const UI_METHOD *default_UI_meth=NULL;
static int ui_meth_num=0;
static STACK_OF(CRYPTO_EX_DATA_FUNCS) *ui_meth=NULL;

UI *UI_new(void)
	{
	return(UI_new_method(NULL));
	}

UI *UI_new_method(const UI_METHOD *method)
	{
	UI *ret;

	ret=(UI *)OPENSSL_malloc(sizeof(UI));
	if (ret == NULL)
		{
		UIerr(UI_F_UI_NEW_METHOD,ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	if (method == NULL)
		ret->meth=UI_get_default_method();
	else
		ret->meth=method;

	ret->strings=NULL;
	return ret;
	}

static void free_string(UI_STRING *uis)
	{
	if (uis->flags & OUT_STRING_FREEABLE)
		OPENSSL_free((char *)uis->out_string);
	OPENSSL_free(uis);
	}

void UI_free(UI *ui)
	{
	sk_UI_STRING_pop_free(ui->strings,free_string);
	OPENSSL_free(ui);
	}

static int allocate_string_stack(UI *ui)
	{
	if (ui->strings == NULL)
		{
		ui->strings=sk_UI_STRING_new_null();
		if (ui->strings == NULL)
			{
			return -1;
			}
		}
	return 0;
	}

static int general_allocate_string(UI *ui, const char *prompt,
	int prompt_freeable, enum UI_string_types type,
	char *result_buf, int minsize, int maxsize, const char *test_buf)
	{
	int ret=-1;

	if (prompt == NULL)
		{
		UIerr(UI_F_GENERAL_ALLOCATE_STRING,ERR_R_PASSED_NULL_PARAMETER);
		}
	else if (allocate_string_stack(ui) >= 0)
		{
		UI_STRING *s=(UI_STRING *)OPENSSL_malloc(sizeof(UI_STRING));
		s->out_string=prompt;
		s->flags=prompt_freeable ? OUT_STRING_FREEABLE : 0;
		s->type=type;
		s->result_buf=result_buf;
		s->result_minsize=minsize;
		s->result_maxsize=maxsize;
		s->test_buf=test_buf;
		ret=sk_UI_STRING_push(ui->strings, s);
		}
	return ret;
	}

/* Returns the index to the place in the stack or 0 for error.  Uses a
   direct reference to the prompt.  */
int UI_add_input_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize)
	{
	return general_allocate_string(ui, prompt, 0,
		echo_p?UI_STRING_ECHO:UI_STRING_NOECHO,
		result_buf, minsize, maxsize, NULL);
	}

/* Same as UI_add_input_string(), excepts it takes a copy of the prompt */
int UI_dup_input_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize)
	{
	char *prompt_copy=NULL;

	if (prompt)
		{
		prompt_copy=strdup(prompt);
		if (prompt_copy == NULL)
			{
			UIerr(UI_F_UI_DUP_INPUT_STRING,ERR_R_MALLOC_FAILURE);
			return 0;
			}
		}
	
	return general_allocate_string(ui, prompt, 1,
		echo_p?UI_STRING_ECHO:UI_STRING_NOECHO,
		result_buf, minsize, maxsize, NULL);
	}

int UI_add_verify_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize, const char *test_buf)
	{
	return general_allocate_string(ui, prompt, 0,
		echo_p?UI_VERIFY_ECHO:UI_VERIFY_NOECHO,
		result_buf, minsize, maxsize, test_buf);
	}

int UI_dup_verify_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize, const char *test_buf)
	{
	char *prompt_copy=NULL;

	if (prompt)
		{
		prompt_copy=strdup(prompt);
		if (prompt_copy == NULL)
			{
			UIerr(UI_F_UI_DUP_VERIFY_STRING,ERR_R_MALLOC_FAILURE);
			return -1;
			}
		}
	
	return general_allocate_string(ui, prompt, 1,
		echo_p?UI_VERIFY_ECHO:UI_VERIFY_NOECHO,
		result_buf, minsize, maxsize, test_buf);
	}

int UI_add_info_string(UI *ui, const char *text)
	{
	return general_allocate_string(ui, text, 0, UI_INFO, NULL, 0, 0, NULL);
	}

int UI_dup_info_string(UI *ui, const char *text)
	{
	char *text_copy=NULL;

	if (text)
		{
		text_copy=strdup(text);
		if (text_copy == NULL)
			{
			UIerr(UI_F_UI_DUP_INFO_STRING,ERR_R_MALLOC_FAILURE);
			return -1;
			}
		}

	return general_allocate_string(ui, text, 1, UI_INFO, NULL, 0, 0, NULL);
	}

int UI_add_error_string(UI *ui, const char *text)
	{
	return general_allocate_string(ui, text, 0, UI_ERROR, NULL, 0, 0,
		NULL);
	}

int UI_dup_error_string(UI *ui, const char *text)
	{
	char *text_copy=NULL;

	if (text)
		{
		text_copy=strdup(text);
		if (text_copy == NULL)
			{
			UIerr(UI_F_UI_DUP_ERROR_STRING,ERR_R_MALLOC_FAILURE);
			return -1;
			}
		}
	return general_allocate_string(ui, text_copy, 1, UI_ERROR, NULL, 0, 0,
		NULL);
	}

void *UI_add_user_data(UI *ui, void *user_data)
	{
	void *old_data = ui->user_data;
	ui->user_data = user_data;
	return old_data;
	}

void *UI_get0_user_data(UI *ui)
	{
	return ui->user_data;
	}

const char *UI_get0_result(UI *ui, int i)
	{
	if (i < 0)
		{
		UIerr(UI_F_UI_GET0_RESULT,UI_R_INDEX_TOO_SMALL);
		return NULL;
		}
	if (i >= sk_UI_STRING_num(ui->strings))
		{
		UIerr(UI_F_UI_GET0_RESULT,UI_R_INDEX_TOO_LARGE);
		return NULL;
		}
	return UI_get0_result_string(sk_UI_STRING_value(ui->strings, i));
	}

int UI_process(UI *ui)
	{
	int i, ok=0;

	if (ui->meth->ui_open_session && !ui->meth->ui_open_session(ui))
		return -1;

	for(i=0; i<sk_UI_STRING_num(ui->strings); i++)
		{
		if (ui->meth->ui_write_string
			&& !ui->meth->ui_write_string(ui,
				sk_UI_STRING_value(ui->strings, i)))
			{
			ok=-1;
			goto err;
			}
		}

	for(i=0; i<sk_UI_STRING_num(ui->strings); i++)
		{
		if (ui->meth->ui_read_string
			&& !ui->meth->ui_read_string(ui,
				sk_UI_STRING_value(ui->strings, i)))
			{
			ok=-1;
			goto err;
			}
		}
 err:
	if (ui->meth->ui_close_session && !ui->meth->ui_close_session(ui))
		return -1;
	return ok;
	}

int UI_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	     CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
        {
	ui_meth_num++;
	return(CRYPTO_get_ex_new_index(ui_meth_num-1,
		&ui_meth,argl,argp,new_func,dup_func,free_func));
        }

int UI_set_ex_data(UI *r, int idx, void *arg)
	{
	return(CRYPTO_set_ex_data(&r->ex_data,idx,arg));
	}

void *UI_get_ex_data(UI *r, int idx)
	{
	return(CRYPTO_get_ex_data(&r->ex_data,idx));
	}

void UI_set_default_method(const UI_METHOD *meth)
	{
	default_UI_meth=meth;
	}

const UI_METHOD *UI_get_default_method(void)
	{
	if (default_UI_meth == NULL)
		{
		default_UI_meth=UI_OpenSSL();
		}
	return default_UI_meth;
	}

const UI_METHOD *UI_get_method(UI *ui)
	{
	return ui->meth;
	}

const UI_METHOD *UI_set_method(UI *ui, const UI_METHOD *meth)
	{
	ui->meth=meth;
	return ui->meth;
	}


UI_METHOD *UI_create_method(void)
	{
	return (UI_METHOD *)OPENSSL_malloc(sizeof(UI_METHOD));
	}

int UI_method_set_opener(UI_METHOD *method, int (*opener)(UI *ui))
	{
	if (method)
		{
		method->ui_open_session = opener;
		return 0;
		}
	else
		return -1;
	}

int UI_method_set_writer(UI_METHOD *method, int (*writer)(UI *ui, UI_STRING *uis))
	{
	if (method)
		{
		method->ui_write_string = writer;
		return 0;
		}
	else
		return -1;
	}

int UI_method_set_reader(UI_METHOD *method, int (*reader)(UI *ui, UI_STRING *uis))
	{
	if (method)
		{
		method->ui_read_string = reader;
		return 0;
		}
	else
		return -1;
	}

int UI_method_set_closer(UI_METHOD *method, int (*closer)(UI *ui))
	{
	if (method)
		{
		method->ui_close_session = closer;
		return 0;
		}
	else
		return -1;
	}

int (*UI_method_get_opener(UI_METHOD *method))(UI*)
	{
	if (method)
		return method->ui_open_session;
	else
		return NULL;
	}

int (*UI_method_get_writer(UI_METHOD *method))(UI*,UI_STRING*)
	{
	if (method)
		return method->ui_write_string;
	else
		return NULL;
	}

int (*UI_method_get_reader(UI_METHOD *method))(UI*,UI_STRING*)
	{
	if (method)
		return method->ui_read_string;
	else
		return NULL;
	}

int (*UI_method_get_closer(UI_METHOD *method))(UI*)
	{
	if (method)
		return method->ui_close_session;
	else
		return NULL;
	}

enum UI_string_types UI_get_string_type(UI_STRING *uis)
	{
	if (!uis)
		return UI_NONE;
	return uis->type;
	}

const char *UI_get0_output_string(UI_STRING *uis)
	{
	if (!uis)
		return NULL;
	return uis->out_string;
	}

const char *UI_get0_result_string(UI_STRING *uis)
	{
	if (!uis)
		return NULL;
	switch(uis->type)
		{
	case UI_STRING_ECHO:
	case UI_STRING_NOECHO:
	case UI_VERIFY_ECHO:
	case UI_VERIFY_NOECHO:
		return uis->result_buf;
	default:
		return NULL;
		}
	}

const char *UI_get0_test_string(UI_STRING *uis)
	{
	if (!uis)
		return NULL;
	return uis->test_buf;
	}

int UI_get_result_minsize(UI_STRING *uis)
	{
	if (!uis)
		return -1;
	return uis->result_minsize;
	}

int UI_get_result_maxsize(UI_STRING *uis)
	{
	if (!uis)
		return -1;
	return uis->result_maxsize;
	}

int UI_set_result(UI_STRING *uis, char *result)
	{
	int l = strlen(result);

	if (!uis)
		return -1;
	if (l < uis->result_minsize)
		{
		UIerr(UI_F_UI_SET_RESULT,UI_R_RESULT_TOO_SMALL);
		return -1;
		}
	if (l > uis->result_maxsize)
		{
		UIerr(UI_F_UI_SET_RESULT,UI_R_RESULT_TOO_LARGE);
		return -1;
		}

	if (!uis->result_buf)
		{
		uis->result_buf = OPENSSL_malloc(uis->result_maxsize+1);
		}

	if (!uis->result_buf)
		{
		UIerr(UI_F_UI_NEW_METHOD,ERR_R_MALLOC_FAILURE);
		return -1;
		}

	strcpy(uis->result_buf, result);
	return 0;
	}
