/* crypto/ui/ui.h -*- mode:C; c-file-style: "eay" -*- */
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

#ifndef HEADER_UI_H
#define HEADER_UI_H

#include <openssl/crypto.h>
#include <openssl/safestack.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* The UI type is a holder for a specific user interface session.  It can
   contain an illimited number of informational or error strings as well
   as things to prompt for, both passwords (noecho mode) and others (echo
   mode), and verification of the same.  All of these are called strings,
   and are further described below. */
typedef struct ui_st UI;

/* All instances of UI have a reference to a method structure, which is a
   ordered vector of functions that implement the lower level things to do.
   There is an instruction on the implementation further down, in the section
   for method implementors. */
typedef struct ui_method_st UI_METHOD;


/* All the following functions return -1 or NULL on error.  When everything is
   fine, they return 0, a positive value or a non-NULL pointer, all depending
   on their purpose. */

/* Creators and destructor.   */
UI *UI_new(void);
UI *UI_new_method(const UI_METHOD *method);
void UI_free(UI *ui);

/* The following functions are used to add strings to be printed and prompt
   strings to prompt for data.  The names are UI_{add,dup}_<function>_string,
   with the following meanings:
	add	add a text or prompt string.  The pointers given to these
		functions are used verbatim, no copying is done.
	dup	make a copy of the text or prompt string, then add the copy
		to the collection of strings in the user interface.
	<function>
		The function is a name for the functionality that the given
		string shall be used for.  It can be one of:
			input	use the string as data prompt.
			verify	use the string as verification prompt.  This
				is used to verify a previous input.
			info	use the string for informational output.
			error	use the string for error output.
   Honestly, there's currently no difference between info and error for the
   moment.

   All of the functions in this group take a UI and a string.  The input and
   verify addition functions also take an echo flag, a buffer for the result
   to end up with, a minimum input size and a maximum input size (the result
   buffer MUST be large enough to be able to contain the maximum number of
   characters).  Additionally, the verify addition functions takes another
   buffer to compare the result against.

   On success, the all return an index of the added information.  That index
   is usefull when retrieving results with UI_get0_result(). */
int UI_add_input_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize);
int UI_dup_input_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize);
int UI_add_verify_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize, const char *test_buf);
int UI_dup_verify_string(UI *ui, const char *prompt, int echo_p,
	char *result_buf, int minsize, int maxsize, const char *test_buf);
int UI_add_info_string(UI *ui, const char *text);
int UI_dup_info_string(UI *ui, const char *text);
int UI_add_error_string(UI *ui, const char *text);
int UI_dup_error_string(UI *ui, const char *text);

/* The following function is used to store a pointer to user-specific data.
   Any previous such pointer will be returned and replaced.

   For callback purposes, this function makes a lot more sense than using
   ex_data, since the latter requires that different parts of OpenSSL or
   applications share the same ex_data index.

   Note that the UI_OpenSSL() method completely ignores the user data.
   Other methods may not, however.  */
void *UI_add_user_data(UI *ui, void *user_data);
/* We need a user data retrieving function as well.  */
void *UI_get0_user_data(UI *ui);

/* Return the result associated with a prompt given with the index i. */
const char *UI_get0_result(UI *ui, int i);

/* When all strings have been added, process the whole thing. */
int UI_process(UI *ui);

/* Some methods may use extra data */
#define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
#define UI_get_app_data(s)             UI_get_ex_data(s,0)
int UI_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int UI_set_ex_data(UI *r,int idx,void *arg);
void *UI_get_ex_data(UI *r, int idx);

/* Use specific methods instead of the built-in one */
void UI_set_default_method(const UI_METHOD *meth);
const UI_METHOD *UI_get_default_method(void);
const UI_METHOD *UI_get_method(UI *ui);
const UI_METHOD *UI_set_method(UI *ui, const UI_METHOD *meth);

/* The method with all the built-in thingies */
UI_METHOD *UI_OpenSSL(void);


/* ---------- For method writers ---------- */
/* A method contains a number of functions that implement the low level
   of the User Interface.  The functions are:

	an opener	This function starts a session, maybe by opening
			a channel to a tty, or by opening a window.
	a writer	This function is called to write a given string,
			maybe to the tty, maybe as a field label in a
			window.
	a reader	This function is called to read a given prompt,
			maybe from the tty, maybe from a field in a
			window.  Note that it's called wth all string
			structures, not only the prompt ones, so it must
			check such things itself.
	a closer	This function closes the session, maybe by closing
			the channel to the tty, or closing the window.

   The way this is used, the opener is first called, then the writer for all
   strings, then the reader for all strings and finally the closer.  Note that
   if you want to prompt from a terminal or other command line interface, the
   best is to have the reader also write the prompts instead of having the
   writer do it.
   All method functions take a UI as argument.  Additionally, the writer and
   the reader take a UI_STRING. */

/* The UI_STRING type is the data structure that contains all the needed info
   about a string or a prompt, including test data for a verification prompt.
*/
DECLARE_STACK_OF(UI_STRING)
typedef struct ui_string_st UI_STRING;

/* The different types of strings that are currently supported.
   This is only needed by method authors. */
enum UI_string_types
	{
	UI_NONE=0,
	UI_STRING_ECHO,		/* Prompt for a string */
	UI_STRING_NOECHO,	/* Prompt for a hidden string */
	UI_VERIFY_ECHO,		/* Prompt for a string and verify */
	UI_VERIFY_NOECHO,	/* Prompt for a hidden string and verify */
	UI_INFO,		/* Send info to the user */
	UI_ERROR		/* Send an error message to the user */
	};

/* Create and manipulate methods */
UI_METHOD *UI_create_method(void);
int UI_method_set_opener(UI_METHOD *method, int (*opener)(UI *ui));
int UI_method_set_writer(UI_METHOD *method, int (*writer)(UI *ui, UI_STRING *uis));
int UI_method_set_reader(UI_METHOD *method, int (*reader)(UI *ui, UI_STRING *uis));
int UI_method_set_closer(UI_METHOD *method, int (*closer)(UI *ui));
int (*UI_method_get_opener(UI_METHOD *method))(UI*);
int (*UI_method_get_writer(UI_METHOD *method))(UI*,UI_STRING*);
int (*UI_method_get_reader(UI_METHOD *method))(UI*,UI_STRING*);
int (*UI_method_get_closer(UI_METHOD *method))(UI*);

/* The following functions are helpers for method writers to access relevant
   data from a UI_STRING. */

/* Return type type of the UI_STRING */
enum UI_string_types UI_get_string_type(UI_STRING *uis);
/* Return the actual string to output (the prompt, info or error) */
const char *UI_get0_output_string(UI_STRING *uis);
/* Return the result of a prompt */
const char *UI_get0_result_string(UI_STRING *uis);
/* Return the string to test the result against.  Only useful with verifies. */
const char *UI_get0_test_string(UI_STRING *uis);
/* Return the required minimum size of the result */
int UI_get_result_minsize(UI_STRING *uis);
/* Return the required maximum size of the result */
int UI_get_result_maxsize(UI_STRING *uis);
/* Set the result of a UI_STRING. */
int UI_set_result(UI_STRING *uis, char *result);


/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_UI_strings(void);

/* Error codes for the UI functions. */

/* Function codes. */
#define UI_F_GENERAL_ALLOCATE_STRING			 100
#define UI_F_UI_DUP_ERROR_STRING			 101
#define UI_F_UI_DUP_INFO_STRING				 102
#define UI_F_UI_DUP_INPUT_STRING			 103
#define UI_F_UI_DUP_VERIFY_STRING			 106
#define UI_F_UI_GET0_RESULT				 107
#define UI_F_UI_NEW_METHOD				 104
#define UI_F_UI_SET_RESULT				 105

/* Reason codes. */
#define UI_R_INDEX_TOO_LARGE				 102
#define UI_R_INDEX_TOO_SMALL				 103
#define UI_R_RESULT_TOO_LARGE				 100
#define UI_R_RESULT_TOO_SMALL				 101

#ifdef  __cplusplus
}
#endif
#endif
