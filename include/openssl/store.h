/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_STORE_H
# define HEADER_STORE_H

# include <stdarg.h>
# include <openssl/ossl_typ.h>
# include <openssl/pem.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*-
 *  The main STORE functions.
 *  -------------------------
 *
 *  These allow applications to open a channel to a resource with supported
 *  data (keys, certs, crls, ...), read the data a piece at a time and decide
 *  what to do with it, and finally close.
 */

typedef struct store_ctx_st STORE_CTX;

/*
 * Typedef for the STORE_INFO post processing callback.  This can be used to
 * massage the given STORE_INFO, or to drop it entirely (by returning NULL).
 */
typedef STORE_INFO *(*STORE_post_process_info_fn)(STORE_INFO *, void *);

/*
 * Open a channel given a URI.  The given UI method will be used any time the
 * loader needs extra input, for example when a password or pin is needed, and
 * will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 */
STORE_CTX *STORE_open(const char *uri, const UI_METHOD *ui_method,
                      void *ui_data, STORE_post_process_info_fn post_process,
                      void *post_process_data);

/*
 * Control / fine tune the STORE channel.  |cmd| determines what is to be
 * done, and depends on the underlying loader (use STORE_get0_scheme to
 * determine which loader is used), except for common commands (see below).
 * Each command takes different arguments.
 */
int STORE_ctrl(STORE_CTX *ctx, int cmd, ... /* args */);

/*
 * Common ctrl commands that different loaders may choose to support.
 */
/* Where custom commands start */
# define STORE_C_CUSTOM_START    100

/*
 * Read one data item (a key, a cert, a CRL) that is supported by the STORE
 * functionality, given a context.
 * Returns a STORE_INFO pointer, from which OpenSSL typed data can be extracted
 * with STORE_INFO_get0_PKEY(), STORE_INFO_get0_CERT(), ...
 * NULL is returned on error, which may include that the data found at the URI
 * can't be figured out for certain or is ambiguous.
 */
STORE_INFO *STORE_load(STORE_CTX *ctx);

/*
 * Check if end of data (end of file) is reached
 * Returns 1 on end, 0 otherwise.
 */
int STORE_eof(STORE_CTX *ctx);

/*
 * Close the channel
 * Returns 1 on success, 0 on error.
 */
int STORE_close(STORE_CTX *ctx);


/*-
 *  Extracting OpenSSL types from STORE_INFOs and creating new STORE_INFOs
 *  ----------------------------------------------------------------------
 */

/*
 * Types of data that can be stored in a STORE_INFO.
 * STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 */
# define STORE_INFO_NAME     1   /* char * */
# define STORE_INFO_PARAMS   2   /* EVP_PKEY * */
# define STORE_INFO_PKEY     3   /* EVP_PKEY * */
# define STORE_INFO_CERT     4   /* X509 * */
# define STORE_INFO_CRL      5   /* X509_CRL * */

/* Used to mark the end of data, see below */
# define STORE_INFO_UNSPECIFIED  0

/*
 * Functions to generate STORE_INFOs, one function for each type we
 * support having in them.  Along with each of them, one macro that
 * can be used to determine what types are supported.
 *
 * In all cases, ownership of the object is transfered to the STORE_INFO
 * and will therefore be freed when the STORE_INFO is freed.
 */
STORE_INFO *STORE_INFO_new_NAME(char *name);
int STORE_INFO_set0_NAME_description(STORE_INFO *info, char *desc);
STORE_INFO *STORE_INFO_new_PARAMS(EVP_PKEY *params);
STORE_INFO *STORE_INFO_new_PKEY(EVP_PKEY *pkey);
STORE_INFO *STORE_INFO_new_CERT(X509 *x509);
STORE_INFO *STORE_INFO_new_CRL(X509_CRL *crl);
/*
 * Special STORE_INFO to mark the end of data.
 * Its type is STORE_INFO_UNSPECIFIED and it has no other data.
 */
STORE_INFO *STORE_INFO_new_ENDOFDATA(void);

/*
 * Functions to try to extract data from a STORE_INFO.
 */
int STORE_INFO_get_type(const STORE_INFO *store_info);
const char *STORE_INFO_get0_NAME(const STORE_INFO *store_info);
char *STORE_INFO_get1_NAME(const STORE_INFO *store_info);
const char *STORE_INFO_get0_NAME_description(const STORE_INFO *store_info);
char *STORE_INFO_get1_NAME_description(const STORE_INFO *store_info);
EVP_PKEY *STORE_INFO_get0_PARAMS(const STORE_INFO *store_info);
EVP_PKEY *STORE_INFO_get1_PARAMS(const STORE_INFO *store_info);
EVP_PKEY *STORE_INFO_get0_PKEY(const STORE_INFO *store_info);
EVP_PKEY *STORE_INFO_get1_PKEY(const STORE_INFO *store_info);
X509 *STORE_INFO_get0_CERT(const STORE_INFO *store_info);
X509 *STORE_INFO_get1_CERT(const STORE_INFO *store_info);
X509_CRL *STORE_INFO_get0_CRL(const STORE_INFO *store_info);
X509_CRL *STORE_INFO_get1_CRL(const STORE_INFO *store_info);

const char *STORE_INFO_type_string(int type);

/*
 * Free the STORE_INFO
 */
void STORE_INFO_free(STORE_INFO *store_info);


/*-
 *  Function to register a loader for the given URI scheme.
 *  -------------------------------------------------------
 *
 *  The loader receives all the main components of an URI except for the
 *  scheme.
 */

typedef struct store_loader_st STORE_LOADER;
STORE_LOADER *STORE_LOADER_new(const char *scheme);
const char *STORE_LOADER_get0_scheme(const STORE_LOADER *store_loader);
/* struct store_loader_ctx_st is defined differently by each loader */
typedef struct store_loader_ctx_st STORE_LOADER_CTX;
typedef STORE_LOADER_CTX *(*STORE_open_fn)(const STORE_LOADER *loader,
                                           const char *uri,
                                           const UI_METHOD *ui_method,
                                           void *ui_data);
int STORE_LOADER_set_open(STORE_LOADER *store_loader,
                          STORE_open_fn store_open_function);
typedef int (*STORE_ctrl_fn)(STORE_LOADER_CTX *ctx, int cmd, va_list args);
int STORE_LOADER_set_ctrl(STORE_LOADER *store_loader,
                          STORE_ctrl_fn store_ctrl_function);
typedef STORE_INFO *(*STORE_load_fn)(STORE_LOADER_CTX *ctx,
                                     const UI_METHOD *ui_method, void *ui_data);
int STORE_LOADER_set_load(STORE_LOADER *store_loader,
                          STORE_load_fn store_load_function);
typedef int (*STORE_eof_fn)(STORE_LOADER_CTX *ctx);
int STORE_LOADER_set_eof(STORE_LOADER *store_loader,
                           STORE_eof_fn store_eof_function);
typedef int (*STORE_close_fn)(STORE_LOADER_CTX *ctx);
int STORE_LOADER_set_close(STORE_LOADER *store_loader,
                           STORE_close_fn store_close_function);
void STORE_LOADER_free(STORE_LOADER *store_loader);

int STORE_register_loader(STORE_LOADER *loader);
STORE_LOADER *STORE_unregister_loader(const char *scheme);


/*****************************************************************************/

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_STORE_strings(void);

/* Error codes for the STORE functions. */

/* Function codes. */
# define STORE_F_FILE_GET_PASS                            118
# define STORE_F_FILE_LOAD                                119
# define STORE_F_FILE_LOAD_TRY_DECODE                     124
# define STORE_F_FILE_OPEN                                120
# define STORE_F_STORE_GET0_LOADER_INT                    100
# define STORE_F_STORE_INFO_GET1_CERT                     101
# define STORE_F_STORE_INFO_GET1_CRL                      102
# define STORE_F_STORE_INFO_GET1_NAME                     103
# define STORE_F_STORE_INFO_GET1_NAME_DESCRIPTION         135
# define STORE_F_STORE_INFO_GET1_PARAMS                   104
# define STORE_F_STORE_INFO_GET1_PKEY                     105
# define STORE_F_STORE_INFO_NEW_CERT                      106
# define STORE_F_STORE_INFO_NEW_CRL                       107
# define STORE_F_STORE_INFO_NEW_EMBEDDED                  123
# define STORE_F_STORE_INFO_NEW_ENDOFDATA                 108
# define STORE_F_STORE_INFO_NEW_NAME                      109
# define STORE_F_STORE_INFO_NEW_PARAMS                    110
# define STORE_F_STORE_INFO_NEW_PKEY                      111
# define STORE_F_STORE_INFO_SET0_NAME_DESCRIPTION         134
# define STORE_F_STORE_INIT_ONCE                          112
# define STORE_F_STORE_LOADER_NEW                         113
# define STORE_F_STORE_OPEN                               114
# define STORE_F_STORE_OPEN_INT                           115
# define STORE_F_STORE_REGISTER_LOADER_INT                117
# define STORE_F_STORE_UNREGISTER_LOADER_INT              116
# define STORE_F_TRY_DECODE_PARAMS                        121
# define STORE_F_TRY_DECODE_PKCS12                        122
# define STORE_F_TRY_DECODE_PKCS8ENCRYPTED                125

/* Reason codes. */
# define STORE_R_AMBIGUOUS_CONTENT_TYPE                   107
# define STORE_R_BAD_PASSWORD_READ                        115
# define STORE_R_ERROR_VERIFYING_PKCS12_MAC               113
# define STORE_R_INVALID_SCHEME                           106
# define STORE_R_IS_NOT_A                                 112
# define STORE_R_NOT_A_CERTIFICATE                        100
# define STORE_R_NOT_A_CRL                                101
# define STORE_R_NOT_A_KEY                                102
# define STORE_R_NOT_A_NAME                               103
# define STORE_R_NOT_PARAMETERS                           104
# define STORE_R_PASSPHRASE_CALLBACK_ERROR                114
# define STORE_R_PATH_MUST_BE_ABSOLUTE                    108
# define STORE_R_UI_PROCESS_INTERRUPTED_OR_CANCELLED      109
# define STORE_R_UNREGISTERED_SCHEME                      105
# define STORE_R_UNSUPPORTED_CONTENT_TYPE                 110
# define STORE_R_URI_AUTHORITY_UNSUPPORED                 111

# ifdef  __cplusplus
}
# endif
#endif
