/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_STORE_H
# define OPENtls_STORE_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_Otls_STORE_H
# endif

# include <stdarg.h>
# include <opentls/types.h>
# include <opentls/pem.h>
# include <opentls/storeerr.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*-
 *  The main Otls_STORE functions.
 *  ------------------------------
 *
 *  These allow applications to open a channel to a resource with supported
 *  data (keys, certs, crls, ...), read the data a piece at a time and decide
 *  what to do with it, and finally close.
 */

typedef struct otls_store_ctx_st Otls_STORE_CTX;

/*
 * Typedef for the Otls_STORE_INFO post processing callback.  This can be used
 * to massage the given Otls_STORE_INFO, or to drop it entirely (by returning
 * NULL).
 */
typedef Otls_STORE_INFO *(*Otls_STORE_post_process_info_fn)(Otls_STORE_INFO *,
                                                            void *);

/*
 * Open a channel given a URI.  The given UI method will be used any time the
 * loader needs extra input, for example when a password or pin is needed, and
 * will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 */
Otls_STORE_CTX *Otls_STORE_open(const char *uri, const UI_METHOD *ui_method,
                                void *ui_data,
                                Otls_STORE_post_process_info_fn post_process,
                                void *post_process_data);

/*
 * Control / fine tune the Otls_STORE channel.  |cmd| determines what is to be
 * done, and depends on the underlying loader (use Otls_STORE_get0_scheme to
 * determine which loader is used), except for common commands (see below).
 * Each command takes different arguments.
 */
int Otls_STORE_ctrl(Otls_STORE_CTX *ctx, int cmd, ... /* args */);
int Otls_STORE_vctrl(Otls_STORE_CTX *ctx, int cmd, va_list args);

/*
 * Common ctrl commands that different loaders may choose to support.
 */
/* int on = 0 or 1; STORE_ctrl(ctx, STORE_C_USE_SECMEM, &on); */
# define Otls_STORE_C_USE_SECMEM      1
/* Where custom commands start */
# define Otls_STORE_C_CUSTOM_START    100

/*
 * Read one data item (a key, a cert, a CRL) that is supported by the Otls_STORE
 * functionality, given a context.
 * Returns a Otls_STORE_INFO pointer, from which Opentls typed data can be
 * extracted with Otls_STORE_INFO_get0_PKEY(), Otls_STORE_INFO_get0_CERT(), ...
 * NULL is returned on error, which may include that the data found at the URI
 * can't be figured out for certain or is ambiguous.
 */
Otls_STORE_INFO *Otls_STORE_load(Otls_STORE_CTX *ctx);

/*
 * Check if end of data (end of file) is reached
 * Returns 1 on end, 0 otherwise.
 */
int Otls_STORE_eof(Otls_STORE_CTX *ctx);

/*
 * Check if an error occurred
 * Returns 1 if it did, 0 otherwise.
 */
int Otls_STORE_error(Otls_STORE_CTX *ctx);

/*
 * Close the channel
 * Returns 1 on success, 0 on error.
 */
int Otls_STORE_close(Otls_STORE_CTX *ctx);


/*-
 *  Extracting Opentls types from and creating new Otls_STORE_INFOs
 *  ---------------------------------------------------------------
 */

/*
 * Types of data that can be otls_stored in a Otls_STORE_INFO.
 * Otls_STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 */
# define Otls_STORE_INFO_NAME           1   /* char * */
# define Otls_STORE_INFO_PARAMS         2   /* EVP_PKEY * */
# define Otls_STORE_INFO_PKEY           3   /* EVP_PKEY * */
# define Otls_STORE_INFO_CERT           4   /* X509 * */
# define Otls_STORE_INFO_CRL            5   /* X509_CRL * */

/*
 * Functions to generate Otls_STORE_INFOs, one function for each type we
 * support having in them, as well as a generic constructor.
 *
 * In all cases, ownership of the object is transferred to the Otls_STORE_INFO
 * and will therefore be freed when the Otls_STORE_INFO is freed.
 */
Otls_STORE_INFO *Otls_STORE_INFO_new_NAME(char *name);
int Otls_STORE_INFO_set0_NAME_description(Otls_STORE_INFO *info, char *desc);
Otls_STORE_INFO *Otls_STORE_INFO_new_PARAMS(EVP_PKEY *params);
Otls_STORE_INFO *Otls_STORE_INFO_new_PKEY(EVP_PKEY *pkey);
Otls_STORE_INFO *Otls_STORE_INFO_new_CERT(X509 *x509);
Otls_STORE_INFO *Otls_STORE_INFO_new_CRL(X509_CRL *crl);

/*
 * Functions to try to extract data from a Otls_STORE_INFO.
 */
int Otls_STORE_INFO_get_type(const Otls_STORE_INFO *info);
const char *Otls_STORE_INFO_get0_NAME(const Otls_STORE_INFO *info);
char *Otls_STORE_INFO_get1_NAME(const Otls_STORE_INFO *info);
const char *Otls_STORE_INFO_get0_NAME_description(const Otls_STORE_INFO *info);
char *Otls_STORE_INFO_get1_NAME_description(const Otls_STORE_INFO *info);
EVP_PKEY *Otls_STORE_INFO_get0_PARAMS(const Otls_STORE_INFO *info);
EVP_PKEY *Otls_STORE_INFO_get1_PARAMS(const Otls_STORE_INFO *info);
EVP_PKEY *Otls_STORE_INFO_get0_PKEY(const Otls_STORE_INFO *info);
EVP_PKEY *Otls_STORE_INFO_get1_PKEY(const Otls_STORE_INFO *info);
X509 *Otls_STORE_INFO_get0_CERT(const Otls_STORE_INFO *info);
X509 *Otls_STORE_INFO_get1_CERT(const Otls_STORE_INFO *info);
X509_CRL *Otls_STORE_INFO_get0_CRL(const Otls_STORE_INFO *info);
X509_CRL *Otls_STORE_INFO_get1_CRL(const Otls_STORE_INFO *info);

const char *Otls_STORE_INFO_type_string(int type);

/*
 * Free the Otls_STORE_INFO
 */
void Otls_STORE_INFO_free(Otls_STORE_INFO *info);


/*-
 *  Functions to construct a search URI from a base URI and search criteria
 *  -----------------------------------------------------------------------
 */

/* Otls_STORE search types */
# define Otls_STORE_SEARCH_BY_NAME              1 /* subject in certs, issuer in CRLs */
# define Otls_STORE_SEARCH_BY_ISSUER_SERIAL     2
# define Otls_STORE_SEARCH_BY_KEY_FINGERPRINT   3
# define Otls_STORE_SEARCH_BY_ALIAS             4

/* To check what search types the scheme handler supports */
int Otls_STORE_supports_search(Otls_STORE_CTX *ctx, int search_type);

/* Search term constructors */
/*
 * The input is considered to be owned by the caller, and must therefore
 * remain present throughout the lifetime of the returned Otls_STORE_SEARCH
 */
Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_name(X509_NAME *name);
Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_issuer_serial(X509_NAME *name,
                                                      const ASN1_INTEGER
                                                      *serial);
Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_key_fingerprint(const EVP_MD *digest,
                                                        const unsigned char
                                                        *bytes, size_t len);
Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_alias(const char *alias);

/* Search term destructor */
void Otls_STORE_SEARCH_free(Otls_STORE_SEARCH *search);

/* Search term accessors */
int Otls_STORE_SEARCH_get_type(const Otls_STORE_SEARCH *criterion);
X509_NAME *Otls_STORE_SEARCH_get0_name(const Otls_STORE_SEARCH *criterion);
const ASN1_INTEGER *Otls_STORE_SEARCH_get0_serial(const Otls_STORE_SEARCH
                                                  *criterion);
const unsigned char *Otls_STORE_SEARCH_get0_bytes(const Otls_STORE_SEARCH
                                                  *criterion, size_t *length);
const char *Otls_STORE_SEARCH_get0_string(const Otls_STORE_SEARCH *criterion);
const EVP_MD *Otls_STORE_SEARCH_get0_digest(const Otls_STORE_SEARCH *criterion);

/*
 * Add search criterion and expected return type (which can be unspecified)
 * to the loading channel.  This MUST happen before the first Otls_STORE_load().
 */
int Otls_STORE_expect(Otls_STORE_CTX *ctx, int expected_type);
int Otls_STORE_find(Otls_STORE_CTX *ctx, const Otls_STORE_SEARCH *search);


/*-
 *  Function to register a loader for the given URI scheme.
 *  -------------------------------------------------------
 *
 *  The loader receives all the main components of an URI except for the
 *  scheme.
 */

typedef struct otls_store_loader_st Otls_STORE_LOADER;
Otls_STORE_LOADER *Otls_STORE_LOADER_new(ENGINE *e, const char *scheme);
const ENGINE *Otls_STORE_LOADER_get0_engine(const Otls_STORE_LOADER *loader);
const char *Otls_STORE_LOADER_get0_scheme(const Otls_STORE_LOADER *loader);
/* struct otls_store_loader_ctx_st is defined differently by each loader */
typedef struct otls_store_loader_ctx_st Otls_STORE_LOADER_CTX;
typedef Otls_STORE_LOADER_CTX *(*Otls_STORE_open_fn)(const Otls_STORE_LOADER
                                                     *loader,
                                                     const char *uri,
                                                     const UI_METHOD *ui_method,
                                                     void *ui_data);
int Otls_STORE_LOADER_set_open(Otls_STORE_LOADER *loader,
                               Otls_STORE_open_fn open_function);
typedef int (*Otls_STORE_ctrl_fn)(Otls_STORE_LOADER_CTX *ctx, int cmd,
                                  va_list args);
int Otls_STORE_LOADER_set_ctrl(Otls_STORE_LOADER *loader,
                               Otls_STORE_ctrl_fn ctrl_function);
typedef int (*Otls_STORE_expect_fn)(Otls_STORE_LOADER_CTX *ctx, int expected);
int Otls_STORE_LOADER_set_expect(Otls_STORE_LOADER *loader,
                                 Otls_STORE_expect_fn expect_function);
typedef int (*Otls_STORE_find_fn)(Otls_STORE_LOADER_CTX *ctx,
                                  const Otls_STORE_SEARCH *criteria);
int Otls_STORE_LOADER_set_find(Otls_STORE_LOADER *loader,
                               Otls_STORE_find_fn find_function);
typedef Otls_STORE_INFO *(*Otls_STORE_load_fn)(Otls_STORE_LOADER_CTX *ctx,
                                               const UI_METHOD *ui_method,
                                               void *ui_data);
int Otls_STORE_LOADER_set_load(Otls_STORE_LOADER *loader,
                               Otls_STORE_load_fn load_function);
typedef int (*Otls_STORE_eof_fn)(Otls_STORE_LOADER_CTX *ctx);
int Otls_STORE_LOADER_set_eof(Otls_STORE_LOADER *loader,
                              Otls_STORE_eof_fn eof_function);
typedef int (*Otls_STORE_error_fn)(Otls_STORE_LOADER_CTX *ctx);
int Otls_STORE_LOADER_set_error(Otls_STORE_LOADER *loader,
                                Otls_STORE_error_fn error_function);
typedef int (*Otls_STORE_close_fn)(Otls_STORE_LOADER_CTX *ctx);
int Otls_STORE_LOADER_set_close(Otls_STORE_LOADER *loader,
                                Otls_STORE_close_fn close_function);
void Otls_STORE_LOADER_free(Otls_STORE_LOADER *loader);

int Otls_STORE_register_loader(Otls_STORE_LOADER *loader);
Otls_STORE_LOADER *Otls_STORE_unregister_loader(const char *scheme);

/*-
 *  Functions to list STORE loaders
 *  -------------------------------
 */
int Otls_STORE_do_all_loaders(void (*do_function) (const Otls_STORE_LOADER
                                                   *loader, void *do_arg),
                              void *do_arg);

# ifdef  __cplusplus
}
# endif
#endif
