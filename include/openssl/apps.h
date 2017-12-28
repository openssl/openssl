/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_APPS_H
# define HEADER_APPS_H

# include <openssl/opensslconf.h>

# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
#  include <conio.h>
# endif

# if defined(OPENSSL_SYS_MSDOS) && !defined(_WIN32)
#  define _kbhit kbhit
# endif

# include "internal/nelem.h"
# include <assert.h>

# include "../../e_os.h"
# include <openssl/e_os2.h>
# include <openssl/ossl_typ.h>
# include <openssl/bio.h>
# include <openssl/x509.h>
# include <openssl/conf.h>
# include <openssl/txt_db.h>
# include <openssl/engine.h>
# include <openssl/ocsp.h>
# include <signal.h>

# if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
#  define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
# else
#  define openssl_fdset(a,b) FD_SET(a, b)
# endif

# ifdef OPENSSL_BUILD_SHLIBSECAPP
#  undef OPENSSL_EXTERN
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# endif

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * quick macro when you need to pass an unsigned char instead of a char.
 * this is true for some implementations of the is*() functions, for
 * example.
 */
#define _UC(c) ((unsigned char)(c))

/* from apps.c */

char *app_getprog(void);
char *app_progname(const char *argv0);
extern const unsigned char tls13_aes128gcmsha256_id[];
extern const unsigned char tls13_aes256gcmsha384_id[];

void app_set_bio_err(BIO *bio);
BIO *app_get_bio_err(void);
BIO *dup_bio_in(int format);
BIO *dup_bio_out(int format);
BIO *dup_bio_err(int format);
BIO *bio_open_owner(const char *filename, int format, int private);
BIO *bio_open_default(const char *filename, char mode, int format);
BIO *bio_open_default_quiet(const char *filename, char mode, int format);

CONF *app_load_config(const char *filename);
CONF *app_load_config_quiet(const char *filename);
int app_load_modules_(const CONF *config, const char *default_config_file);
#ifndef OPENSSL_BUILD_SHLIBSECAPP
extern char *default_config_file;
#define app_load_modules(config) app_load_modules_(config, default_config_file)
#endif

void unbuffer(FILE *fp);
void wait_for_async(SSL *s);
# if defined(OPENSSL_SYS_MSDOS)
int has_stdin_waiting(void);
# endif

void corrupt_signature(const ASN1_STRING *signature);
int set_cert_times(X509 *x, const char *startdate, const char *enddate,
                   int days);

typedef struct args_st {
    int size;
    int argc;
    char **argv;
} ARGS;

# define PW_MIN_LENGTH 4
typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;

int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_data);

int setup_ui_method(void);
void destroy_ui_method(void);
const UI_METHOD *get_ui_method(void);

int chopup_args(ARGS *arg, char *buf);
# ifdef HEADER_X509_H
int dump_cert_text(BIO *out, X509 *x);
void print_name(BIO *out, const char *title, X509_NAME *nm,
                unsigned long lflags);
# endif
void print_bignum_var(BIO *, const BIGNUM *, const char*,
                      int, unsigned char *);
void print_array(BIO *, const char *, int, const unsigned char *);
int set_nameopt(const char *arg);
unsigned long get_nameopt(void);
int set_cert_ex(unsigned long *flags, const char *arg);
int set_name_ex(unsigned long *flags, const char *arg);
int set_ext_copy(int *copy_type, const char *arg);
int copy_extensions(X509 *x, X509_REQ *req, int copy_type);
int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2);
int add_oid_section(CONF *conf);
X509 *load_cert(const char *file, int format, const char *cert_descrip);
X509_CRL *load_crl(const char *infile, int format);
EVP_PKEY *load_key(const char *file, int format, int maybe_stdin,
                   const char *pass, ENGINE *e, const char *key_descrip);
EVP_PKEY *load_pubkey(const char *file, int format, int maybe_stdin,
                      const char *pass, ENGINE *e, const char *key_descrip);
int load_certs(const char *file, STACK_OF(X509) **certs, int format,
               const char *pass, const char *cert_descrip);
int load_crls(const char *file, STACK_OF(X509_CRL) **crls, int format,
              const char *pass, const char *cert_descrip);
X509_STORE *setup_verify(const char *CAfile, const char *CApath,
                         int noCAfile, int noCApath);
__owur int ctx_set_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                    const char *CApath, int noCAfile,
                                    int noCApath);

#ifndef OPENSSL_NO_CT

/*
 * Sets the file to load the Certificate Transparency log list from.
 * If path is NULL, loads from the default file path.
 * Returns 1 on success, 0 otherwise.
 */
__owur int ctx_set_ctlog_list_file(SSL_CTX *ctx, const char *path);

#endif

ENGINE *setup_engine(const char *engine, int debug);
void release_engine(ENGINE *e);

# define DB_type         0
# define DB_exp_date     1
# define DB_rev_date     2
# define DB_serial       3      /* index - unique */
# define DB_file         4
# define DB_name         5      /* index - unique when active and not
                                 * disabled */
# define DB_NUMBER       6

# define DB_TYPE_REV     'R'    /* Revoked  */
# define DB_TYPE_EXP     'E'    /* Expired  */
# define DB_TYPE_VAL     'V'    /* Valid ; inserted with: ca ... -valid */
# define DB_TYPE_SUSP    'S'    /* Suspended  */

typedef struct db_attr_st {
    int unique_subject;
} DB_ATTR;
typedef struct ca_db_st {
    DB_ATTR attributes;
    TXT_DB *db;
} CA_DB;

void* app_malloc(int sz, const char *what);
BIGNUM *load_serial(const char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(const char *serialfile, const char *suffix, const BIGNUM *serial,
                ASN1_INTEGER **retai);
int rotate_serial(const char *serialfile, const char *new_suffix,
                  const char *old_suffix);
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai);
CA_DB *load_index(const char *dbfile, DB_ATTR *dbattr);
int index_index(CA_DB *db);
int save_index(const char *dbfile, const char *suffix, CA_DB *db);
int rotate_index(const char *dbfile, const char *new_suffix,
                 const char *old_suffix);
void free_index(CA_DB *db);
# define index_name_cmp_noconst(a, b) \
        index_name_cmp((const OPENSSL_CSTRING *)CHECKED_PTR_OF(OPENSSL_STRING, a), \
        (const OPENSSL_CSTRING *)CHECKED_PTR_OF(OPENSSL_STRING, b))
int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b);
int parse_yesno(const char *str, int def);

X509_NAME *parse_name(const char *str, long chtype, int multirdn);
void policies_print(X509_STORE_CTX *ctx);
int bio_to_mem(unsigned char **out, int maxlen, BIO *in);
int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);

extern char *psk_key;


unsigned char *next_protos_parse(size_t *outlen, const char *in);

void print_cert_checks(BIO *bio, X509 *x,
                       const char *checkhost,
                       const char *checkemail, const char *checkip);

void store_setup_crl_download(X509_STORE *st);

/* See OPT_FMT_xxx, above. */
/* On some platforms, it's important to distinguish between text and binary
 * files.  On some, there might even be specific file formats for different
 * contents.  The FORMAT_xxx macros are meant to express an intent with the
 * file being read or created.
 */
# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)     /* Base64 */
# define FORMAT_ASN1     4                      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8                      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPubicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPubicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */

# define EXT_COPY_NONE   0
# define EXT_COPY_ADD    1
# define EXT_COPY_ALL    2

# define NETSCAPE_CERT_HDR       "certificate"

# define APP_PASS_LEN    1024

/*
 * IETF RFC 5280 says serial number must be <= 20 bytes. Use 159 bits
 * so that the first bit will never be one, so that the DER encoding
 * rules won't force a leading octet.
 */
# define SERIAL_RAND_BITS        159

int app_isdir(const char *);
int app_access(const char *, int flag);
int fileno_stdin(void);
int fileno_stdout(void);
int raw_read_stdin(void *, int);
int raw_write_stdout(const void *, int);

# define TM_START        0
# define TM_STOP         1
double app_tminterval(int stop, int usertime);

void make_uppercase(char *string);

typedef struct verify_options_st {
    int depth;
    int quiet;
    int error;
    int return_error;
} VERIFY_CB_ARGS;

extern VERIFY_CB_ARGS verify_args;


/* from app_rand.c */
void app_RAND_load_conf(CONF *c, const char *section);
void app_RAND_write(void);
void app_RAND_set_file(const char *name);
int app_RAND_loadfiles(char *name);

# ifdef  __cplusplus
}
# endif
#endif
