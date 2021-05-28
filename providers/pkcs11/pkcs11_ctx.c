#ifndef PKSC11_CTX_H
#define PKSC11_CTX_H

#ifndef CK_PTR
# define CK_PTR *
#endif

#ifndef CK_BOOL
  typedef unsigned char CK_BOOL;
#endif                          /* CK_BOOL */

#ifndef CK_DECLARE_FUNCTION
# define CK_DECLARE_FUNCTION(returnType, name) \
         returnType name
#endif

#ifndef CK_DECLARE_FUNCTION_POINTER
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
         returnType (CK_PTR name)
#endif

#ifndef CK_CALLBACK_FUNCTION
# define CK_CALLBACK_FUNCTION(returnType, name) \
         returnType (CK_PTR name)
#endif

#ifndef NULL_PTR
# include <stddef.h> /* provides NULL */
# define NULL_PTR NULL
#endif

#ifndef PKCS11UNPACKED /* for PKCS11 modules that dont pack */
# pragma pack(push, 1)
#endif

#include "pkcs11-v30/pkcs11.h" /* official PKCS11 3.0 header */

#ifndef PKCS11UNPACKED
# pragma pack(pop)
#endif


#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
# include <openssl/bio.h>

struct pkcs11_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;         /* For all provider modules */
    BIO_METHOD *corebiometh;
    OPENSSL_CORE_CTX *corectx;

    /* default core params */
    char *openssl_version;
    char *provider_name;
    char *module_filename;
    char *module;
    /* custom core params */
    char *pkcs11module;
    char *pkcs11slotpin;
    char *pkcs11userpin;
    char *pkcs11objects;
    char *pkcs11rsakeygen;

    /* pkcs11 module data */
    void *so_handle;
    CK_FUNCTION_LIST *fn;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE *mechlist;
    CK_MECHANISM_INFO *mechinfo;
    CK_ULONG mechcount;
    CK_SESSION_HANDLE session;
    CK_BBOOL tokobjs;
    struct {
      /* X9.31 and PKCS#1 */
      int avail;
      CK_ULONG idx;
    } rsakeygen[2];

    /* operation dispatch tables */
    OSSL_ALGORITHM *digest;
    OSSL_ALGORITHM *cipher;
    OSSL_ALGORITHM *mac;
    OSSL_ALGORITHM *kdf;
    OSSL_ALGORITHM *keymgmt;
    OSSL_ALGORITHM *keyexch;
    OSSL_ALGORITHM *signature;
    OSSL_ALGORITHM *asym_cipher;
    OSSL_ALGORITHM *serializer;

   /* functions offered by libcrypto to the providers */
    OSSL_FUNC_core_gettable_params_fn       *core_gettable_params;
    OSSL_FUNC_core_get_params_fn            *core_get_params;
    OSSL_FUNC_core_thread_start_fn          *core_thread_start;
    OSSL_FUNC_core_get_libctx_fn            *core_get_libctx;
    OSSL_FUNC_core_new_error_fn             *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn       *core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn            *core_vset_error;
    OSSL_FUNC_core_set_error_mark_fn        *core_set_error_mark;
    OSSL_FUNC_core_clear_last_error_mark_fn *core_clear_last_error_mark;
    OSSL_FUNC_core_pop_error_to_mark_fn     *core_pop_error_to_mark;
    OSSL_FUNC_CRYPTO_malloc_fn              *CRYPTO_malloc;
    OSSL_FUNC_CRYPTO_zalloc_fn              *CRYPTO_zalloc;
    OSSL_FUNC_CRYPTO_free_fn                *CRYPTO_free;
    OSSL_FUNC_CRYPTO_clear_free_fn          *CRYPTO_clear_free;
    OSSL_FUNC_CRYPTO_realloc_fn             *CRYPTO_realloc;
    OSSL_FUNC_CRYPTO_clear_realloc_fn       *CRYPTO_clear_realloc;
    OSSL_FUNC_CRYPTO_secure_malloc_fn       *CRYPTO_secure_malloc;
    OSSL_FUNC_CRYPTO_secure_zalloc_fn       *CRYPTO_secure_zalloc;
    OSSL_FUNC_CRYPTO_secure_free_fn         *CRYPTO_secure_free;
    OSSL_FUNC_CRYPTO_secure_clear_free_fn   *CRYPTO_secure_clear_free;
    OSSL_FUNC_CRYPTO_secure_allocated_fn    *CRYPTO_secure_allocated;
    OSSL_FUNC_OPENSSL_cleanse_fn            *OPENSSL_cleanse;
    OSSL_FUNC_BIO_new_file_fn               *BIO_new_file;
    OSSL_FUNC_BIO_new_membuf_fn             *BIO_new_membuf;
    OSSL_FUNC_BIO_read_ex_fn                *BIO_read_ex;
    OSSL_FUNC_BIO_free_fn                   *BIO_free;
    OSSL_FUNC_BIO_vprintf_fn                *BIO_vprintf;
    OSSL_FUNC_self_test_cb_fn               *self_test_cb;
};

typedef struct pkcs11_st PKCS11_CTX;

#endif // PKSC11_CTX_H
