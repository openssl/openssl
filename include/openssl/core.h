/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CORE_H
# define OSSL_CORE_H

# include <stddef.h>
# include <openssl/ossl_typ.h>

# ifdef __cplusplus
extern "C" {
# endif

/*-
 * Base types
 * ----------
 *
 * These are the types that the OpenSSL core and providers have in common
 * to communicate data between them.
 */

/*
 * Dispatch table element.  function_id numbers are defined further down,
 * see macros with '_FUNC' in their names.
 *
 * An array of these is always terminated by function_id == 0
 */
struct ossl_dispatch_st {
    int function_id;
    void (*function)(void);
};

/*
 * Other items, essentially an int<->pointer map element.
 *
 * We make this type distinct from OSSL_DISPATCH to ensure that dispatch
 * tables remain tables with function pointers only.
 *
 * This is used whenever we need to pass things like a table of error reason
 * codes <-> reason string maps, parameter name <-> parameter type maps, ...
 *
 * Usage determines which field works as key if any, rather than field order.
 *
 * An array of these is always terminated by id == 0 && ptr == NULL
 */
struct ossl_item_st {
    unsigned int id;
    void *ptr;
};

/*
 * Type to tie together algorithm name, property definition string and
 * the algorithm implementation in the form of a dispatch table.
 *
 * An array of these is always terminated by algorithm_name == NULL
 */
struct ossl_algorithm_st {
    const char *algorithm_name;      /* key */
    const char *property_definition; /* key */
    const OSSL_DISPATCH *implementation;
};

/*
 * Type to pass object data in a uniform way, without exposing the object
 * structure.
 *
 * An array of these is always terminated by key == NULL
 */
struct ossl_param_st {
    const char *key;             /* the name of the parameter */
    unsigned int data_type;      /* declare what kind of content is in buffer */
    void *data;                  /* value being passed in or out */
    size_t data_size;            /* data size */
    size_t *return_size;         /* OPTIONAL: address to content size */
};

/* Currently supported OSSL_PARAM data types */
/*
 * OSSL_PARAM_INTEGER and OSSL_PARAM_UNSIGNED_INTEGER
 * are arbitrary length and therefore require an arbitrarily sized buffer,
 * since they may be used to pass numbers larger than what is natively
 * available.
 *
 * The number must be buffered in native form, i.e. MSB first on B_ENDIAN
 * systems and LSB first on L_ENDIAN systems.  This means that arbitrary
 * native integers can be stored in the buffer, just make sure that the
 * buffer size is correct and the buffer itself is properly aligned (for
 * example by having the buffer field point at a C integer).
 */
# define OSSL_PARAM_INTEGER              1
# define OSSL_PARAM_UNSIGNED_INTEGER     2
/*-
 * OSSL_PARAM_REAL
 * is a C binary floating point values in native form and alignment.
 */
# define OSSL_PARAM_REAL                 3
/*-
 * OSSL_PARAM_UTF8_STRING
 * is a printable string.  Is expteced to be printed as it is.
 */
# define OSSL_PARAM_UTF8_STRING          4
/*-
 * OSSL_PARAM_OCTET_STRING
 * is a string of bytes with no further specification.  Is expected to be
 * printed as a hexdump.
 */
# define OSSL_PARAM_OCTET_STRING         5
/*-
 * OSSL_PARAM_UTF8_PTR
 * is a pointer to a printable string.  Is expteced to be printed as it is.
 *
 * The difference between this and OSSL_PARAM_UTF8_STRING is that only pointers
 * are manipulated for this type.
 *
 * This is more relevant for parameter requests, where the responding
 * function doesn't need to copy the data to the provided buffer, but
 * sets the provided buffer to point at the actual data instead.
 *
 * WARNING!  Using these is FRAGILE, as it assumes that the actual
 * data and its location are constant.
 */
# define OSSL_PARAM_UTF8_PTR             6
/*-
 * OSSL_PARAM_OCTET_PTR
 * is a pointer to a string of bytes with no further specification.  It is
 * expected to be printed as a hexdump.
 *
 * The difference between this and OSSL_PARAM_OCTET_STRING is that only pointers
 * are manipulated for this type.
 *
 * This is more relevant for parameter requests, where the responding
 * function doesn't need to copy the data to the provided buffer, but
 * sets the provided buffer to point at the actual data instead.
 *
 * WARNING!  Using these is FRAGILE, as it assumes that the actual
 * data and its location are constant.
 */
# define OSSL_PARAM_OCTET_PTR            7

/*-
 * Provider entry point
 * --------------------
 *
 * This function is expected to be present in any dynamically loadable
 * provider module.  By definition, if this function doesn't exist in a
 * module, that module is not an OpenSSL provider module.
 */
/*-
 * |provider|   pointer to opaque type OSSL_PROVIDER.  This can be used
 *              together with some functions passed via |in| to query data.
 * |in|         is the array of functions that the Core passes to the provider.
 * |out|        will be the array of base functions that the provider passes
 *              back to the Core.
 */
typedef int (OSSL_provider_init_fn)(const OSSL_PROVIDER *provider,
                                    const OSSL_DISPATCH *in,
                                    const OSSL_DISPATCH **out);
# ifdef __VMS
#  pragma names save
#  pragma names uppercase,truncated
# endif
extern OSSL_provider_init_fn OSSL_provider_init;
# ifdef __VMS
#  pragma names restore
# endif

# ifdef __cplusplus
}
# endif

#endif
