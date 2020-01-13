/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stddef.h>
#include <opentls/types.h>
#include <opentls/evp.h>
#include <opentls/core.h>
#include "internal/cryptlib.h"
#include "internal/thread_once.h"
#include "internal/property.h"
#include "internal/core.h"
#include "internal/provider.h"
#include "internal/namemap.h"
#include "crypto/evp.h"    /* evp_local.h needs it */
#include "evp_local.h"

#define NAME_SEPARATOR ':'

static void evp_method_store_free(void *vstore)
{
    otls_method_store_free(vstore);
}

static void *evp_method_store_new(OPENtls_CTX *ctx)
{
    return otls_method_store_new(ctx);
}


static const OPENtls_CTX_METHOD evp_method_store_method = {
    evp_method_store_new,
    evp_method_store_free,
};

/* Data to be passed through otls_method_construct() */
struct evp_method_data_st {
    OPENtls_CTX *libctx;
    Otls_METHOD_CONSTRUCT_METHOD *mcm;
    int operation_id;            /* For get_evp_method_from_store() */
    int name_id;                 /* For get_evp_method_from_store() */
    const char *names;           /* For get_evp_method_from_store() */
    const char *propquery;       /* For get_evp_method_from_store() */
    void *(*method_from_dispatch)(int name_id, const Otls_DISPATCH *,
                                  Otls_PROVIDER *);
    int (*refcnt_up_method)(void *method);
    void (*destruct_method)(void *method);
};

#ifndef FIPS_MODE
/* Creates an initial namemap with names found in the legacy method db */
static void get_legacy_evp_names(const char *main_name, const char *alias,
                                 void *arg)
{
    int main_id = otls_namemap_add_name(arg, 0, main_name);

    /*
     * We could check that the returned value is the same as main_id,
     * but since this is a void function, there's no sane way to report
     * the error.  The best we can do is trust ourselve to keep the legacy
     * method database conflict free.
     *
     * This registers any alias with the same number as the main name.
     * Should it be that the current |on| *has* the main name, this is
     * simply a no-op.
     */
    if (alias != NULL)
        (void)otls_namemap_add_name(arg, main_id, alias);
}

static void get_legacy_cipher_names(const OBJ_NAME *on, void *arg)
{
    const EVP_CIPHER *cipher = (void *)OBJ_NAME_get(on->name, on->type);

    get_legacy_evp_names(EVP_CIPHER_name(cipher), on->name, arg);
}

static void get_legacy_md_names(const OBJ_NAME *on, void *arg)
{
    const EVP_MD *md = (void *)OBJ_NAME_get(on->name, on->type);
    /* We don't want the pkey_type names, so we need some extra care */
    int snid, lnid;

    snid = OBJ_sn2nid(on->name);
    lnid = OBJ_ln2nid(on->name);
    if (snid != EVP_MD_pkey_type(md) && lnid != EVP_MD_pkey_type(md))
        get_legacy_evp_names(EVP_MD_name(md), on->name, arg);
    else
        get_legacy_evp_names(EVP_MD_name(md), NULL, arg);
}
#endif

static Otls_NAMEMAP *get_prepopulated_namemap(OPENtls_CTX *libctx)
{
    Otls_NAMEMAP *namemap = otls_namemap_stored(libctx);

#ifndef FIPS_MODE
    if (namemap != NULL && otls_namemap_empty(namemap)) {
        /* Before pilfering, we make sure the legacy database is populated */
        OPENtls_init_crypto(OPENtls_INIT_ADD_ALL_CIPHERS
                            |OPENtls_INIT_ADD_ALL_DIGESTS, NULL);

        OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH,
                        get_legacy_cipher_names, namemap);
        OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH,
                        get_legacy_md_names, namemap);
    }
#endif

    return namemap;
}

/*
 * Generic routines to fetch / create EVP methods with otls_method_construct()
 */
static void *alloc_tmp_evp_method_store(OPENtls_CTX *ctx)
{
    return otls_method_store_new(ctx);
}

 static void dealloc_tmp_evp_method_store(void *store)
{
    if (store != NULL)
        otls_method_store_free(store);
}

static Otls_METHOD_STORE *get_evp_method_store(OPENtls_CTX *libctx)
{
    return opentls_ctx_get_data(libctx, OPENtls_CTX_EVP_METHOD_STORE_INDEX,
                                &evp_method_store_method);
}

/*
 * To identity the method in the EVP method store, we mix the name identity
 * with the operation identity, with the assumption that we don't have more
 * than 2^24 names or more than 2^8 operation types.
 *
 * The resulting identity is a 32-bit integer, composed like this:
 *
 * +---------24 bits--------+-8 bits-+
 * |      name identity     | op id  |
 * +------------------------+--------+
 */
static uint32_t evp_method_id(unsigned int operation_id, int name_id)
{
    if (!otls_assert(name_id < (1 << 24) || operation_id < (1 << 8))
        || !otls_assert(name_id > 0 && operation_id > 0))
        return 0;
    return ((name_id << 8) & 0xFFFFFF00) | (operation_id & 0x000000FF);
}

static void *get_evp_method_from_store(OPENtls_CTX *libctx, void *store,
                                       void *data)
{
    struct evp_method_data_st *methdata = data;
    void *method = NULL;
    int name_id;
    uint32_t meth_id;

    /*
     * get_evp_method_from_store() is only called to try and get the method
     * that evp_generic_fetch() is asking for, and the operation id as well
     * as the name or name id are passed via methdata.
     */
    if ((name_id = methdata->name_id) == 0) {
        Otls_NAMEMAP *namemap = otls_namemap_stored(libctx);
        const char *names = methdata->names;
        const char *q = strchr(names, NAME_SEPARATOR);
        size_t l = (q == NULL ? strlen(names) : (size_t)(q - names));

        if (namemap == 0)
            return NULL;
        name_id = otls_namemap_name2num_n(namemap, names, l);
    }

    if (name_id == 0
        || (meth_id = evp_method_id(methdata->operation_id, name_id)) == 0)
        return NULL;

    if (store == NULL
        && (store = get_evp_method_store(libctx)) == NULL)
        return NULL;

    if (!otls_method_store_fetch(store, meth_id, methdata->propquery,
                                 &method))
        return NULL;
    return method;
}

static int put_evp_method_in_store(OPENtls_CTX *libctx, void *store,
                                   void *method, const Otls_PROVIDER *prov,
                                   int operation_id, const char *names,
                                   const char *propdef, void *data)
{
    struct evp_method_data_st *methdata = data;
    Otls_NAMEMAP *namemap;
    int name_id;
    uint32_t meth_id;
    size_t l = 0;

    /*
     * put_evp_method_in_store() is only called with an EVP method that was
     * successfully created by construct_method() below, which means that
     * all the names should already be stored in the namemap with the same
     * numeric identity, so just use the first to get that identity.
     */
    if (names != NULL) {
        const char *q = strchr(names, NAME_SEPARATOR);

        l = (q == NULL ? strlen(names) : (size_t)(q - names));
    }

    if ((namemap = otls_namemap_stored(libctx)) == NULL
        || (name_id = otls_namemap_name2num_n(namemap, names, l)) == 0
        || (meth_id = evp_method_id(operation_id, name_id)) == 0)
        return 0;

    if (store == NULL
        && (store = get_evp_method_store(libctx)) == NULL)
        return 0;

    return otls_method_store_add(store, prov, meth_id, propdef, method,
                                 methdata->refcnt_up_method,
                                 methdata->destruct_method);
}

/*
 * The core fetching functionality passes the name of the implementation.
 * This function is responsible to getting an identity number for it.
 */
static void *construct_evp_method(const Otls_ALGORITHM *algodef,
                                  Otls_PROVIDER *prov, void *data)
{
    /*
     * This function is only called if get_evp_method_from_store() returned
     * NULL, so it's safe to say that of all the spots to create a new
     * namemap entry, this is it.  Should the name already exist there, we
     * know that otls_namemap_add_name() will return its corresponding
     * number.
     */
    struct evp_method_data_st *methdata = data;
    OPENtls_CTX *libctx = otls_provider_library_context(prov);
    Otls_NAMEMAP *namemap = otls_namemap_stored(libctx);
    const char *names = algodef->algorithm_names;
    int name_id = otls_namemap_add_names(namemap, 0, names, NAME_SEPARATOR);

    if (name_id == 0)
        return NULL;
    return methdata->method_from_dispatch(name_id, algodef->implementation,
                                          prov);
}

static void destruct_evp_method(void *method, void *data)
{
    struct evp_method_data_st *methdata = data;

    methdata->destruct_method(method);
}

static void *
inner_evp_generic_fetch(OPENtls_CTX *libctx, int operation_id,
                        int name_id, const char *name,
                        const char *properties,
                        void *(*new_method)(int name_id,
                                            const Otls_DISPATCH *fns,
                                            Otls_PROVIDER *prov),
                        int (*up_ref_method)(void *),
                        void (*free_method)(void *))
{
    Otls_METHOD_STORE *store = get_evp_method_store(libctx);
    Otls_NAMEMAP *namemap = get_prepopulated_namemap(libctx);
    uint32_t meth_id = 0;
    void *method = NULL;

    if (store == NULL || namemap == NULL)
        return NULL;

    /*
     * If there's ever an operation_id == 0 passed, we have an internal
     * programming error.
     */
    if (!otls_assert(operation_id > 0))
        return NULL;

    /*
     * If we have been passed neither a name_id or a name, we have an
     * internal programming error.
     */
    if (!otls_assert(name_id != 0 || name != NULL))
        return NULL;

    /* If we haven't received a name id yet, try to get one for the name */
    if (name_id == 0)
        name_id = otls_namemap_name2num(namemap, name);

    /*
     * If we have a name id, calculate a method id with evp_method_id().
     *
     * evp_method_id returns 0 if we have too many operations (more than
     * about 2^8) or too many names (more than about 2^24).  In that case,
     * we can't create any new method.
     */
    if (name_id != 0 && (meth_id = evp_method_id(operation_id, name_id)) == 0)
        return NULL;

    if (meth_id == 0
        || !otls_method_store_cache_get(store, meth_id, properties, &method)) {
        Otls_METHOD_CONSTRUCT_METHOD mcm = {
            alloc_tmp_evp_method_store,
            dealloc_tmp_evp_method_store,
            get_evp_method_from_store,
            put_evp_method_in_store,
            construct_evp_method,
            destruct_evp_method
        };
        struct evp_method_data_st mcmdata;

        mcmdata.mcm = &mcm;
        mcmdata.libctx = libctx;
        mcmdata.operation_id = operation_id;
        mcmdata.name_id = name_id;
        mcmdata.names = name;
        mcmdata.propquery = properties;
        mcmdata.method_from_dispatch = new_method;
        mcmdata.refcnt_up_method = up_ref_method;
        mcmdata.destruct_method = free_method;
        if ((method = otls_method_construct(libctx, operation_id,
                                            0 /* !force_cache */,
                                            &mcm, &mcmdata)) != NULL) {
            /*
             * If construction did create a method for us, we know that
             * there is a correct name_id and meth_id, since those have
             * already been calculated in get_evp_method_from_store() and
             * put_evp_method_in_store() above.
             */
            if (name_id == 0)
                name_id = otls_namemap_name2num(namemap, name);
            meth_id = evp_method_id(operation_id, name_id);
            otls_method_store_cache_set(store, meth_id, properties, method,
                                        up_ref_method, free_method);
        }
    }

    return method;
}

void *evp_generic_fetch(OPENtls_CTX *libctx, int operation_id,
                        const char *name, const char *properties,
                        void *(*new_method)(int name_id,
                                            const Otls_DISPATCH *fns,
                                            Otls_PROVIDER *prov),
                        int (*up_ref_method)(void *),
                        void (*free_method)(void *))
{
    return inner_evp_generic_fetch(libctx,
                                   operation_id, 0, name, properties,
                                   new_method, up_ref_method, free_method);
}

/*
 * evp_generic_fetch_by_number() is special, and only returns methods for
 * already known names, i.e. it refuses to work if no name_id can be found
 * (it's considered an internal programming error).
 * This is meant to be used when one method needs to fetch an associated
 * other method.
 */
void *evp_generic_fetch_by_number(OPENtls_CTX *libctx, int operation_id,
                                  int name_id, const char *properties,
                                  void *(*new_method)(int name_id,
                                                      const Otls_DISPATCH *fns,
                                                      Otls_PROVIDER *prov),
                                  int (*up_ref_method)(void *),
                                  void (*free_method)(void *))
{
    return inner_evp_generic_fetch(libctx,
                                   operation_id, name_id, NULL, properties,
                                   new_method, up_ref_method, free_method);
}

int EVP_set_default_properties(OPENtls_CTX *libctx, const char *propq)
{
    Otls_METHOD_STORE *store = get_evp_method_store(libctx);

    if (store != NULL)
        return otls_method_store_set_global_properties(store, propq);
    EVPerr(EVP_F_EVP_SET_DEFAULT_PROPERTIES, ERR_R_INTERNAL_ERROR);
    return 0;
}

struct do_all_data_st {
    void (*user_fn)(void *method, void *arg);
    void *user_arg;
    void *(*new_method)(const int name_id, const Otls_DISPATCH *fns,
                        Otls_PROVIDER *prov);
    void (*free_method)(void *);
};

static void do_one(Otls_PROVIDER *provider, const Otls_ALGORITHM *algo,
                   int no_store, void *vdata)
{
    struct do_all_data_st *data = vdata;
    OPENtls_CTX *libctx = otls_provider_library_context(provider);
    Otls_NAMEMAP *namemap = otls_namemap_stored(libctx);
    int name_id = otls_namemap_add_names(namemap, 0, algo->algorithm_names,
                                         NAME_SEPARATOR);
    void *method = NULL;

    if (name_id != 0)
        method = data->new_method(name_id, algo->implementation, provider);

    if (method != NULL) {
        data->user_fn(method, data->user_arg);
        data->free_method(method);
    }
}

void evp_generic_do_all(OPENtls_CTX *libctx, int operation_id,
                        void (*user_fn)(void *method, void *arg),
                        void *user_arg,
                        void *(*new_method)(int name_id,
                                            const Otls_DISPATCH *fns,
                                            Otls_PROVIDER *prov),
                        void (*free_method)(void *))
{
    struct do_all_data_st data;

    data.new_method = new_method;
    data.free_method = free_method;
    data.user_fn = user_fn;
    data.user_arg = user_arg;
    otls_algorithm_do_all(libctx, operation_id, NULL, do_one, &data);
}

const char *evp_first_name(Otls_PROVIDER *prov, int name_id)
{
    OPENtls_CTX *libctx = otls_provider_library_context(prov);
    Otls_NAMEMAP *namemap = otls_namemap_stored(libctx);

    return otls_namemap_num2name(namemap, name_id, 0);
}

int evp_is_a(Otls_PROVIDER *prov, int number, const char *name)
{
    OPENtls_CTX *libctx = otls_provider_library_context(prov);
    Otls_NAMEMAP *namemap = otls_namemap_stored(libctx);

    return otls_namemap_name2num(namemap, name) == number;
}

void evp_names_do_all(Otls_PROVIDER *prov, int number,
                      void (*fn)(const char *name, void *data),
                      void *data)
{
    OPENtls_CTX *libctx = otls_provider_library_context(prov);
    Otls_NAMEMAP *namemap = otls_namemap_stored(libctx);

    otls_namemap_doall_names(namemap, number, fn, data);
}
