#include <opentls/evp.h>
#include <opentls/err.h>
#include <opentls/core.h>
#include <opentls/core_numbers.h>
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"

static int evp_mac_up_ref(void *vmac)
{
    EVP_MAC *mac = vmac;
    int ref = 0;

    CRYPTO_UP_REF(&mac->refcnt, &ref, mac->lock);
    return 1;
}

static void evp_mac_free(void *vmac)
{
    EVP_MAC *mac = vmac;
    int ref = 0;

    if (mac == NULL)
        return;

    CRYPTO_DOWN_REF(&mac->refcnt, &ref, mac->lock);
    if (ref > 0)
        return;
    otls_provider_free(mac->prov);
    CRYPTO_THREAD_lock_free(mac->lock);
    OPENtls_free(mac);
}

static void *evp_mac_new(void)
{
    EVP_MAC *mac = NULL;

    if ((mac = OPENtls_zalloc(sizeof(*mac))) == NULL
        || (mac->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        evp_mac_free(mac);
        return NULL;
    }

    mac->refcnt = 1;

    return mac;
}

static void *evp_mac_from_dispatch(int name_id,
                                   const Otls_DISPATCH *fns,
                                   Otls_PROVIDER *prov)
{
    EVP_MAC *mac = NULL;
    int fnmaccnt = 0, fnctxcnt = 0;

    if ((mac = evp_mac_new()) == NULL) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    mac->name_id = name_id;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case Otls_FUNC_MAC_NEWCTX:
            if (mac->newctx != NULL)
                break;
            mac->newctx = Otls_get_OP_mac_newctx(fns);
            fnctxcnt++;
            break;
        case Otls_FUNC_MAC_DUPCTX:
            if (mac->dupctx != NULL)
                break;
            mac->dupctx = Otls_get_OP_mac_dupctx(fns);
            break;
        case Otls_FUNC_MAC_FREECTX:
            if (mac->freectx != NULL)
                break;
            mac->freectx = Otls_get_OP_mac_freectx(fns);
            fnctxcnt++;
            break;
        case Otls_FUNC_MAC_INIT:
            if (mac->init != NULL)
                break;
            mac->init = Otls_get_OP_mac_init(fns);
            fnmaccnt++;
            break;
        case Otls_FUNC_MAC_UPDATE:
            if (mac->update != NULL)
                break;
            mac->update = Otls_get_OP_mac_update(fns);
            fnmaccnt++;
            break;
        case Otls_FUNC_MAC_FINAL:
            if (mac->final != NULL)
                break;
            mac->final = Otls_get_OP_mac_final(fns);
            fnmaccnt++;
            break;
        case Otls_FUNC_MAC_GETTABLE_PARAMS:
            if (mac->gettable_params != NULL)
                break;
            mac->gettable_params =
                Otls_get_OP_mac_gettable_params(fns);
            break;
        case Otls_FUNC_MAC_GETTABLE_CTX_PARAMS:
            if (mac->gettable_ctx_params != NULL)
                break;
            mac->gettable_ctx_params =
                Otls_get_OP_mac_gettable_ctx_params(fns);
            break;
        case Otls_FUNC_MAC_SETTABLE_CTX_PARAMS:
            if (mac->settable_ctx_params != NULL)
                break;
            mac->settable_ctx_params =
                Otls_get_OP_mac_settable_ctx_params(fns);
            break;
        case Otls_FUNC_MAC_GET_PARAMS:
            if (mac->get_params != NULL)
                break;
            mac->get_params = Otls_get_OP_mac_get_params(fns);
            break;
        case Otls_FUNC_MAC_GET_CTX_PARAMS:
            if (mac->get_ctx_params != NULL)
                break;
            mac->get_ctx_params = Otls_get_OP_mac_get_ctx_params(fns);
            break;
        case Otls_FUNC_MAC_SET_CTX_PARAMS:
            if (mac->set_ctx_params != NULL)
                break;
            mac->set_ctx_params = Otls_get_OP_mac_set_ctx_params(fns);
            break;
        }
    }
    if (fnmaccnt != 3
        || fnctxcnt != 2) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a complete set of "mac" functions, and a complete set of context
         * management functions, as well as the size function.
         */
        evp_mac_free(mac);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    mac->prov = prov;
    if (prov != NULL)
        otls_provider_up_ref(prov);

    return mac;
}

EVP_MAC *EVP_MAC_fetch(OPENtls_CTX *libctx, const char *algorithm,
                       const char *properties)
{
    return evp_generic_fetch(libctx, Otls_OP_MAC, algorithm, properties,
                             evp_mac_from_dispatch, evp_mac_up_ref,
                             evp_mac_free);
}

int EVP_MAC_up_ref(EVP_MAC *mac)
{
    return evp_mac_up_ref(mac);
}

void EVP_MAC_free(EVP_MAC *mac)
{
    evp_mac_free(mac);
}

const Otls_PROVIDER *EVP_MAC_provider(const EVP_MAC *mac)
{
    return mac->prov;
}

const Otls_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac)
{
    if (mac->gettable_params == NULL)
        return NULL;
    return mac->gettable_params();
}

const Otls_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac)
{
    if (mac->gettable_ctx_params == NULL)
        return NULL;
    return mac->gettable_ctx_params();
}

const Otls_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac)
{
    if (mac->settable_ctx_params == NULL)
        return NULL;
    return mac->settable_ctx_params();
}

void EVP_MAC_do_all_provided(OPENtls_CTX *libctx,
                             void (*fn)(EVP_MAC *mac, void *arg),
                             void *arg)
{
    evp_generic_do_all(libctx, Otls_OP_MAC,
                       (void (*)(void *, void *))fn, arg,
                       evp_mac_from_dispatch, evp_mac_free);
}
