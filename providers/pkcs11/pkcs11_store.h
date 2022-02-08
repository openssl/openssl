 
#ifndef PKCS11_STORE_H
# define PKCS11_STORE_H

#include <prov/providercommon.h>
#include "pkcs11_ctx.h"

#define CKF_STORE              0x00100000UL

OSSL_ALGORITHM *pkcs11_store_get_algo_tbl(OPENSSL_STACK *sk, const char *id);

#endif /* PKCS11_STORE_H */
