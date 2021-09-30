 
#ifndef PKCS11_SIGN_H
# define PKCS11_SIGN_H

#include <prov/providercommon.h>
#include "pkcs11_ctx.h"

OSSL_ALGORITHM *pkcs11_sign_get_algo_tbl(OPENSSL_STACK *sk, const char *id);

#endif /* PKCS11_SIGN_H */
