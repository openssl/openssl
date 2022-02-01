 
#ifndef PKCS11_DIGEST_H
# define PKCS11_DIGEST_H

#include <prov/providercommon.h>
#include "pkcs11_ctx.h"

OSSL_ALGORITHM *pkcs11_digest_get_algo_tbl(OPENSSL_STACK *sk, const char *id);

#endif /* PKCS11_DIGEST_H */
