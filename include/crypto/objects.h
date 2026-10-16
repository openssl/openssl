/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_OBJECTS_H)
#define OSSL_CRYPTO_OBJECTS_H

#include <openssl/objects.h>

#include "internal/bytestring.h"

void ossl_obj_cleanup_int(void);

/**
 * @brief Looks up the NID of an OBJECT IDENTIFIER without decoding it.
 * @param oid the content octets of the OBJECT IDENTIFIER
 * @returns the NID, or NID_undef if the OBJECT IDENTIFIER is unknown
 */
int ossl_obj_cbs2nid(const CBS *oid);

#endif /* !defined(OSSL_CRYPTO_OBJECTS_H) */
