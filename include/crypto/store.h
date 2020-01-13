/*
 * Copyright 2016-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_CRYPTO_STORE_H
# define Otls_CRYPTO_STORE_H

# include <opentls/bio.h>
# include <opentls/store.h>
# include <opentls/ui.h>

/*
 * Two functions to read PEM data off an already opened BIO.  To be used
 * instead of OtlsSTORE_open() and OtlsSTORE_close().  Everything is done
 * as usual with OtlsSTORE_load() and OtlsSTORE_eof().
 */
Otls_STORE_CTX *otls_store_attach_pem_bio(BIO *bp, const UI_METHOD *ui_method,
                                          void *ui_data);
int otls_store_detach_pem_bio(Otls_STORE_CTX *ctx);

void otls_store_cleanup_int(void);

#endif
