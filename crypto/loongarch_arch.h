/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_CRYPTO_LOONGARCH_ARCH_H
# define OSSL_CRYPTO_LOONGARCH_ARCH_H

extern unsigned int OPENSSL_loongarchcap_P;
# define LOONGARCH_CFG2      0x02
# define LOONGARCH_CFG2_LSX  (1<<6)
# define LOONGARCH_CFG2_LASX (1<<7)

#endif
