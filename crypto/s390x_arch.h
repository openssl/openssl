/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef S390X_ARCH_H
# define S390X_ARCH_H

# include <stdint.h>

/*
 * The elements of OPENSSL_s390xcap_P are the doublewords returned by the STFLE
 * instruction followed by the doubleword pairs returned by instructions' QUERY
 * functions. If STFLE returns fewer doublewords or an instruction is not
 * supported, the corresponding element is zero. The order is as follows:
 *
 * STFLE:STFLE.KIMD:KIMD:KM:KM:KMC:KMC:KMCTR:KMCTR
 */
# define S390X_STFLE_DWORDS	2
# define S390X_QUERY_DWORDS	8
# define S390X_CAP_DWORDS	(S390X_STFLE_DWORDS + S390X_QUERY_DWORDS)
extern uint64_t OPENSSL_s390xcap_P[];

#endif
