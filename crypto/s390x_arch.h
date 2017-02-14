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
 * STFLE:STFLE:STFLE.KIMD:KIMD:KM:KM:KMC:KMC:KMAC:KMAC:KMCTR:KMCTR:KMA:KMA
 */
# define S390X_STFLE_DWORDS	3
# define S390X_QUERY_DWORDS	12
# define S390X_CAP_DWORDS	(S390X_STFLE_DWORDS + S390X_QUERY_DWORDS)
extern uint64_t OPENSSL_s390xcap_P[];

/* OPENSSL_s390xcap_P[2] flags */
# define S390X_STFLE_VXE	(1ULL << 56)
# define S390X_STFLE_VXD	(1ULL << 57)
# define S390X_STFLE_VX		(1ULL << 62)

/* OPENSSL_s390xcap_P[5] flags */
# define S390X_KM_AES_256	(1ULL << 43)
# define S390X_KM_AES_192	(1ULL << 44)
# define S390X_KM_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[7] flags */
# define S390X_KMC_AES_256	(1ULL << 43)
# define S390X_KMC_AES_192	(1ULL << 44)
# define S390X_KMC_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[9] flags */
# define S390X_KMAC_AES_256	(1ULL << 43)
# define S390X_KMAC_AES_192	(1ULL << 44)
# define S390X_KMAC_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[13] flags */
# define S390X_KMA_GCM_AES_256	(1ULL << 43)
# define S390X_KMA_GCM_AES_192	(1ULL << 44)
# define S390X_KMA_GCM_AES_128	(1ULL << 45)

/* %r0 flags */
# define S390X_KMA_LPC		(1ULL <<  8)
# define S390X_KMA_LAAD		(1ULL <<  9)
# define S390X_KMA_HS		(1ULL << 10)

#endif
