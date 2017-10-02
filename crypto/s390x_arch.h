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

/*
 * The elements of OPENSSL_s390xcap_P are the doublewords returned by the STFLE
 * instruction followed by the doubleword pairs returned by instructions' QUERY
 * functions. If STFLE returns fewer doublewords or an instruction is not
 * supported, the corresponding element is zero. The order is as follows:
 *
 * STFLE:STFLE:STFLE.
 * KIMD:KIMD:KLMD:KLMD:KM:KM:KMC:KMC:KMAC:KMAC:KMCTR:KMCTR:KMO:KMO:KMF:KMF
 * :PRNO:PRNO:KMA:KMA
 */
# define S390X_STFLE_DWORDS	3
# define S390X_QUERY_DWORDS	20
# define S390X_CAP_DWORDS	(S390X_STFLE_DWORDS + S390X_QUERY_DWORDS)
extern unsigned long long OPENSSL_s390xcap_P[];

/* Offsets */
# define S390X_STFLE		0
# define S390X_KIMD		(S390X_STFLE + S390X_STFLE_DWORDS)
# define S390X_KLMD		(S390X_KIMD + 2)
# define S390X_KM		(S390X_KLMD + 2)
# define S390X_KMC		(S390X_KM + 2)
# define S390X_KMAC		(S390X_KMC + 2)
# define S390X_KMCTR		(S390X_KMAC + 2)
# define S390X_KMO		(S390X_KMCTR + 2)
# define S390X_KMF		(S390X_KMO + 2)
# define S390X_PRNO		(S390X_KMF + 2)
# define S390X_KMA		(S390X_PRNO + 2)

/* OPENSSL_s390xcap_P[S390X_STFLE + 2] flags */
# define S390X_STFLE_VXE	(1ULL << 56)
# define S390X_STFLE_VXD	(1ULL << 57)
# define S390X_STFLE_VX		(1ULL << 62)

/* OPENSSL_s390xcap_P[S390X_KIMD] flags */
# define S390X_KIMD_SHAKE_256	(1ULL << 26)
# define S390X_KIMD_SHAKE_128	(1ULL << 27)
# define S390X_KIMD_SHA3_512	(1ULL << 28)
# define S390X_KIMD_SHA3_384	(1ULL << 29)
# define S390X_KIMD_SHA3_256	(1ULL << 30)
# define S390X_KIMD_SHA3_224	(1ULL << 31)

/* OPENSSL_s390xcap_P[S390X_KLMD] flags */
# define S390X_KLMD_SHAKE_256	(1ULL << 26)
# define S390X_KLMD_SHAKE_128	(1ULL << 27)
# define S390X_KLMD_SHA3_512	(1ULL << 28)
# define S390X_KLMD_SHA3_384	(1ULL << 29)
# define S390X_KLMD_SHA3_256	(1ULL << 30)
# define S390X_KLMD_SHA3_224	(1ULL << 31)

/* OPENSSL_s390xcap_P[S390X_KM] flags */
# define S390X_KM_AES_256	(1ULL << 43)
# define S390X_KM_AES_192	(1ULL << 44)
# define S390X_KM_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[S390X_KMC] flags */
# define S390X_KMC_AES_256	(1ULL << 43)
# define S390X_KMC_AES_192	(1ULL << 44)
# define S390X_KMC_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[S390X_KMAC] flags */
# define S390X_KMAC_AES_256	(1ULL << 43)
# define S390X_KMAC_AES_192	(1ULL << 44)
# define S390X_KMAC_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[S390X_KMO] flags */
# define S390X_KMO_AES_256	(1ULL << 43)
# define S390X_KMO_AES_192	(1ULL << 44)
# define S390X_KMO_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[S390X_KMF] flags */
# define S390X_KMF_AES_256	(1ULL << 43)
# define S390X_KMF_AES_192	(1ULL << 44)
# define S390X_KMF_AES_128	(1ULL << 45)

/* OPENSSL_s390xcap_P[S390X_PRNO + 1] flags */
# define S390X_PRNO_TRNG	(1ULL << 13)

/* OPENSSL_s390xcap_P[S390X_KMA] flags */
# define S390X_KMA_GCM_AES_256	(1ULL << 43)
# define S390X_KMA_GCM_AES_192	(1ULL << 44)
# define S390X_KMA_GCM_AES_128	(1ULL << 45)

#endif
