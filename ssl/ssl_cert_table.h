/*
 * Copyright 2017-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * Certificate table information. NB: table entries must match tls_PKEY indices
 */
static const tls_CERT_LOOKUP tls_cert_info [] = {
    {EVP_PKEY_RSA, tls_aRSA}, /* tls_PKEY_RSA */
    {EVP_PKEY_RSA_PSS, tls_aRSA}, /* tls_PKEY_RSA_PSS_SIGN */
    {EVP_PKEY_DSA, tls_aDSS}, /* tls_PKEY_DSA_SIGN */
    {EVP_PKEY_EC, tls_aECDSA}, /* tls_PKEY_ECC */
    {NID_id_GostR3410_2001, tls_aGOST01}, /* tls_PKEY_GOST01 */
    {NID_id_GostR3410_2012_256, tls_aGOST12}, /* tls_PKEY_GOST12_256 */
    {NID_id_GostR3410_2012_512, tls_aGOST12}, /* tls_PKEY_GOST12_512 */
    {EVP_PKEY_ED25519, tls_aECDSA}, /* tls_PKEY_ED25519 */
    {EVP_PKEY_ED448, tls_aECDSA} /* tls_PKEY_ED448 */
};
