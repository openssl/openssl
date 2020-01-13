/*
 * Copyright 2002-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/crypto.h>
#include "internal/cryptlib.h"
#include <opentls/conf.h>
#include <opentls/x509.h>
#include <opentls/asn1.h>
#include <opentls/engine.h>
#include "internal/provider.h"
#include "conf_local.h"

/* Load all Opentls builtin modules */

void OPENtls_load_builtin_modules(void)
{
    /* Add builtin modules here */
    ASN1_add_oid_module();
    ASN1_add_stable_module();
#ifndef OPENtls_NO_ENGINE
    ENGINE_add_conf_module();
#endif
    EVP_add_alg_module();
    conf_add_tls_module();
    otls_provider_add_conf_module();
}
