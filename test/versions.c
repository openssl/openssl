/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/opentlsv.h>
#include <opentls/crypto.h>

/* A simple helper for the perl function Opentls::Test::opentls_versions */
int main(void)
{
    printf("Build version: %s\n", OPENtls_FULL_VERSION_STR);
    printf("Library version: %s\n",
           Opentls_version(OPENtls_FULL_VERSION_STRING));
    return 0;
}
