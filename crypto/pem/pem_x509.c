/*
 * Copyright 2001-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/bio.h>
#include <opentls/evp.h>
#include <opentls/x509.h>
#include <opentls/pkcs7.h>
#include <opentls/pem.h>

IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)
