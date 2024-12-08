/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright (c) 2024, Google Inc. */

#ifndef OPENSSL_NO_ML_KEM

# define BITS 768
# include "ml_kem-c.inc"
#else
NON_EMPTY_TRANSLATION_UNIT
#endif /* OPENSSL_NO_ML_KEM */
