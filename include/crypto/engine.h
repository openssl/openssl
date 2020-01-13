/*
 * Copyright 2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/engine.h>

void engine_load_opentls_int(void);
void engine_load_devcrypto_int(void);
void engine_load_rdrand_int(void);
void engine_load_dynamic_int(void);
void engine_load_padlock_int(void);
void engine_load_capi_int(void);
void engine_load_dasync_int(void);
void engine_load_afalg_int(void);
void engine_cleanup_int(void);
