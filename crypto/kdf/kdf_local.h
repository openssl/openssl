/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

int call_ctrl(int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
              EVP_KDF_IMPL *impl, int cmd, ...);
int kdf_str2ctrl(EVP_KDF_IMPL *impl,
                 int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
                 int cmd, const char *str);
int kdf_hex2ctrl(EVP_KDF_IMPL *impl,
                 int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
                 int cmd, const char *hex);
int kdf_md2ctrl(EVP_KDF_IMPL *impl,
                int (*ctrl)(EVP_KDF_IMPL *impl, int cmd, va_list args),
                int cmd, const char *md_name);

