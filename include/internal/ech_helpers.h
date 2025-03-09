/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * These functions are ECH helpers that are used within the library but
 * also by ECH test code.
 */

#ifndef OPENSSL_ECH_HELPERS_H
# define OPENSSL_ECH_HELPERS_H
# pragma once

# ifndef OPENSSL_NO_ECH

int ossl_ech_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                            size_t *exts, size_t *echoffset,
                            uint16_t *echtype, uint16_t *echlen);
int ossl_ech_make_enc_info(unsigned char *encoding, size_t encoding_length,
                           unsigned char *info, size_t *info_len);

# endif
#endif
