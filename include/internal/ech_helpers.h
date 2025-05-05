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

int ossl_ech_make_enc_info(const unsigned char *encoding,
                           size_t encoding_length,
                           unsigned char *info, size_t *info_len);

/*
 * Given a CH find the offsets of the session id, extensions and ECH
 * ch is the encoded client hello
 * ch_len is the length of ch
 * sessid returns offset of session_id length
 * exts points to offset of extensions
 * extlens returns length of extensions
 * echoffset returns offset of ECH
 * echtype returns the ext type of the ECH
 * echlen returns the length of the ECH
 * snioffset returns offset of (outer) SNI
 * snilen returns the length of the SNI
 * inner 1 if the ECH is marked as an inner, 0 for outer
 * return 1 for success, other otherwise
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 *
 * Note: input here is untrusted!
 */
int ossl_ech_helper_get_ch_offsets(const unsigned char *ch, size_t ch_len,
                                   size_t *sessid, size_t *exts,
                                   size_t *extlens,
                                   size_t *echoffset, uint16_t *echtype,
                                   size_t *echlen, size_t *snioffset,
                                   size_t *snilen, int *inner);

# endif
#endif
