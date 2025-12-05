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

/*
 * the max HPKE 'info' we'll process is the max ECHConfig size
 * (OSSL_ECH_MAX_ECHCONFIG_LEN) plus OSSL_ECH_CONTEXT_STRING(len=7) + 1
 */
#  define OSSL_ECH_MAX_INFO_LEN (OSSL_ECH_MAX_ECHCONFIG_LEN + 8)

int ossl_ech_make_enc_info(const unsigned char *encoding,
                           size_t encoding_length,
                           unsigned char *info, size_t *info_len);

/*
 * Given a CH find the offsets of the session id, extensions and ECH
 * ch is the encoded client hello
 * ch_len is the length of ch
 * sessid_off returns offset of session_id length
 * exts_off points to offset of extensions
 * exts_len returns length of extensions
 * ech_off returns offset of ECH
 * echtype returns the ext type of the ECH
 * ech_len returns the length of the ECH
 * sni_off returns offset of (outer) SNI
 * sni_len returns the length of the SNI
 * inner 1 if the ECH is marked as an inner, 0 for outer
 * return 1 for success, other otherwise
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 *
 * Note: input here is untrusted!
 */
int ossl_ech_helper_get_ch_offsets(const unsigned char *ch, size_t ch_len,
                                   size_t *sessid_off, size_t *exts_off,
                                   size_t *exts_len,
                                   size_t *ech_off, uint16_t *echtype,
                                   size_t *ech_len, size_t *sni_off,
                                   size_t *sni_len, int *inner);

/*
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * sh is the SH buffer
 * sh_len is the length of the SH
 * exts points to offset of extensions
 * echoffset points to offset of ECH
 * echtype points to the ext type of the ECH
 * return 1 for success, other otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
int ossl_ech_helper_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                                   size_t *exts, size_t *echoffset,
                                   uint16_t *echtype);

/*
 * make up HPKE "info" input as per spec
 * encoding is the ECHconfig being used
 * encodinglen is the length of ECHconfig being used
 * info is a caller-allocated buffer for results
 * info_len is the buffer size on input, used-length on output
 * return 1 for success, other otherwise
 */
int ossl_ech_helper_make_enc_info(unsigned char *encoding,
                                  size_t encoding_length,
                                  unsigned char *info, size_t *info_len);

# endif
#endif
