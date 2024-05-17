/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * These functions are ECH helpers that are used by functions within
 * ssl/ech.c but also by test code e.g. in test/echcorrupttest.c
 */

#ifndef OPENSSL_ECH_HELPERS_H
# define OPENSSL_ECH_HELPERS_H
# pragma once

# ifndef OPENSSL_NO_ECH

/*
 * @brief Given a CH find the offsets of the session id, extensions and ECH
 * @param: ch is the encoded client hello
 * @param: ch_len is the length of ch
 * @param: sessid returns offset of session_id length
 * @param: exts points to offset of extensions
 * @param: extlens returns length of extensions
 * @param: echoffset returns offset of ECH
 * @param: echtype returns the ext type of the ECH
 * @param: echlen returns the length of the ECH
 * @param: snioffset returns offset of (outer) SNI
 * @param: snilen returns the length of the SNI
 * @param: inner 1 if the ECH is marked as an inner, 0 for outer
 * @return 1 for success, other otherwise
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 *
 * Note: input here is untrusted!
 */
int ech_helper_get_ch_offsets(const unsigned char *ch, size_t ch_len,
                              size_t *sessid, size_t *exts, size_t *extlens,
                              size_t *echoffset, uint16_t *echtype,
                              size_t *echlen,
                              size_t *snioffset, size_t *snilen, int *inner);

/*!
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * @param: sh is the SH buffer
 * @paramL sh_len is the length of the SH
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @return 1 for success, other otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
int ech_helper_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                              size_t *exts, size_t *echoffset,
                              uint16_t *echtype);

/*
 * @brief make up HPKE "info" input as per spec
 * @param encoding is the ECHconfig being used
 * @param encodinglen is the length of ECHconfig being used
 * @param info is a caller-allocated buffer for results
 * @param info_len is the buffer size on input, used-length on output
 * @return 1 for success, other otherwise
 */
int ech_helper_make_enc_info(unsigned char *encoding, size_t encoding_length,
                             unsigned char *info, size_t *info_len);

/*
 * @brief Decode from TXT RR to binary buffer
 * @param in is the base64 encoded string
 * @param inlen is the length of in
 * @param out is the binary equivalent
 * @return is the number of octets in |out| if successful, <=0 for failure
 */
int ech_helper_base64_decode(char *in, size_t inlen, unsigned char **out);
# endif
#endif
