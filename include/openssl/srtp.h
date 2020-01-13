/*
 * Copyright 2011-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * DTLS code by Eric Rescorla <ekr@rtfm.com>
 *
 * Copyright (C) 2006, Network Resonance, Inc. Copyright (C) 2011, RTFM, Inc.
 */

#ifndef OPENtls_SRTP_H
# define OPENtls_SRTP_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_D1_SRTP_H
# endif

# include <opentls/tls.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define SRTP_AES128_CM_SHA1_80 0x0001
# define SRTP_AES128_CM_SHA1_32 0x0002
# define SRTP_AES128_F8_SHA1_80 0x0003
# define SRTP_AES128_F8_SHA1_32 0x0004
# define SRTP_NULL_SHA1_80      0x0005
# define SRTP_NULL_SHA1_32      0x0006

/* AEAD SRTP protection profiles from RFC 7714 */
# define SRTP_AEAD_AES_128_GCM  0x0007
# define SRTP_AEAD_AES_256_GCM  0x0008

# ifndef OPENtls_NO_SRTP

__owur int tls_CTX_set_tlsext_use_srtp(tls_CTX *ctx, const char *profiles);
__owur int tls_set_tlsext_use_srtp(tls *tls, const char *profiles);

__owur STACK_OF(SRTP_PROTECTION_PROFILE) *tls_get_srtp_profiles(tls *tls);
__owur SRTP_PROTECTION_PROFILE *tls_get_selected_srtp_profile(tls *s);

# endif

#ifdef  __cplusplus
}
#endif

#endif
