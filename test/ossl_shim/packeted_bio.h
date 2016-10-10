/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef HEADER_PACKETED_BIO
#define HEADER_PACKETED_BIO

#include <openssl/e_os2.h>
#include <openssl/bio.h>

#include "crypto/scoped_types.h"

#if defined(OPENSSL_SYS_WINDOWS)
#pragma warning(push, 3)
#include <winsock2.h>
#pragma warning(pop)
#else
#include <sys/time.h>
#endif


// PacketedBioCreate creates a filter BIO which implements a reliable in-order
// blocking datagram socket. The resulting BIO, on |BIO_read|, may simulate a
// timeout which sets |*out_timeout| to the timeout and fails the read.
// |*out_timeout| must be zero on entry to |BIO_read|; it is an error to not
// apply the timeout before the next |BIO_read|.
//
// Note: The read timeout simulation is intended to be used with the async BIO
// wrapper. It doesn't simulate BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, used in DTLS's
// blocking mode.
ScopedBIO PacketedBioCreate(timeval *out_timeout);


#endif  // HEADER_PACKETED_BIO
