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

#ifndef HEADER_ASYNC_BIO
#define HEADER_ASYNC_BIO

#include <openssl/bio.h>

#include "crypto/scoped_types.h"


// AsyncBioCreate creates a filter BIO for testing asynchronous state
// machines which consume a stream socket. Reads and writes will fail
// and return EAGAIN unless explicitly allowed. Each async BIO has a
// read quota and a write quota. Initially both are zero. As each is
// incremented, bytes are allowed to flow through the BIO.
ScopedBIO AsyncBioCreate();

// AsyncBioCreateDatagram creates a filter BIO for testing for
// asynchronous state machines which consume datagram sockets. The read
// and write quota count in packets rather than bytes.
ScopedBIO AsyncBioCreateDatagram();

// AsyncBioAllowRead increments |bio|'s read quota by |count|.
void AsyncBioAllowRead(BIO *bio, size_t count);

// AsyncBioAllowWrite increments |bio|'s write quota by |count|.
void AsyncBioAllowWrite(BIO *bio, size_t count);

// AsyncBioEnforceWriteQuota configures where |bio| enforces its write quota.
void AsyncBioEnforceWriteQuota(BIO *bio, bool enforce);


#endif  // HEADER_ASYNC_BIO
