/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TEST_SHIM_PACKETED_BIO_H
#define OSSL_TEST_SHIM_PACKETED_BIO_H

#include <functional>

#include <openssl/base.h>

#if defined(OPENSSL_WINDOWS)
#include <winsock2.h>
#else
#include <sys/time.h>
#endif


// PacketedBioCreate creates a filter BIO which implements a reliable in-order
// blocking datagram socket. It uses the value of |*clock| as the clock.
// |get_timeout| should output what the |SSL| object believes is the next
// timeout, or return false if there is none. It will be compared against
// assertions from the runner. |set_mtu| will be called when the runner asks to
// change the MTU.
//
// During a |BIO_read|, the peer may signal the filter BIO to simulate a
// timeout. The operation will fail immediately. The caller must then call
// |PacketedBioAdvanceClock| before retrying |BIO_read|.
bssl::UniquePtr<BIO> PacketedBioCreate(
    timeval *clock, std::function<bool(timeval *)> get_timeout,
    std::function<bool(uint32_t)> set_mtu);

// PacketedBioAdvanceClock advances |bio|'s clock and returns true if there is a
// pending timeout. Otherwise, it returns false.
bool PacketedBioAdvanceClock(BIO *bio);

// PacketedBioAdvanceClock return's |bio|'s clock.
timeval *PacketedBioGetClock(BIO *bio);


#endif  // OSSL_TEST_SHIM_PACKETED_BIO_H
