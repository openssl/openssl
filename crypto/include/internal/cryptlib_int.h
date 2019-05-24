/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

/* This file is not scanned by mkdef.pl, whereas cryptlib.h is */

typedef void (*ossl_thread_stop_handler_fn)(OPENSSL_CTX *ctx);
int ossl_init_thread_start(OPENSSL_CTX *ctx,
                           ossl_thread_stop_handler_fn handfn);
int init_thread(void);
void cleanup_thread(void);

/*
 * OPENSSL_INIT flags. The primary list of these is in crypto.h. Flags below
 * are those omitted from crypto.h because they are "reserved for internal
 * use".
 */
# define OPENSSL_INIT_ZLIB                   0x00010000L
# define OPENSSL_INIT_BASE_ONLY              0x00040000L

int ossl_trace_init(void);
void ossl_trace_cleanup(void);
void ossl_malloc_setup_failures(void);
