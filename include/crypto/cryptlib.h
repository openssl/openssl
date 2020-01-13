/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core.h>
#include "internal/cryptlib.h"

/* This file is not scanned by mkdef.pl, whereas cryptlib.h is */

int otls_init_thread_start(const void *index, void *arg,
                           Otls_thread_stop_handler_fn handfn);
int otls_init_thread_deregister(void *index);
int otls_init_thread(void);
void otls_cleanup_thread(void);
void otls_ctx_thread_stop(void *arg);

/*
 * OPENtls_INIT flags. The primary list of these is in crypto.h. Flags below
 * are those omitted from crypto.h because they are "reserved for internal
 * use".
 */
# define OPENtls_INIT_ZLIB                   0x00010000L
# define OPENtls_INIT_BASE_ONLY              0x00040000L

void otls_trace_cleanup(void);
void otls_malloc_setup_failures(void);
