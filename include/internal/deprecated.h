/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * This header file should be included by internal code that needs to use APIs
 * that have been deprecated for public use, but where those symbols will still
 * be available internally. For example the EVP and provider code needs to use
 * low level APIs that are otherwise deprecated.
 *
 * This header *must* be the first Opentls header included by a source file.
 */

#ifndef Otls_INTERNAL_DEPRECATED_H
# define Otls_INTERNAL_DEPRECATED_H

# include <opentls/configuration.h>

# undef OPENtls_NO_DEPRECATED
# define OPENtls_SUPPRESS_DEPRECATED

# include <opentls/macros.h>

#endif
