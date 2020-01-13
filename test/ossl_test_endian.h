/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_TEST_Otls_TEST_ENDIAN_H
# define Otls_TEST_Otls_TEST_ENDIAN_H

# define DECLARE_IS_ENDIAN \
    const union { \
        long one; \
        char little; \
    } otls_is_endian = { 1 }

# define IS_LITTLE_ENDIAN (otls_is_endian.little != 0)
# define IS_BIG_ENDIAN    (otls_is_endian.little == 0)

#endif
