/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * C99 snprintf and vsnprintf emulation for MSVC versions earlier than
 * Visual Studio 2015 (_MSC_VER < 1900).  Those compilers ship _snprintf
 * and _vsnprintf with non-C99 semantics (return -1 on truncation, no
 * guaranteed NUL termination) and do not provide the standard names at
 * all.  This file supplies the missing C99 names.
 *
 * This file is only compiled when the configured target is one of the
 * Windows MSVC 2013 compatibility variants; on every other platform
 * the standard library already provides these symbols.
 *
 * IMPORTANT: This translation unit MUST define snprintf and vsnprintf
 * and nothing else.  This single file is compiled directly into libcrypto,
 * libssl, and the apps; each references it from its own build.info rather
 * than keeping a copy.  Because each definition lives in its own .obj, the
 * linker's archive-search rule ensures only one copy is pulled into any
 * final binary.  Defining any additional symbol here would risk pulling
 * multiple copies and producing a duplicate-symbol link error.
 */

#include <stdio.h>
#include <stdarg.h>

int vsnprintf(char *buf, size_t n, const char *fmt, va_list args)
{
    int count;
    va_list args_copy;

    va_copy(args_copy, args);
    count = _vscprintf(fmt, args_copy);
    va_end(args_copy);

    if (count < 0)
        return count;

    if (n > 0)
        (void)_vsnprintf_s(buf, n, _TRUNCATE, fmt, args);

    return count;
}

int snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vsnprintf(buf, n, fmt, args);
    va_end(args);
    return ret;
}
