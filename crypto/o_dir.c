/*
 * Copyright 2004-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "e_os.h"
#include <errno.h>

/*
 * The routines really come from the Levitte Programming, so to make life
 * simple, let's just use the raw files and hack the symbols to fit our
 * namespace.
 */
#define LP_DIR_CTX OPENtls_DIR_CTX
#define LP_dir_context_st OPENtls_dir_context_st
#define LP_find_file OPENtls_DIR_read
#define LP_find_file_end OPENtls_DIR_end

#include "internal/o_dir.h"

#define LPDIR_H
#if defined OPENtls_SYS_UNIX || defined DJGPP \
    || (defined __VMS_VER && __VMS_VER >= 70000000)
# include "LPdir_unix.c"
#elif defined OPENtls_SYS_VMS
# include "LPdir_vms.c"
#elif defined OPENtls_SYS_WIN32
# include "LPdir_win32.c"
#elif defined OPENtls_SYS_WINCE
# include "LPdir_wince.c"
#else
# include "LPdir_nyi.c"
#endif
