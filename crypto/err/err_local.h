/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/e_os2.h>

static ossl_inline void err_get_slot(ERR_STATE *es)
{
    es->top = (es->top + 1) % ERR_NUM_ERRORS;
    if (es->top == es->bottom)
        es->bottom = (es->bottom + 1) % ERR_NUM_ERRORS;
}

static ossl_inline void err_clear_data(ERR_STATE *es, size_t i, int deall)
{
    if (es->err_data_flags[i] & ERR_TXT_MALLOCED) {
        if (deall) {
            OPENSSL_free(es->err_data[i]);
            es->err_data[i] = NULL;
            es->err_data_size[i] = 0;
            es->err_data_flags[i] = 0;
        } else if (es->err_data[i] != NULL) {
            es->err_data[i][0] = '\0';
        }
    } else {
        es->err_data[i] = NULL;
        es->err_data_size[i] = 0;
        es->err_data_flags[i] = 0;
    }
}

static ossl_inline void err_set_error(ERR_STATE *es, size_t i,
                                      int lib, int reason)
{
    es->err_buffer[i] = ERR_PACK(lib, 0, reason);
}

static ossl_inline void err_set_debug(ERR_STATE *es, size_t i,
                                      const char *file, int line,
                                      const char *fn)
{
    es->err_file[i] = file;
    es->err_line[i] = line;
    es->err_func[i] = fn;
}

static ossl_inline void err_set_data(ERR_STATE *es, size_t i,
                                     void *data, size_t datasz, int flags)
{
    es->err_data[i] = data;
    es->err_data_size[i] = datasz;
    es->err_data_flags[i] = flags;
}

static ossl_inline void err_clear(ERR_STATE *es, size_t i, int deall)
{
    err_clear_data(es, i, (deall));
    es->err_flags[i] = 0;
    es->err_buffer[i] = 0;
    es->err_file[i] = NULL;
    es->err_line[i] = -1;
}

ERR_STATE *err_get_state_int(void);
