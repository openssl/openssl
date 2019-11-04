/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/cmperr.h>

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA CMP_str_reasons[] = {
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_ERROR_PARSING_PKISTATUS),
    "error parsing pkistatus"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_FAILURE_OBTAINING_RANDOM),
    "failure obtaining random"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_INVALID_ARGS), "invalid args"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_MULTIPLE_SAN_SOURCES),
    "multiple san sources"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_MISSING_SENDER_IDENTIFICATION),
    "missing sender identification"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_NO_STDIO), "no stdio"},
    {ERR_PACK(ERR_LIB_CMP, 0, CMP_R_NULL_ARGUMENT), "null argument"},
    {0, NULL}
};

#endif

int ERR_load_CMP_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(CMP_str_reasons[0].error) == NULL)
        ERR_load_strings_const(CMP_str_reasons);
#endif
    return 1;
}
