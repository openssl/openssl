/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/*
 * ====================================================================
 * Copyright 2016 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 * Authored by Diego F. Aranha (d@miracl.com).
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bp.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_EC,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_EC,0,reason)

static ERR_STRING_DATA BP_str_functs[] = {
    {BP_F_G1_ELEM_NEW, "G1_ELEM_new"},
    {BP_F_G2_ELEM_NEW, "G2_ELEM_new"},
    {BP_F_G2_ELEM_SET_AFFINE_COORDINATES, "G2_ELEM_set_affine_coordinates"},
    {BP_F_G2_ELEM_GET_AFFINE_COORDINATES, "G2_ELEM_get_affine_coordinates"},
    {BP_F_G2_ELEM_POINT2OCT, " G2_ELEM_point2oct"},
    {BP_F_G2_ELEM_OCT2POINT, " G2_ELEM_oct2point"},
    {BP_F_G2_ELEM_ADD, "G2_ELEM_add"},
    {BP_F_G2_ELEM_DBL, "G2_ELEM_dbl"},
    {BP_F_G2_ELEM_CMP, "G2_ELEM_cmp"},
    {BP_F_G2_ELEM_is_on_curve, "G2_ELEM_is_on_curve"},
    {BP_F_G2_ELEMS_MUL, "G2_ELEMs_MUL"},
    {BP_F_G2_WNAF_PRECOMPUTE_MULT, "g2_wnaf_precompute_mult"},
    {0, NULL}
};

static ERR_STRING_DATA BP_str_reasons[] = {
    {ERR_REASON(BP_R_BIGNUM_OUT_OF_RANGE), "bignum out of range"},
    {ERR_REASON(BP_R_BUFFER_TOO_SMALL), "buffer too small"},
    {ERR_REASON(BP_R_COORDINATES_OUT_OF_RANGE), "coordinates out of range"},
    {ERR_REASON(BP_R_DECODE_ERROR), "decode error"},
    {ERR_REASON(BP_R_BP_GROUP_NEW_BY_NAME_FAILURE),
     "group new by name failure"},
    {ERR_REASON(BP_R_INCOMPATIBLE_OBJECTS), "incompatible objects"},
    {ERR_REASON(BP_R_INVALID_ARGUMENT), "invalid argument"},
    {ERR_REASON(BP_R_INVALID_COMPRESSED_POINT), "invalid compressed point"},
    {ERR_REASON(BP_R_INVALID_COMPRESSION_BIT), "invalid compression bit"},
    {ERR_REASON(BP_R_INVALID_CURVE), "invalid curve"},
    {ERR_REASON(BP_R_INVALID_ENCODING), "invalid encoding"},
    {ERR_REASON(BP_R_INVALID_FIELD), "invalid field"},
    {ERR_REASON(BP_R_INVALID_FORM), "invalid form"},
    {ERR_REASON(BP_R_INVALID_GROUP_ORDER), "invalid group order"},
    {ERR_REASON(BP_R_MISSING_PARAMETERS), "missing parameters"},
    {ERR_REASON(BP_R_NEED_NEW_SETUP_VALUES), "need new setup values"},
    {ERR_REASON(BP_R_NOT_IMPLEMENTED), "not implemented"},
    {ERR_REASON(BP_R_NOT_INITIALIZED), "not initialized"},
    {ERR_REASON(BP_R_NO_FIELD_MOD), "no field mod"},
    {ERR_REASON(BP_R_NO_PARAMETERS_SET), "no parameters set"},
    {ERR_REASON(BP_R_OPERATION_NOT_SUPPORTED), "operation not supported"},
    {ERR_REASON(BP_R_PASSED_NULL_PARAMETER), "passed null parameter"},
    {ERR_REASON(BP_R_POINT_ARITHMETIC_FAILURE), "point arithmetic failure"},
    {ERR_REASON(BP_R_POINT_AT_INFINITY), "point at infinity"},
    {ERR_REASON(BP_R_POINT_IS_NOT_ON_CURVE), "point is not on curve"},
    {ERR_REASON(BP_R_UNDEFINED_GENERATOR), "undefined generator"},
    {ERR_REASON(BP_R_UNDEFINED_ORDER), "undefined order"},
    {ERR_REASON(BP_R_UNKNOWN_GROUP), "unknown group"},
    {ERR_REASON(BP_R_UNKNOWN_ORDER), "unknown order"},
    {ERR_REASON(BP_R_UNSUPPORTED_FIELD), "unsupported field"},
    {ERR_REASON(BP_R_WRONG_CURVE_PARAMETERS), "wrong curve parameters"},
    {ERR_REASON(BP_R_WRONG_ORDER), "wrong order"},
    {0, NULL}
};

#endif

void ERR_load_BP_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(BP_str_functs[0].error) == NULL) {
        ERR_load_strings(0, BP_str_functs);
        ERR_load_strings(0, BP_str_reasons);
    }
#endif
}
