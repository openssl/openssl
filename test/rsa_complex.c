/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Check to see if there is a conflict between complex.h and openssl/rsa.h.
 * The former defines "I" as a macro and earlier versions of the latter use
 * for function arguments.
 */
#if defined(__STDC_VERSION__)
# if __STDC_VERSION__ >= 199901L
#  include <complex.h>
# endif
#endif
#include <openssl/rsa.h>
#include <stdlib.h>

#ifdef __SUNPRO_C
# pragma weak OPENSSL_sk_pop_free
# pragma weak OPENSSL_sk_dup
# pragma weak OPENSSL_sk_pop
# pragma weak OPENSSL_sk_num
# pragma weak OPENSSL_sk_new
# pragma weak OPENSSL_sk_set
# pragma weak OPENSSL_sk_free
# pragma weak OPENSSL_sk_find
# pragma weak OPENSSL_sk_push
# pragma weak OPENSSL_sk_sort
# pragma weak OPENSSL_sk_zero
# pragma weak OPENSSL_sk_is_sorted
# pragma weak OPENSSL_sk_shift
# pragma weak OPENSSL_sk_value
# pragma weak OPENSSL_sk_delete_ptr
# pragma weak OPENSSL_sk_unshift
# pragma weak OPENSSL_sk_new_null
# pragma weak OPENSSL_sk_set_cmp_func
# pragma weak OPENSSL_sk_delete
# pragma weak OPENSSL_sk_insert
# pragma weak OPENSSL_sk_deep_copy
# pragma weak OPENSSL_sk_find_ex
# pragma weak OPENSSL_sk_reserve
# pragma weak OPENSSL_sk_new_reserve
#endif /* __SUNPRO_C */

int main(int argc, char *argv[])
{
    /* There are explicitly no run time checks for this one */
    return EXIT_SUCCESS;
}
