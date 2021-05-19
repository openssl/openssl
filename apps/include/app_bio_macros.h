/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APP_BIO_MACROS_H
# define OSSL_APP_BIO_MACROS_H

/* The functions are declared in app_bio_functions.h */
# define bio_in (*app_bio_in_location())
# define bio_out (*app_bio_out_location())
# define bio_err (*app_bio_err_location())

#endif
