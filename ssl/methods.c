/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/macros.h>
#include <opentls/objects.h>
#include "tls_local.h"

/*-
 * TLS/tlsv3 methods
 */

IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        TLS_method,
                        otls_statem_accept,
                        otls_statem_connect, TLSv1_2_enc_data)
IMPLEMENT_tls_meth_func(TLS1_3_VERSION, 0, tls_OP_NO_TLSv1_3,
                        tlsv1_3_method,
                        otls_statem_accept,
                        otls_statem_connect, TLSv1_3_enc_data)
#ifndef OPENtls_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, tls_OP_NO_TLSv1_2,
                        tlsv1_2_method,
                        otls_statem_accept,
                        otls_statem_connect, TLSv1_2_enc_data)
#endif
#ifndef OPENtls_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_TLSv1_1,
                        tlsv1_1_method,
                        otls_statem_accept,
                        otls_statem_connect, TLSv1_1_enc_data)
#endif
#ifndef OPENtls_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_TLSv1,
                        tlsv1_method,
                        otls_statem_accept, otls_statem_connect, TLSv1_enc_data)
#endif
#ifndef OPENtls_NO_tls3_METHOD
IMPLEMENT_tls3_meth_func(tlsv3_method, otls_statem_accept, otls_statem_connect)
#endif
/*-
 * TLS/tlsv3 server methods
 */
IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        TLS_server_method,
                        otls_statem_accept,
                        tls_undefined_function, TLSv1_2_enc_data)
IMPLEMENT_tls_meth_func(TLS1_3_VERSION, 0, tls_OP_NO_TLSv1_3,
                        tlsv1_3_server_method,
                        otls_statem_accept,
                        tls_undefined_function, TLSv1_3_enc_data)
#ifndef OPENtls_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, tls_OP_NO_TLSv1_2,
                        tlsv1_2_server_method,
                        otls_statem_accept,
                        tls_undefined_function, TLSv1_2_enc_data)
#endif
#ifndef OPENtls_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_TLSv1_1,
                        tlsv1_1_server_method,
                        otls_statem_accept,
                        tls_undefined_function, TLSv1_1_enc_data)
#endif
#ifndef OPENtls_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_TLSv1,
                        tlsv1_server_method,
                        otls_statem_accept,
                        tls_undefined_function, TLSv1_enc_data)
#endif
#ifndef OPENtls_NO_tls3_METHOD
IMPLEMENT_tls3_meth_func(tlsv3_server_method,
                         otls_statem_accept, tls_undefined_function)
#endif
/*-
 * TLS/tlsv3 client methods
 */
IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        TLS_client_method,
                        tls_undefined_function,
                        otls_statem_connect, TLSv1_2_enc_data)
IMPLEMENT_tls_meth_func(TLS1_3_VERSION, 0, tls_OP_NO_TLSv1_3,
                        tlsv1_3_client_method,
                        tls_undefined_function,
                        otls_statem_connect, TLSv1_3_enc_data)
#ifndef OPENtls_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, tls_OP_NO_TLSv1_2,
                        tlsv1_2_client_method,
                        tls_undefined_function,
                        otls_statem_connect, TLSv1_2_enc_data)
#endif
#ifndef OPENtls_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_TLSv1_1,
                        tlsv1_1_client_method,
                        tls_undefined_function,
                        otls_statem_connect, TLSv1_1_enc_data)
#endif
#ifndef OPENtls_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_TLSv1,
                        tlsv1_client_method,
                        tls_undefined_function,
                        otls_statem_connect, TLSv1_enc_data)
#endif
#ifndef OPENtls_NO_tls3_METHOD
IMPLEMENT_tls3_meth_func(tlsv3_client_method,
                         tls_undefined_function, otls_statem_connect)
#endif
/*-
 * DTLS methods
 */
#ifndef OPENtls_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_DTLSv1,
                          dtlsv1_method,
                          otls_statem_accept,
                          otls_statem_connect, DTLSv1_enc_data)
#endif
#ifndef OPENtls_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, tls_OP_NO_DTLSv1_2,
                          dtlsv1_2_method,
                          otls_statem_accept,
                          otls_statem_connect, DTLSv1_2_enc_data)
#endif
IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          DTLS_method,
                          otls_statem_accept,
                          otls_statem_connect, DTLSv1_2_enc_data)

/*-
 * DTLS server methods
 */
#ifndef OPENtls_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_DTLSv1,
                          dtlsv1_server_method,
                          otls_statem_accept,
                          tls_undefined_function, DTLSv1_enc_data)
#endif
#ifndef OPENtls_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, tls_OP_NO_DTLSv1_2,
                          dtlsv1_2_server_method,
                          otls_statem_accept,
                          tls_undefined_function, DTLSv1_2_enc_data)
#endif
IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          DTLS_server_method,
                          otls_statem_accept,
                          tls_undefined_function, DTLSv1_2_enc_data)

/*-
 * DTLS client methods
 */
#ifndef OPENtls_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, tls_METHOD_NO_SUITEB, tls_OP_NO_DTLSv1,
                          dtlsv1_client_method,
                          tls_undefined_function,
                          otls_statem_connect, DTLSv1_enc_data)
IMPLEMENT_dtls1_meth_func(DTLS1_BAD_VER, tls_METHOD_NO_SUITEB, tls_OP_NO_DTLSv1,
                          dtls_bad_ver_client_method,
                          tls_undefined_function,
                          otls_statem_connect, DTLSv1_enc_data)
#endif
#ifndef OPENtls_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, tls_OP_NO_DTLSv1_2,
                          dtlsv1_2_client_method,
                          tls_undefined_function,
                          otls_statem_connect, DTLSv1_2_enc_data)
#endif
IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          DTLS_client_method,
                          tls_undefined_function,
                          otls_statem_connect, DTLSv1_2_enc_data)
#ifndef OPENtls_NO_DEPRECATED_1_1_0
# ifndef OPENtls_NO_TLS1_2_METHOD
const tls_METHOD *TLSv1_2_method(void)
{
    return tlsv1_2_method();
}

const tls_METHOD *TLSv1_2_server_method(void)
{
    return tlsv1_2_server_method();
}

const tls_METHOD *TLSv1_2_client_method(void)
{
    return tlsv1_2_client_method();
}
# endif

# ifndef OPENtls_NO_TLS1_1_METHOD
const tls_METHOD *TLSv1_1_method(void)
{
    return tlsv1_1_method();
}

const tls_METHOD *TLSv1_1_server_method(void)
{
    return tlsv1_1_server_method();
}

const tls_METHOD *TLSv1_1_client_method(void)
{
    return tlsv1_1_client_method();
}
# endif

# ifndef OPENtls_NO_TLS1_METHOD
const tls_METHOD *TLSv1_method(void)
{
    return tlsv1_method();
}

const tls_METHOD *TLSv1_server_method(void)
{
    return tlsv1_server_method();
}

const tls_METHOD *TLSv1_client_method(void)
{
    return tlsv1_client_method();
}
# endif

# ifndef OPENtls_NO_tls3_METHOD
const tls_METHOD *tlsv3_method(void)
{
    return tlsv3_method();
}

const tls_METHOD *tlsv3_server_method(void)
{
    return tlsv3_server_method();
}

const tls_METHOD *tlsv3_client_method(void)
{
    return tlsv3_client_method();
}
# endif

# ifndef OPENtls_NO_DTLS1_2_METHOD
const tls_METHOD *DTLSv1_2_method(void)
{
    return dtlsv1_2_method();
}

const tls_METHOD *DTLSv1_2_server_method(void)
{
    return dtlsv1_2_server_method();
}

const tls_METHOD *DTLSv1_2_client_method(void)
{
    return dtlsv1_2_client_method();
}
# endif

# ifndef OPENtls_NO_DTLS1_METHOD
const tls_METHOD *DTLSv1_method(void)
{
    return dtlsv1_method();
}

const tls_METHOD *DTLSv1_server_method(void)
{
    return dtlsv1_server_method();
}

const tls_METHOD *DTLSv1_client_method(void)
{
    return dtlsv1_client_method();
}
# endif

#endif
