/* ssl/ssl_stat.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
#include "ssl_locl.h"

const char *SSL_state_string_long(const SSL *s)
{
    const char *str;

    if (ossl_statem_in_error(s)) {
        return "error";
    }

    switch (SSL_get_state(s)) {
    case TLS_ST_BEFORE:
        str = "before SSL initialization";
        break;
    case TLS_ST_OK:
        str = "SSL negotiation finished successfully";
        break;

/* SSLv3 additions */
    case TLS_ST_CW_CLNT_HELLO:
        str = "SSLv3/TLS write client hello";
        break;
    case TLS_ST_CR_SRVR_HELLO:
        str = "SSLv3/TLS read server hello";
        break;
    case TLS_ST_CR_CERT:
        str = "SSLv3/TLS read server certificate";
        break;
    case TLS_ST_CR_KEY_EXCH:
        str = "SSLv3/TLS read server key exchange";
        break;
    case TLS_ST_CR_CERT_REQ:
        str = "SSLv3/TLS read server certificate request";
        break;
    case TLS_ST_CR_SESSION_TICKET:
        str = "SSLv3/TLS read server session ticket";
        break;
    case TLS_ST_CR_SRVR_DONE:
        str = "SSLv3/TLS read server done";
        break;
    case TLS_ST_CW_CERT:
        str = "SSLv3/TLS write client certificate";
        break;
    case TLS_ST_CW_KEY_EXCH:
        str = "SSLv3/TLS write client key exchange";
        break;
    case TLS_ST_CW_CERT_VRFY:
        str = "SSLv3/TLS write certificate verify";
        break;

    case TLS_ST_CW_CHANGE:
    case TLS_ST_SW_CHANGE:
        str = "SSLv3/TLS write change cipher spec";
        break;
    case TLS_ST_CW_FINISHED:
    case TLS_ST_SW_FINISHED:
        str = "SSLv3/TLS write finished";
        break;
    case TLS_ST_CR_CHANGE:
    case TLS_ST_SR_CHANGE:
        str = "SSLv3/TLS read change cipher spec";
        break;
    case TLS_ST_CR_FINISHED:
    case TLS_ST_SR_FINISHED:
        str = "SSLv3/TLS read finished";
        break;

    case TLS_ST_SR_CLNT_HELLO:
        str = "SSLv3/TLS read client hello";
        break;
    case TLS_ST_SW_HELLO_REQ:
        str = "SSLv3/TLS write hello request";
        break;
    case TLS_ST_SW_SRVR_HELLO:
        str = "SSLv3/TLS write server hello";
        break;
    case TLS_ST_SW_CERT:
        str = "SSLv3/TLS write certificate";
        break;
    case TLS_ST_SW_KEY_EXCH:
        str = "SSLv3/TLS write key exchange";
        break;
    case TLS_ST_SW_CERT_REQ:
        str = "SSLv3/TLS write certificate request";
        break;
    case TLS_ST_SW_SESSION_TICKET:
        str = "SSLv3/TLS write session ticket";
        break;
    case TLS_ST_SW_SRVR_DONE:
        str = "SSLv3/TLS write server done";
        break;
    case TLS_ST_SR_CERT:
        str = "SSLv3/TLS read client certificate";
        break;
    case TLS_ST_SR_KEY_EXCH:
        str = "SSLv3/TLS read client key exchange";
        break;
    case TLS_ST_SR_CERT_VRFY:
        str = "SSLv3/TLS read certificate verify";
        break;

/* DTLS */
    case DTLS_ST_CR_HELLO_VERIFY_REQUEST:
        str = "DTLS1 read hello verify request";
        break;
    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        str = "DTLS1 write hello verify request";
        break;

    default:
        str = "unknown state";
        break;
    }
    return (str);
}


const char *SSL_state_string(const SSL *s)
{
    const char *str;

    if (ossl_statem_in_error(s)) {
        return "SSLERR";
    }

    switch (SSL_get_state(s)) {
    case TLS_ST_BEFORE:
        str = "PINIT ";
        break;
    case TLS_ST_OK:
        str = "SSLOK ";
        break;

    case TLS_ST_CW_CLNT_HELLO:
        str = "TWCH";
        break;
    case TLS_ST_CR_SRVR_HELLO:
        str = "TRSH";
        break;
    case TLS_ST_CR_CERT:
        str = "TRSC";
        break;
    case TLS_ST_CR_KEY_EXCH:
        str = "TRSKE";
        break;
    case TLS_ST_CR_CERT_REQ:
        str = "TRCR";
        break;
    case TLS_ST_CR_SRVR_DONE:
        str = "TRSD";
        break;
    case TLS_ST_CW_CERT:
        str = "TWCC";
        break;
    case TLS_ST_CW_KEY_EXCH:
        str = "TWCKE";
        break;
    case TLS_ST_CW_CERT_VRFY:
        str = "TWCV";
        break;

    case TLS_ST_SW_CHANGE:
    case TLS_ST_CW_CHANGE:
        str = "TWCCS";
        break;
    case TLS_ST_SW_FINISHED:
    case TLS_ST_CW_FINISHED:
        str = "TWFIN";
        break;
    case TLS_ST_SR_CHANGE:
    case TLS_ST_CR_CHANGE:
        str = "TRCCS";
        break;
    case TLS_ST_SR_FINISHED:
    case TLS_ST_CR_FINISHED:
        str = "TRFIN";
        break;

    case TLS_ST_SW_HELLO_REQ:
        str = "TWHR";
        break;
    case TLS_ST_SR_CLNT_HELLO:
        str = "TRCH";
        break;
    case TLS_ST_SW_SRVR_HELLO:
        str = "TWSH";
        break;
    case TLS_ST_SW_CERT:
        str = "TWSC";
        break;
    case TLS_ST_SW_KEY_EXCH:
        str = "TWSKE";
        break;
    case TLS_ST_SW_CERT_REQ:
        str = "TWCR";
        break;
    case TLS_ST_SW_SRVR_DONE:
        str = "TWSD";
        break;
    case TLS_ST_SR_CERT:
        str = "TRCC";
        break;
    case TLS_ST_SR_KEY_EXCH:
        str = "TRCKE";
        break;
    case TLS_ST_SR_CERT_VRFY:
        str = "TRCV";
        break;

/* DTLS */
    case DTLS_ST_CR_HELLO_VERIFY_REQUEST:
        str = "DRCHV";
        break;
    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        str = "DWCHV";
        break;

    default:
        str = "UNKWN ";
        break;
    }
    return (str);
}

const char *SSL_alert_type_string_long(int value)
{
    value >>= 8;
    if (value == SSL3_AL_WARNING)
        return ("warning");
    else if (value == SSL3_AL_FATAL)
        return ("fatal");
    else
        return ("unknown");
}

const char *SSL_alert_type_string(int value)
{
    value >>= 8;
    if (value == SSL3_AL_WARNING)
        return ("W");
    else if (value == SSL3_AL_FATAL)
        return ("F");
    else
        return ("U");
}

const char *SSL_alert_desc_string(int value)
{
    const char *str;

    switch (value & 0xff) {
    case SSL3_AD_CLOSE_NOTIFY:
        str = "CN";
        break;
    case SSL3_AD_UNEXPECTED_MESSAGE:
        str = "UM";
        break;
    case SSL3_AD_BAD_RECORD_MAC:
        str = "BM";
        break;
    case SSL3_AD_DECOMPRESSION_FAILURE:
        str = "DF";
        break;
    case SSL3_AD_HANDSHAKE_FAILURE:
        str = "HF";
        break;
    case SSL3_AD_NO_CERTIFICATE:
        str = "NC";
        break;
    case SSL3_AD_BAD_CERTIFICATE:
        str = "BC";
        break;
    case SSL3_AD_UNSUPPORTED_CERTIFICATE:
        str = "UC";
        break;
    case SSL3_AD_CERTIFICATE_REVOKED:
        str = "CR";
        break;
    case SSL3_AD_CERTIFICATE_EXPIRED:
        str = "CE";
        break;
    case SSL3_AD_CERTIFICATE_UNKNOWN:
        str = "CU";
        break;
    case SSL3_AD_ILLEGAL_PARAMETER:
        str = "IP";
        break;
    case TLS1_AD_DECRYPTION_FAILED:
        str = "DC";
        break;
    case TLS1_AD_RECORD_OVERFLOW:
        str = "RO";
        break;
    case TLS1_AD_UNKNOWN_CA:
        str = "CA";
        break;
    case TLS1_AD_ACCESS_DENIED:
        str = "AD";
        break;
    case TLS1_AD_DECODE_ERROR:
        str = "DE";
        break;
    case TLS1_AD_DECRYPT_ERROR:
        str = "CY";
        break;
    case TLS1_AD_EXPORT_RESTRICTION:
        str = "ER";
        break;
    case TLS1_AD_PROTOCOL_VERSION:
        str = "PV";
        break;
    case TLS1_AD_INSUFFICIENT_SECURITY:
        str = "IS";
        break;
    case TLS1_AD_INTERNAL_ERROR:
        str = "IE";
        break;
    case TLS1_AD_USER_CANCELLED:
        str = "US";
        break;
    case TLS1_AD_NO_RENEGOTIATION:
        str = "NR";
        break;
    case TLS1_AD_UNSUPPORTED_EXTENSION:
        str = "UE";
        break;
    case TLS1_AD_CERTIFICATE_UNOBTAINABLE:
        str = "CO";
        break;
    case TLS1_AD_UNRECOGNIZED_NAME:
        str = "UN";
        break;
    case TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        str = "BR";
        break;
    case TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:
        str = "BH";
        break;
    case TLS1_AD_UNKNOWN_PSK_IDENTITY:
        str = "UP";
        break;
    default:
        str = "UK";
        break;
    }
    return (str);
}

const char *SSL_alert_desc_string_long(int value)
{
    const char *str;

    switch (value & 0xff) {
    case SSL3_AD_CLOSE_NOTIFY:
        str = "close notify";
        break;
    case SSL3_AD_UNEXPECTED_MESSAGE:
        str = "unexpected_message";
        break;
    case SSL3_AD_BAD_RECORD_MAC:
        str = "bad record mac";
        break;
    case SSL3_AD_DECOMPRESSION_FAILURE:
        str = "decompression failure";
        break;
    case SSL3_AD_HANDSHAKE_FAILURE:
        str = "handshake failure";
        break;
    case SSL3_AD_NO_CERTIFICATE:
        str = "no certificate";
        break;
    case SSL3_AD_BAD_CERTIFICATE:
        str = "bad certificate";
        break;
    case SSL3_AD_UNSUPPORTED_CERTIFICATE:
        str = "unsupported certificate";
        break;
    case SSL3_AD_CERTIFICATE_REVOKED:
        str = "certificate revoked";
        break;
    case SSL3_AD_CERTIFICATE_EXPIRED:
        str = "certificate expired";
        break;
    case SSL3_AD_CERTIFICATE_UNKNOWN:
        str = "certificate unknown";
        break;
    case SSL3_AD_ILLEGAL_PARAMETER:
        str = "illegal parameter";
        break;
    case TLS1_AD_DECRYPTION_FAILED:
        str = "decryption failed";
        break;
    case TLS1_AD_RECORD_OVERFLOW:
        str = "record overflow";
        break;
    case TLS1_AD_UNKNOWN_CA:
        str = "unknown CA";
        break;
    case TLS1_AD_ACCESS_DENIED:
        str = "access denied";
        break;
    case TLS1_AD_DECODE_ERROR:
        str = "decode error";
        break;
    case TLS1_AD_DECRYPT_ERROR:
        str = "decrypt error";
        break;
    case TLS1_AD_EXPORT_RESTRICTION:
        str = "export restriction";
        break;
    case TLS1_AD_PROTOCOL_VERSION:
        str = "protocol version";
        break;
    case TLS1_AD_INSUFFICIENT_SECURITY:
        str = "insufficient security";
        break;
    case TLS1_AD_INTERNAL_ERROR:
        str = "internal error";
        break;
    case TLS1_AD_USER_CANCELLED:
        str = "user canceled";
        break;
    case TLS1_AD_NO_RENEGOTIATION:
        str = "no renegotiation";
        break;
    case TLS1_AD_UNSUPPORTED_EXTENSION:
        str = "unsupported extension";
        break;
    case TLS1_AD_CERTIFICATE_UNOBTAINABLE:
        str = "certificate unobtainable";
        break;
    case TLS1_AD_UNRECOGNIZED_NAME:
        str = "unrecognized name";
        break;
    case TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        str = "bad certificate status response";
        break;
    case TLS1_AD_BAD_CERTIFICATE_HASH_VALUE:
        str = "bad certificate hash value";
        break;
    case TLS1_AD_UNKNOWN_PSK_IDENTITY:
        str = "unknown PSK identity";
        break;
    default:
        str = "unknown";
        break;
    }
    return (str);
}
