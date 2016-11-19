/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include "internal/uri.h"
#include "uri_charmap.h"

#include <openssl/e_os2.h>

/*
 * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
 *
 * pct-encoded   = "%" HEXDIG HEXDIG
 */
static int span_pchars2(const char *p, size_t *off, const char *chars)
{
    size_t save_off = *off;

    while (p[*off] != '\0') {
        if (!is_valid(p[*off]))
            break;
        if (p[*off] == '%' && is_HEXDIG(p[*off + 1]) && is_HEXDIG(p[*off + 2]))
            *off += 3;
        else if (is_unreserved(p[*off]) || is_sub_delims(p[*off])
                 || (chars != NULL && strchr(chars, p[*off]) != NULL))
            (*off)++;
        else
            break;
    }
    return *off != save_off;
}
#define span_pchars(p, off) span_pchars2((p), (off), ":@")

static int span_chars(const char *p, size_t *off, unsigned int types,
                      const char *chars)
{
    size_t save_off = *off;

    /*
     * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
     *
     * pct-encoded   = "%" HEXDIG HEXDIG
     */
    while (p[*off] != '\0') {
        if (!is_valid(p[*off]))
            break;
        if (is_type(p[*off], types)
            || (chars != NULL && strchr(chars, p[*off]) != NULL))
            (*off)++;
        else
            break;
    }
    return *off != save_off;
}

/*
 * scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 */
static int extract_scheme(char **scheme, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *scheme = NULL;

    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_SCHEME, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (!is_ALPHA(p[off]))
        return 1;
    while (span_chars(p, &off, CHARTYPE_ALPHA|CHARTYPE_DIGIT, "+-."))
        ;

    /* Check if the loop stopped because of an invalid character */
    if (!is_valid(p[off])) {
        char tmpbuf[200];
        URIerr(URI_F_EXTRACT_SCHEME, URI_R_INVALID_CHARACTER_IN_URI);
        BIO_snprintf(tmpbuf, sizeof(tmpbuf),
                 "character code = %u, offset = %" OSSLzu,
                 (unsigned char)p[off], off);
        ERR_add_error_data(1, tmpbuf);
        return 0;
    }

    if (p[off] != ':')
        return 1;

    if ((*scheme = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_SCHEME, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    off++;
    *pp = p + off;
    return 1;
}

/*
 * userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
 * host          = IP-literal / IPv4address / reg-name
 * port          = *DIGIT
 *
 * IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
 *
 * IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
 *
 * IPv6address   =                            6( h16 ":" ) ls32
 *               /                       "::" 5( h16 ":" ) ls32
 *               / [               h16 ] "::" 4( h16 ":" ) ls32
 *               / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
 *               / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
 *               / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
 *               / [ *4( h16 ":" ) h16 ] "::"              ls32
 *               / [ *5( h16 ":" ) h16 ] "::"              h16
 *               / [ *6( h16 ":" ) h16 ] "::"
 *
 * h16           = 1*4HEXDIG
 * ls32          = ( h16 ":" h16 ) / IPv4address
 * IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
 *
 * dec-octet     = DIGIT                 ; 0-9
 *               / %x31-39 DIGIT         ; 10-99
 *               / "1" 2DIGIT            ; 100-199
 *               / "2" %x30-34 DIGIT     ; 200-249
 *               / "25" %x30-35          ; 250-255
 *
 * reg-name      = *( unreserved / pct-encoded / sub-delims )
 */
static int span_user(const char *p, size_t *off)
{
    (void)span_pchars2(p, off, "");
    return 1;
}
static int span_password(const char *p, size_t *off)
{
    (void)span_pchars2(p, off, "");
    return 1;
}
static int span_userinfo(const char *p, size_t *off)
{
    size_t tmp_off = *off;

    (void)span_user(p, &tmp_off);
    if (p[tmp_off] == ':') {
        tmp_off++;
        (void)span_password(p, &tmp_off);
    }
    if (p[tmp_off] != '@')
        return 0;
    *off = tmp_off + 1;
    return 1;
}
static int span_host(const char *p, size_t *off)
{
    size_t tmp_off = *off;

    if (p[tmp_off] == '[') {
        size_t tmp_off2 = ++tmp_off;

        /* Check for IPvFuture */
        if (p[tmp_off++] != 'v'
            || !span_chars(p, &tmp_off, CHARTYPE_HEXDIG, NULL)
            || p[tmp_off++] != '.'
            || !span_chars(p, &tmp_off, CHARTYPE_unreserved|CHARTYPE_sub_delims,
                          ":")) {
            tmp_off = tmp_off2;

            /* No IPvFuture, check for IPv6address */
            {
                int dblcolon = 0;
                int maxcolons = 7;

                /* check for starting :: */
                if (p[tmp_off] == ':' && p[tmp_off + 1] == ':') {
                    dblcolon++;
                    tmp_off += 2;
                    maxcolons--;
                }

                /*
                 * check for HEXDIG strings followed by : and possibly ONE ::
                 * if we haven't already had one.
                 * We stop after the last colon found
                 */
                {
                    size_t laststart = 0;

                    while ((laststart = tmp_off, 1)
                           && maxcolons > 0
                           && span_chars(p, &tmp_off, CHARTYPE_HEXDIG, "")
                           && p[tmp_off] == ':') {
                        if (p[++tmp_off] == ':') {
                            tmp_off++;
                            if (++dblcolon > 1)
                                break;
                            maxcolons -= 2;
                        } else
                            maxcolons--;
                    }
                    tmp_off = laststart;
                }
                /* If there's more then one ::, all is lost */
                /*
                 * If there was no :: and there wasn't exactly 7 HEXDIG series
                 * followed by a colon, all is lost as well
                 */
                if (dblcolon > 1 || (dblcolon == 0 && maxcolons > 0))
                    tmp_off = tmp_off2;
                /*
                 * Otherwise, we might end this with an IPv4 address,
                 * maxcolumns allowing, and we might also end this with a last
                 * serie of HEXDIG.  We try IPv4 first.
                 */
                else {
                    size_t v4_end = tmp_off;

                    /*
                     * IPv4 addresses take up 32 bits, so it can't be here if
                     * we maxed out on the colons
                     */
                    if (maxcolons > 0
                        && ((p[v4_end] == '0' && (v4_end++, 1))
                            || span_chars(p, &v4_end, CHARTYPE_DIGIT, ""))
                        && p[v4_end++] == '.'
                        && ((p[v4_end] == '0' && (v4_end++, 1))
                            || span_chars(p, &v4_end, CHARTYPE_DIGIT, ""))
                        && p[v4_end++] == '.'
                        && ((p[v4_end] == '0' && (v4_end++, 1))
                            || span_chars(p, &v4_end, CHARTYPE_DIGIT, ""))
                        && p[v4_end++] == '.'
                        && ((p[v4_end] == '0' && (v4_end++, 1))
                            || span_chars(p, &v4_end, CHARTYPE_DIGIT, ""))
                        && v4_end - tmp_off < 16)
                        tmp_off = v4_end;
                    /*
                     * If there was no IPv4 address, we check for an ending
                     * serie of HEXDIG.  If there is no such thing, there MUST
                     * be an ending ::
                     */
                    else if (!span_chars(p, &tmp_off, CHARTYPE_HEXDIG, "")
                             && (dblcolon == 0
                                 || p[tmp_off - 1] != ':'
                                 || p[tmp_off - 2] != ':'))
                        /* None found */
                        tmp_off = tmp_off2;
                }

            }
        }

        if (tmp_off != tmp_off2 && p[tmp_off++] == ']') {
            *off = tmp_off;
            return 1;
        }
    } else {
        size_t tmp_off2 = tmp_off;

        /* Check for IPv4address or reg-name.  The longest wins */
        if (!(((p[tmp_off] == '0' && (tmp_off++, 1))
               || span_chars(p, &tmp_off, CHARTYPE_DIGIT, ""))
              && p[tmp_off++] == '.'
              && ((p[tmp_off] == '0' && (tmp_off++, 1))
                  || span_chars(p, &tmp_off, CHARTYPE_DIGIT, ""))
              && p[tmp_off++] == '.'
              && ((p[tmp_off] == '0' && (tmp_off++, 1))
                  || span_chars(p, &tmp_off, CHARTYPE_DIGIT, ""))
              && p[tmp_off++] == '.'
              && ((p[tmp_off] == '0' && (tmp_off++, 1))
                  || span_chars(p, &tmp_off, CHARTYPE_DIGIT, ""))
              && tmp_off - tmp_off < 16))
            tmp_off = *off;

        (void)span_pchars2(p, &tmp_off2, NULL);

        *off = tmp_off2 > tmp_off ? tmp_off2 : tmp_off;

        return 1;
    }
    return 0;
}
static int span_port(const char *p, size_t *off)
{
    if (p[*off] != ':')
        return 0;
    (*off)++;
    (void)span_chars(p, off, CHARTYPE_DIGIT, NULL);
    return 1;
}

/*
 * authority     = [ userinfo "@" ] host [ ":" port ]
 */
static int extract_authority(char **authority, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *authority = NULL;

    if (!is_valid(*p)) {
        URIerr(URI_F_EXTRACT_AUTHORITY, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }
    if (p[off] != '/')
        return 1;
    p++;
    if (!is_valid(*p)) {
        URIerr(URI_F_EXTRACT_AUTHORITY, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }
    if (p[off] != '/')
        return 1;
    p++;

    (void)span_userinfo(p, &off);
    if (!span_host(p, &off)) {
        URIerr(URI_F_EXTRACT_AUTHORITY, URI_R_MALFORMED_HOST_IN_URI);
        return 0;
    }
    (void)span_port(p, &off);

    /* Check if the spans stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_AUTHORITY, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if ((*authority = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_AUTHORITY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pp = p + off;
    return 1;
}

/*
 * segment       = *pchar
 * segment-nz    = 1*pchar
 * segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
 *               ; non-zero-length segment without any colon ":"
 */
static int span_slash_segment(const char *p, size_t *off)
{
    if (p[*off] != '/')
        return 0;
    (*off)++;
    (void)span_pchars(p, off);
    return 1;
}

static int span_segment_nz(const char *p, size_t *off)
{
    size_t save_off = *off;

    (void)span_pchars(p, off);
    return save_off != *off;
}

static int span_segment_nz_nc(const char *p, size_t *off)
{
    size_t save_off = *off;

    (void)span_pchars2(p, off, "@");
    return save_off != *off;
}

/*
 * path-abempty  = *( "/" segment )
 * path-absolute = "/" [ segment-nz *( "/" segment ) ]
 * path-noscheme = segment-nz-nc *( "/" segment )
 * path-rootless = segment-nz *( "/" segment )
 * path-empty    = 0<pchar>
 */
static int extract_path_abempty(char **path, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *path = NULL;
    while(span_slash_segment(p, &off))
        ;

    /* Check if the loop stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_PATH_ABEMPTY, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (off > 0 && (*path = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_PATH_ABEMPTY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pp = p + off;
    return 1;
}
static int extract_path_absolute(char **path, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *path = NULL;
    if (p[off] == '/') {
        off++;
        if (span_segment_nz(p, &off)) {
            while(span_slash_segment(p, &off))
                ;
        }
    }

    /* Check if the loop stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_PATH_ABSOLUTE, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (off > 0 && (*path = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_PATH_ABSOLUTE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pp = p + off;
    return 1;
}
static int extract_path_noscheme(char **path, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *path = NULL;
    if (span_segment_nz_nc(p, &off))
        while(span_slash_segment(p, &off))
            ;

    /* Check if the loop stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_PATH_NOSCHEME, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (off > 0 && (*path = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_PATH_NOSCHEME, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pp = p + off;
    return 1;
}
static int extract_path_rootless(char **path, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *path = NULL;
    if (span_segment_nz(p, &off))
        while(span_slash_segment(p, &off))
            ;

    /* Check if the loop stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_PATH_ROOTLESS, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (off > 0 && (*path = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_PATH_ROOTLESS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pp = p + off;
    return 1;
}
static int extract_path_empty(char **path, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *path = NULL;
    if (span_pchars(p, &off)) {
        URIerr(URI_F_EXTRACT_PATH_EMPTY, URI_R_MALFORMED_PATH_IN_URI);
        return 0;
    }
    return 1;
}

/*
 * hier-part     = "//" authority path-abempty
 *               / path-absolute
 *               / path-rootless
 *               / path-empty
 */
static int extract_hierpart(char **authority, char **path, const char **pp)
{
    if (!extract_authority(authority, pp))
        return 0;

    if (*authority != NULL)
        return extract_path_abempty(path, pp);

    if (!extract_path_absolute(path, pp)
        || (*path == NULL && !extract_path_rootless(path, pp))
        || (*path == NULL && !extract_path_empty(path, pp)))
        return 0;
    return 1;
}

/*
 * relative-part = "//" authority path-abempty
 *               / path-absolute
 *               / path-noscheme
 *               / path-empty
 */
static int extract_relativepart(char **authority, char **path, const char **pp)
{
    if (!extract_authority(authority, pp))
        return 0;

    if (*authority != NULL)
        return extract_path_abempty(path, pp);

    if (!extract_path_absolute(path, pp)
        || (*path == NULL && !extract_path_noscheme(path, pp))
        || (*path == NULL && !extract_path_empty(path, pp)))
        return 0;
    return 1;
}

/*
 * query         = *( pchar / "/" / "?" )
 */
static int extract_query(char **query, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *query = NULL;

    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_QUERY, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (p[off] != '?')
        return 1;
    p++;

    while(span_pchars(p, &off) || span_chars(p, &off, 0, "/?"))
        ;

    /* Check if the loop stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_QUERY, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if ((*query = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_QUERY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pp = p + off;
    return 1;
}

/*
 * fragment      = *( pchar / "/" / "?" )
 */
static int extract_fragment(char **fragment, const char **pp)
{
    const char *p = *pp;
    size_t off = 0;

    *fragment = NULL;

    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_FRAGMENT, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (p[off] != '#')
        return 1;
    p++;

    while(span_pchars(p, &off) || span_chars(p, &off, 0, "/?"))
        ;

    /* Check if the loop stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_FRAGMENT, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if ((*fragment = OPENSSL_strndup(p, off)) == NULL) {
        URIerr(URI_F_EXTRACT_FRAGMENT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pp = p + off;
    return 1;
}

/*
 * URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 *
 * URI-reference = URI / relative-ref
 *
 * relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
 */
int OPENSSL_decode_uri(const char *uri, char **scheme, char **authority,
                       char **path, char **query, char **fragment)
{
    const char *p = uri;

    OPENSSL_init_crypto(0, NULL);

    if (extract_scheme(scheme, &p)
        && (*scheme
            ? extract_hierpart(authority, path, &p)
            : extract_relativepart(authority, path, &p))
        && extract_query(query, &p)
        && extract_fragment(fragment, &p)
        && *p == '\0')
        return 1;

    if (*p != '\0') {
        URIerr(URI_F_OPENSSL_DECODE_URI, URI_R_FAILED_TO_DECODE_URI);
        ERR_add_error_data(3, "URI=\"", uri, "\"");
    }

    if (scheme != NULL) {
        OPENSSL_free(*scheme);
        *scheme = NULL;
    }
    if (authority != NULL) {
        OPENSSL_free(*authority);
        *authority = NULL;
    }
    if (path != NULL) {
        OPENSSL_free(*path);
        *path = NULL;
    }
    if (query != NULL) {
        OPENSSL_free(*query);
        *query = NULL;
    }
    if (fragment != NULL) {
        OPENSSL_free(*fragment);
        *fragment = NULL;
    }

    return 0;
}

/* Inline percent decoding */
static ossl_inline int dehex(char c)
{
    return (c >= '0' && c <= '9'
            ? c - '0'
            : (c >= 'A' && c <= 'F'
               ? c - 'A' + 10
               : (c >= 'a' && c <= 'f'
                  ? c - 'a' + 10
                  : -1)));
}

int OPENSSL_percent_decode_inline(char *str)
{
    if (str != NULL) {
        char *p = str, *r = str;

        while (*p != '\0') {
            if (*p == '%') {
                char n1 = dehex(*++p);
                char n2 = dehex(*++p);

                if (n1 == -1 || n2 == -1) {
                    URIerr(URI_F_OPENSSL_PERCENT_DECODE_INLINE,
                           URI_R_INVALID_PERCENT_CODE);
                    return 0;
                }

                if (n1 == 0 && n2 == 0) {
                    URIerr(URI_F_OPENSSL_PERCENT_DECODE_INLINE,
                           URI_R_PERCENT_NUL_UNSUPPORTED);
                    return 0;
                }

                *r = (n1 << 4) | n2;
            } else {
                *r = *p;
            }
            p++;
            r++;
        }

        *r = '\0';
    }

    return 1;
}

static int extract_userinfo(char **user, char **password, const char **pp)
{
    const char *p = *pp;
    size_t off = 0, user_end = 0, password_start = 0;

    if (user != NULL)
        *user = NULL;
    if (password != NULL)
        *password = NULL;

    if (p == NULL)
        return 1;

    if (span_user(p, &off)) {
        user_end = off;
        if (p[off] == ':') {
            password_start = ++off;
            (void)span_password(p, &off);
        }
    }

    /* Check if the spans stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_USERINFO, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if (p[off] == '@') {
        if ((user != NULL && (*user = OPENSSL_strndup(p, user_end)) == NULL)
            || (password != NULL && password_start != 0
                && (*password =
                    OPENSSL_strndup(p + password_start,
                                    off - password_start)) == NULL)) {
            URIerr(URI_F_EXTRACT_USERINFO, ERR_R_MALLOC_FAILURE);
            if (user != NULL)
                OPENSSL_free(*user);
            return 0;
        }
        *pp = p + off + 1;
    }

    return 1;
}

static int extract_hostinfo(char **host, char **service, const char **pp)
{
    const char *p = *pp;
    size_t off = 0, host_end = 0, service_start = 0;

    if (host != NULL)
        *host = NULL;
    if (service != NULL)
        *service = NULL;

    if (p == NULL)
        return 1;

    if (!span_host(p, &off)) {
        URIerr(URI_F_EXTRACT_HOSTINFO, URI_R_MALFORMED_HOST_IN_URI);
        return 0;
    }
    host_end = off;
    if (span_port(p, &off)) {
        service_start = host_end + 1;
    }

    /* Check if the spans stopped because of an invalid character */
    if (!is_valid(p[off])) {
        URIerr(URI_F_EXTRACT_HOSTINFO, URI_R_INVALID_CHARACTER_IN_URI);
        return 0;
    }

    if ((host != NULL && (*host = OPENSSL_strndup(p, host_end)) == NULL)
        || (service != NULL && service_start != 0
            && (*service = OPENSSL_strndup(p + service_start,
                                           off - service_start)) == NULL)) {
        URIerr(URI_F_EXTRACT_HOSTINFO, ERR_R_MALLOC_FAILURE);
        if (host != NULL)
            OPENSSL_free(*host);
        return 0;
    }

    *pp = p + off;
    return 1;
}

int OPENSSL_decode_authority(const char *authority, char **user,
                             char **password, char **host, char **service)
{
    const char *p = authority;

    OPENSSL_init_crypto(0, NULL);

    if (extract_userinfo(user, password, &p)
        && extract_hostinfo(host, service, &p)
        && (p == NULL || *p == '\0'))
        return 1;

    if (*p != '\0') {
        URIerr(URI_F_OPENSSL_DECODE_AUTHORITY, URI_R_FAILED_TO_DECODE_URI);
        ERR_add_error_data(3, "authority=\"", authority, "\"");
    }

    if (user != NULL) {
        OPENSSL_free(*user);
        *user = NULL;
    }
    if (password != NULL) {
        OPENSSL_free(*password);
        *password = NULL;
    }
    if (host != NULL) {
        OPENSSL_free(*host);
        *host = NULL;
    }
    if (service != NULL) {
        OPENSSL_free(*service);
        *service = NULL;
    }

    return 0;
}
