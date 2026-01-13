/*
 * Copyright 2004-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto/ctype.h"
#include "crypto/x509.h"

#include "x509_local.h"

/* X509_VERIFY_PARAM functions */

#define SET_HOST 0
#define ADD_HOST 1

static X509_BUFFER *buffer_from_bytes(const uint8_t *bytes, size_t length)
{
    X509_BUFFER *buf;

    if ((buf = OPENSSL_zalloc(sizeof *buf)) != NULL
        && (buf->data = OPENSSL_memdup(bytes, length)) != NULL)
        buf->len = length;        
    else
        OPENSSL_free(buf);
    return buf;
}

static X509_BUFFER *buffer_from_string(const uint8_t *bytes, size_t length)
{
    X509_BUFFER *buf, *ret = NULL;
    uint8_t *data = NULL;

    if ((buf = OPENSSL_zalloc(sizeof *buf)) == NULL)
        goto err;

    if ((data = (uint8_t *)OPENSSL_strdup((char *)bytes)) == NULL)
        goto err;

    if (strlen((char *)data) != length)
        goto err;

    ret = buf;
    buf = NULL;
    ret->data = data;
    ret->len = length;
    data = NULL;

err:
    free(buf);
    free(data);

    return ret;
}

static X509_BUFFER *buffer_copy(const X509_BUFFER *b)
{
    return buffer_from_bytes(b->data, b->len);
}

static void buffer_free(X509_BUFFER *b)
{
    if (b == NULL)
        return;
    OPENSSL_free((void *)b->data);
    OPENSSL_free(b);
}

static int replace_buffer_stack(STACK_OF(X509_BUFFER) **dest,
    STACK_OF(X509_BUFFER) *const *src)
{
    sk_X509_BUFFER_pop_free(*dest, buffer_free);
    *dest = NULL;
    if (*src != NULL) {
        *dest = sk_X509_BUFFER_deep_copy(*src, buffer_copy, buffer_free);
        if (*dest == NULL)
            return 0;
    }
    return 1;
}

static int buffer_cmp(const X509_BUFFER *const *a, const X509_BUFFER *const *b)
{
    if ((*a)->len < (*b)->len)
        return -1;
    if ((*a)->len > (*b)->len)
        return 1;
    return memcmp((*a)->data, (*b)->data, (*b)->len);
}

static void clear_buffer_stack(STACK_OF(X509_BUFFER) **buffer_stack)
{
    sk_X509_BUFFER_pop_free(*buffer_stack, buffer_free);
    *buffer_stack = NULL;
}

static int add_bytes_to_buffer_stack(STACK_OF(X509_BUFFER) **buffer_stack,
    const uint8_t *name, size_t name_len)
{
    STACK_OF(X509_BUFFER) *tmp_stack = NULL;
    X509_BUFFER *copy = NULL;
    int ret = 0;

    if ((copy = buffer_from_bytes(name, name_len)) == NULL)
        goto err;

    tmp_stack = *buffer_stack;
    if (tmp_stack == NULL && (tmp_stack = sk_X509_BUFFER_new(buffer_cmp)) == NULL)
        goto err;

    if (!sk_X509_BUFFER_push(tmp_stack, copy))
        goto err;

    ret = 1;
    copy = NULL;
    *buffer_stack = tmp_stack;
    tmp_stack = NULL;

err:
    sk_X509_BUFFER_pop_free(tmp_stack, buffer_free);
    buffer_free(copy);

    return ret;
}

static int add_string_to_buffer_stack(STACK_OF(X509_BUFFER) **buffer_stack,
    const uint8_t *name, size_t name_len)
{
    STACK_OF(X509_BUFFER) *tmp_stack = NULL;
    X509_BUFFER *copy = NULL;
    int ret = 0;

    if ((copy = buffer_from_string(name, name_len)) == NULL)
        goto err;

    tmp_stack = *buffer_stack;
    if (tmp_stack == NULL && (tmp_stack = sk_X509_BUFFER_new(buffer_cmp)) == NULL)
        goto err;

    if (!sk_X509_BUFFER_push(tmp_stack, copy))
        goto err;

    ret = 1;
    copy = NULL;
    *buffer_stack = tmp_stack;
    tmp_stack = NULL;

err:
    sk_X509_BUFFER_pop_free(tmp_stack, buffer_free);
    buffer_free(copy);

    return ret;
}

/*
 * Input validation for verification parameter names. As these could
 * potentially come from untrusted input, doing basic input validation
 * makes sense.
 */
static int validate_ip_name(const uint8_t *name, size_t len)
{
    if (name != NULL && (len == 4 || len == 16))
        return 1;
    return 0;
}

static int validate_string_name(const char *name, size_t *name_len)
{
    size_t len = *name_len;

    if (name == NULL || len == 0)
        return 0;

    /* Accept the trailing \0 byte if this is a C string */
    if (name[len - 1] == '\0')
        len--;

    /* Refuse the empty string */
    if (len == 0)
        return 0;

    /* Refuse values with embedded \0 bytes other than at the end */
    if (memchr(name, '\0', len) != NULL)
        return 0;

    return 1;
}

static int is_alnum(int c, int enforce)
{
    if (enforce)
        return ossl_isalnum(c);
    else
        return c != '.' && c != '-';
}

/*
 * XXX charset_enforce allows anything, but this is actually incorrect.
 * We appear to be supporting utf-8 names in the openssl application by
 * passing utf8 values and generating certifiates with utf-8 email addresses
 * in them.
 *
 * This is incorrect, the encoded values in the certificates must be encoded
 * as Punycode - not directly as utf-8, so by the time we are comparing
 * an email address in a vpm to an email address in a certificate we
 * should just be comparing the bytes, but they should be Punycode *NOT*
 * utf-8.
 *
 * I am currently setting charset_enforce to 0 when setting an email address
 * because we have tests that appear to include utf8 in a certificate and are
 * testing for it, which is wrong.
 *
 * what *should* be happening is the Punycode should be in the cert, the "openssl"
 * application should be converting the utf-8 to Punycode, adding it to the vpm
 * as an email address, then the compare is done Punycode to Punycode.
 *
 * I am correctly validating DNS names, which in the cert (and in DNS responses)
 * should always be Punycode.
 */
static int validate_dns_name(const char *name, size_t len, int charset_enforce)
{
    size_t i, part_len;
    char c, prev;

    if (len < 2 || len > 256)
        return 0;

    part_len = 0;
    prev = '\0';
    for (i = 0; i < len; i++) {
        c = name[i];
        if (c == '.') {
            /* Can not start a label with a . */
            if (part_len == 0)
                return 0;
            /* Can not end a label with a _ */
            if (prev == '_')
                return 0;
            part_len = 0;
        } else {
            if (!is_alnum(c, charset_enforce) && c != '-')
                return 0;
            if (c == '-') {
                /* Can not start a label with a _ */
                if (part_len == 0)
                    return 0;
            }
        }
        part_len++;
        if (part_len > 63)
            return 0;

        prev = c;
    }
    /* Can not end with a . or a _ */
    if (prev == '.' || prev == '-')
        return 0;

    return 1;
}

static int validate_email_name(const char *name, size_t len)
{
    size_t dns_len, local_len;
    char *at, *dnsname;

    /* 63 for local part, 1 for @, 255 for domain name, 1 for \0 */
    if (len > 326)
        return 0;

    /* Reject it if there is no @ */
    if ((at = memchr(name, '@', len)) == NULL)
        return 0;

    /* Ensure the local part is not oversize */
    local_len = len - (at - name);
    if (local_len > 63)
        return 0;

    /* We don't do any further validation of the local part */

    /* What is after the @ must valid as a dns name */
    dnsname = at + 1;
    dns_len = len - local_len - 1;

    /*
     * Do not enforce the character set on the other part of
     * an email address for the moment. This is incorrect, but
     * the openssl app appears to have tests for encoding invalid
     * certificates with utf8 values directly in the certificate and
     * checking values which are utf8 directly against that certificate.
     *
     * This is incorrect, as the certificate should have the utf8 values
     * encoded as Punycode, and the application should itself turn the
     * utf8 values into Punycode before setting them in a VPM. But for
     * the moment we keep things the same.
     */
    return validate_dns_name(dnsname, dns_len, /*charset_enforce=*/0);
}

X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void)
{
    X509_VERIFY_PARAM *param;

    param = OPENSSL_zalloc(sizeof(*param));
    if (param == NULL)
        return NULL;
    param->trust = X509_TRUST_DEFAULT;
    /* param->inh_flags = X509_VP_FLAG_DEFAULT; */
    param->depth = -1;
    param->auth_level = -1; /* -1 means unset, 0 is explicit */
    return param;
}

void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param)
{
    if (param == NULL)
        return;
    sk_ASN1_OBJECT_pop_free(param->policies, ASN1_OBJECT_free);
    clear_buffer_stack(&param->hosts);
    clear_buffer_stack(&param->ips);
    clear_buffer_stack(&param->emails);
    OPENSSL_free(param->peername);
    OPENSSL_free(param);
}

/*-
 * This function determines how parameters are "inherited" from one structure
 * to another. There are several different ways this can happen.
 *
 * 1. If a child structure needs to have its values initialized from a parent
 *    they are simply copied across. For example SSL_CTX copied to SSL.
 * 2. If the structure should take on values only if they are currently unset.
 *    For example the values in an SSL structure will take appropriate value
 *    for SSL servers or clients but only if the application has not set new
 *    ones.
 *
 * The "inh_flags" field determines how this function behaves.
 *
 * Normally any values which are set in the default are not copied from the
 * destination and verify flags are ORed together.
 *
 * If X509_VP_FLAG_DEFAULT is set then anything set in the source is copied
 * to the destination. Effectively the values in "to" become default values
 * which will be used only if nothing new is set in "from".
 *
 * If X509_VP_FLAG_OVERWRITE is set then all value are copied across whether
 * they are set or not. Flags is still Ored though.
 *
 * If X509_VP_FLAG_RESET_FLAGS is set then the flags value is copied instead
 * of ORed.
 *
 * If X509_VP_FLAG_LOCKED is set then no values are copied.
 *
 * If X509_VP_FLAG_ONCE is set then the current inh_flags setting is zeroed
 * after the next call.
 */

/* Macro to test if a field should be copied from src to dest */

#define test_x509_verify_param_copy(field, def) \
    (to_overwrite || (src->field != def && (to_default || dest->field == def)))

/* Macro to test and copy a field if necessary */

#define x509_verify_param_copy(field, def)       \
    if (test_x509_verify_param_copy(field, def)) \
        dest->field = src->field;

int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *dest,
    const X509_VERIFY_PARAM *src)
{
    unsigned long inh_flags;
    int to_default, to_overwrite;

    if (src == NULL)
        return 1;
    inh_flags = dest->inh_flags | src->inh_flags;

    if ((inh_flags & X509_VP_FLAG_ONCE) != 0)
        dest->inh_flags = 0;

    if ((inh_flags & X509_VP_FLAG_LOCKED) != 0)
        return 1;

    to_default = (inh_flags & X509_VP_FLAG_DEFAULT) != 0;
    to_overwrite = (inh_flags & X509_VP_FLAG_OVERWRITE) != 0;

    x509_verify_param_copy(purpose, 0);
    x509_verify_param_copy(trust, X509_TRUST_DEFAULT);
    x509_verify_param_copy(depth, -1);
    x509_verify_param_copy(auth_level, -1);

    /* If overwrite or check time not set, copy across */

    if (to_overwrite || (dest->flags & X509_V_FLAG_USE_CHECK_TIME) == 0) {
        dest->check_time = src->check_time;
        dest->flags &= ~X509_V_FLAG_USE_CHECK_TIME;
        /* Don't need to copy flag: that is done below */
    }

    if ((inh_flags & X509_VP_FLAG_RESET_FLAGS) != 0)
        dest->flags = 0;

    dest->flags |= src->flags;

    if (test_x509_verify_param_copy(policies, NULL)) {
        if (!X509_VERIFY_PARAM_set1_policies(dest, src->policies))
            return 0;
    }

    x509_verify_param_copy(hostflags, 0);

    if (test_x509_verify_param_copy(hosts, NULL)) {
        if (!replace_buffer_stack(&dest->hosts, &src->hosts))
            return 0;
    }

    if (test_x509_verify_param_copy(ips, NULL)) {
        if (!replace_buffer_stack(&dest->ips, &src->ips))
            return 0;
    }

    if (test_x509_verify_param_copy(emails, NULL)) {
        if (!replace_buffer_stack(&dest->emails, &src->emails))
            return 0;
    }

    return 1;
}

int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,
    const X509_VERIFY_PARAM *from)
{
    unsigned long save_flags;
    int ret;

    if (to == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    save_flags = to->inh_flags;
    to->inh_flags |= X509_VP_FLAG_DEFAULT;
    ret = X509_VERIFY_PARAM_inherit(to, from);
    to->inh_flags = save_flags;
    return ret;
}

int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name)
{
    OPENSSL_free(param->name);
    param->name = OPENSSL_strdup(name);
    return param->name != NULL;
}

int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags)
{
    param->flags |= flags;
    if ((flags & X509_V_FLAG_POLICY_MASK) != 0)
        param->flags |= X509_V_FLAG_POLICY_CHECK;
    return 1;
}

int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,
    unsigned long flags)
{
    param->flags &= ~flags;
    return 1;
}

unsigned long X509_VERIFY_PARAM_get_flags(const X509_VERIFY_PARAM *param)
{
    return param->flags;
}

uint32_t X509_VERIFY_PARAM_get_inh_flags(const X509_VERIFY_PARAM *param)
{
    return param->inh_flags;
}

int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM *param, uint32_t flags)
{
    param->inh_flags = flags;
    return 1;
}

/* resets to default (any) purpose if |purpose| == X509_PURPOSE_DEFAULT_ANY */
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose)
{
    return X509_PURPOSE_set(&param->purpose, purpose);
}

int X509_VERIFY_PARAM_get_purpose(const X509_VERIFY_PARAM *param)
{
    return param->purpose;
}

int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust)
{
    return X509_TRUST_set(&param->trust, trust);
}

void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth)
{
    param->depth = depth;
}

void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM *param, int auth_level)
{
    param->auth_level = auth_level;
}

time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM *param)
{
    /* This will be in the time_t range, because the only setter uses time_t */
    return (time_t)param->check_time;
}

void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t)
{
    param->check_time = (int64_t)t;
    param->flags |= X509_V_FLAG_USE_CHECK_TIME;
}

void ossl_x509_verify_param_set_time_posix(X509_VERIFY_PARAM *param, int64_t t)
{
    param->check_time = t;
    param->flags |= X509_V_FLAG_USE_CHECK_TIME;
}

int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param,
    ASN1_OBJECT *policy)
{
    if (param->policies == NULL) {
        param->policies = sk_ASN1_OBJECT_new_null();
        if (param->policies == NULL)
            return 0;
    }

    if (sk_ASN1_OBJECT_push(param->policies, policy) <= 0)
        return 0;
    return 1;
}

int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
    STACK_OF(ASN1_OBJECT) *policies)
{
    int i;
    ASN1_OBJECT *oid, *doid;

    if (param == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    sk_ASN1_OBJECT_pop_free(param->policies, ASN1_OBJECT_free);

    if (policies == NULL) {
        param->policies = NULL;
        return 1;
    }

    param->policies = sk_ASN1_OBJECT_new_null();
    if (param->policies == NULL)
        return 0;

    for (i = 0; i < sk_ASN1_OBJECT_num(policies); i++) {
        oid = sk_ASN1_OBJECT_value(policies, i);
        doid = OBJ_dup(oid);
        if (doid == NULL)
            return 0;
        if (!sk_ASN1_OBJECT_push(param->policies, doid)) {
            ASN1_OBJECT_free(doid);
            return 0;
        }
    }
    param->flags |= X509_V_FLAG_POLICY_CHECK;
    return 1;
}

char *X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM *param, int idx)
{
    X509_BUFFER *buf = sk_X509_BUFFER_value(param->hosts, idx);

    return (buf != NULL) ? (char *)buf->data : NULL;
}

int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param,
    const char *dnsname, size_t len)
{
    clear_buffer_stack(&param->hosts);
    if (dnsname == NULL)
        return 1;
    if (len == 0)
        len = strlen(dnsname);
    if (len == 0)
        return 1;
    if (dnsname == NULL && len == 0)
        return 1;
    return X509_VERIFY_PARAM_add1_host(param, dnsname, len);
}

int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param,
    const char *dnsname, size_t len)
{
    if (dnsname == NULL)
        return 1;
    if (len == 0)
        len = strlen(dnsname);
    if (len == 0)
        return 1;
    if (!validate_string_name(dnsname, &len))
        return 0;
    if (!validate_dns_name(dnsname, len, /*charset_enforce=*/1))
        return 0;
    return add_string_to_buffer_stack(&param->hosts, (const uint8_t *)dnsname, len);
}

int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param,
    const uint8_t *ip, size_t len)
{
    clear_buffer_stack(&param->ips);
    if (ip == NULL)
        return 1;
    return X509_VERIFY_PARAM_add1_ip(param, ip, len);
}

int X509_VERIFY_PARAM_add1_ip(X509_VERIFY_PARAM *param,
    const uint8_t *ip, size_t len)
{
    if (!validate_ip_name(ip, len))
        return 0;
    return add_bytes_to_buffer_stack(&param->ips, ip, len);
}

char *X509_VERIFY_PARAM_get0_email(X509_VERIFY_PARAM *param)
{
    X509_BUFFER *buf = sk_X509_BUFFER_value(param->emails, 0);

    return (buf != NULL) ? (char *)buf->data : NULL;
}

int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param,
    const char *email, size_t len)
{
    clear_buffer_stack(&param->emails);
    if (email == NULL)
        return 1;
    return X509_VERIFY_PARAM_add1_email(param, email, len);
}

int X509_VERIFY_PARAM_add1_email(X509_VERIFY_PARAM *param,
    const char *email, size_t len)
{
    if (len == 0)
        len = strlen(email);
    if (!validate_string_name(email, &len))
        return 0;
    if (!validate_email_name(email, len))
        return 0;
    int ret = add_string_to_buffer_stack(&param->emails, (const uint8_t *)email, len);
    return ret;
}

void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param,
    unsigned int flags)
{
    param->hostflags = flags;
}

unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param)
{
    return param->hostflags;
}

char *X509_VERIFY_PARAM_get0_peername(const X509_VERIFY_PARAM *param)
{
    return param->peername;
}

/*
 * Move peername from one param structure to another, freeing any name present
 * at the target.  If the source is a NULL parameter structure, free and zero
 * the target peername.
 */
void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM *to,
    X509_VERIFY_PARAM *from)
{
    char *peername = (from != NULL) ? from->peername : NULL;

    if (to->peername != peername) {
        OPENSSL_free(to->peername);
        to->peername = peername;
    }
    if (from != NULL)
        from->peername = NULL;
}

static const unsigned char *int_X509_VERIFY_PARAM_get0_ip(X509_VERIFY_PARAM *param, size_t *plen, size_t idx)
{
    if (param == NULL || param->ips == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    X509_BUFFER *buf = sk_X509_BUFFER_value(param->ips, idx);

    if (buf != NULL) {
        if (plen != NULL)
            *plen = buf->len;
        return (unsigned char *)buf->data;
    }
    return NULL;
}

char *X509_VERIFY_PARAM_get1_ip_asc(X509_VERIFY_PARAM *param)
{
    size_t iplen;
    /* XXX casts away const */
    unsigned char *ip = (unsigned char *)int_X509_VERIFY_PARAM_get0_ip(param, &iplen, 0);

    return ip == NULL ? NULL : ossl_ipaddr_to_asc(ip, (int)iplen);
}

int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *param, const char *ipasc)
{
    unsigned char ipout[16];
    size_t iplen;

    if (ipasc == NULL)
        return X509_VERIFY_PARAM_set1_ip(param, NULL, 0);
    if ((iplen = (size_t)ossl_a2i_ipadd(ipout, ipasc)) == 0)
        return 0;
    return X509_VERIFY_PARAM_set1_ip(param, ipout, iplen);
}

int X509_VERIFY_PARAM_add1_ip_asc(X509_VERIFY_PARAM *param, const char *ipasc)
{
    unsigned char ipout[16];
    size_t iplen;

    if ((iplen = (size_t)ossl_a2i_ipadd(ipout, ipasc)) == 0)
        return 0;
    return X509_VERIFY_PARAM_add1_ip(param, ipout, iplen);
}

int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param)
{
    return param->depth;
}

int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param)
{
    return param->auth_level;
}

const char *X509_VERIFY_PARAM_get0_name(const X509_VERIFY_PARAM *param)
{
    return param->name;
}

/*
 * Default verify parameters: these are used for various applications and can
 * be overridden by the user specified table. NB: the 'name' field *must* be
 * in alphabetical order because it will be searched using OBJ_search.
 */

static const X509_VERIFY_PARAM default_table[] = {
    {
        .name = "code_sign", /* Code sign parameters */
        .purpose = X509_PURPOSE_CODE_SIGN,
        .trust = X509_TRUST_OBJECT_SIGN,
        .depth = -1,
        .auth_level = -1,
    },
    {
        .name = "default", /* X509 default parameters */
        .flags = X509_V_FLAG_TRUSTED_FIRST,
        .depth = 100,
        .auth_level = -1,
    },
    {
        .name = "pkcs7", /* S/MIME sign parameters */
        .purpose = X509_PURPOSE_SMIME_SIGN,
        .trust = X509_TRUST_EMAIL,
        .depth = -1,
        .auth_level = -1,
    },
    {
        .name = "smime_sign", /* S/MIME sign parameters */
        .purpose = X509_PURPOSE_SMIME_SIGN,
        .trust = X509_TRUST_EMAIL,
        .depth = -1,
        .auth_level = -1,
    },
    {
        .name = "ssl_client", /* SSL/TLS client parameters */
        .purpose = X509_PURPOSE_SSL_CLIENT,
        .trust = X509_TRUST_SSL_CLIENT,
        .depth = -1,
        .auth_level = -1,
    },
    {
        .name = "ssl_server", /* SSL/TLS server parameters */
        .purpose = X509_PURPOSE_SSL_SERVER,
        .trust = X509_TRUST_SSL_SERVER,
        .depth = -1,
        .auth_level = -1,
    }
};

static STACK_OF(X509_VERIFY_PARAM) *param_table = NULL;

static int table_cmp(const X509_VERIFY_PARAM *a, const X509_VERIFY_PARAM *b)
{
    return strcmp(a->name, b->name);
}

DECLARE_OBJ_BSEARCH_CMP_FN(X509_VERIFY_PARAM, X509_VERIFY_PARAM, table);
IMPLEMENT_OBJ_BSEARCH_CMP_FN(X509_VERIFY_PARAM, X509_VERIFY_PARAM, table);

static int param_cmp(const X509_VERIFY_PARAM *const *a,
    const X509_VERIFY_PARAM *const *b)
{
    return strcmp((*a)->name, (*b)->name);
}

int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param)
{
    int idx;
    X509_VERIFY_PARAM *ptmp;

    if (param_table == NULL) {
        param_table = sk_X509_VERIFY_PARAM_new(param_cmp);
        if (param_table == NULL)
            return 0;
    } else {
        idx = sk_X509_VERIFY_PARAM_find(param_table, param);
        if (idx >= 0) {
            ptmp = sk_X509_VERIFY_PARAM_delete(param_table, idx);
            X509_VERIFY_PARAM_free(ptmp);
        }
    }

    if (sk_X509_VERIFY_PARAM_push(param_table, param) <= 0)
        return 0;
    return 1;
}

int X509_VERIFY_PARAM_get_count(void)
{
    int num = OSSL_NELEM(default_table);

    if (param_table != NULL)
        num += sk_X509_VERIFY_PARAM_num(param_table);
    return num;
}

const X509_VERIFY_PARAM *X509_VERIFY_PARAM_get0(int id)
{
    int num = OSSL_NELEM(default_table);

    if (id < 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (id < num)
        return default_table + id;
    return sk_X509_VERIFY_PARAM_value(param_table, id - num);
}

const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name)
{
    int idx;
    X509_VERIFY_PARAM pm;

    pm.name = (char *)name;
    if (param_table != NULL) {
        /* Ideally, this would be done under a lock */
        sk_X509_VERIFY_PARAM_sort(param_table);
        idx = sk_X509_VERIFY_PARAM_find(param_table, &pm);
        if (idx >= 0)
            return sk_X509_VERIFY_PARAM_value(param_table, idx);
    }
    return OBJ_bsearch_table(&pm, default_table, OSSL_NELEM(default_table));
}

void X509_VERIFY_PARAM_table_cleanup(void)
{
    sk_X509_VERIFY_PARAM_pop_free(param_table, X509_VERIFY_PARAM_free);
    param_table = NULL;
}
