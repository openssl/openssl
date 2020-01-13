/*
 * Copyright 2012-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "tls_local.h"
#include <opentls/conf.h>
#include <opentls/objects.h>
#include <opentls/dh.h>
#include "internal/nelem.h"

/*
 * structure holding name tables. This is used for permitted elements in lists
 * such as TLSv1.
 */

typedef struct {
    const char *name;
    int namelen;
    unsigned int name_flags;
    unsigned long option_value;
} tls_flag_tbl;

/* Switch table: use for single command line switches like no_tls2 */
typedef struct {
    unsigned long option_value;
    unsigned int name_flags;
} tls_switch_tbl;

/* Sense of name is inverted e.g. "TLSv1" will clear tls_OP_NO_TLSv1 */
#define tls_TFLAG_INV   0x1
/* Mask for type of flag referred to */
#define tls_TFLAG_TYPE_MASK 0xf00
/* Flag is for options */
#define tls_TFLAG_OPTION    0x000
/* Flag is for cert_flags */
#define tls_TFLAG_CERT      0x100
/* Flag is for verify mode */
#define tls_TFLAG_VFY       0x200
/* Option can only be used for clients */
#define tls_TFLAG_CLIENT tls_CONF_FLAG_CLIENT
/* Option can only be used for servers */
#define tls_TFLAG_SERVER tls_CONF_FLAG_SERVER
#define tls_TFLAG_BOTH (tls_TFLAG_CLIENT|tls_TFLAG_SERVER)

#define tls_FLAG_TBL(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_BOTH, flag}
#define tls_FLAG_TBL_SRV(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_SERVER, flag}
#define tls_FLAG_TBL_CLI(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_CLIENT, flag}
#define tls_FLAG_TBL_INV(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_INV|tls_TFLAG_BOTH, flag}
#define tls_FLAG_TBL_SRV_INV(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_INV|tls_TFLAG_SERVER, flag}
#define tls_FLAG_TBL_CERT(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_CERT|tls_TFLAG_BOTH, flag}

#define tls_FLAG_VFY_CLI(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_VFY | tls_TFLAG_CLIENT, flag}
#define tls_FLAG_VFY_SRV(str, flag) \
        {str, (int)(sizeof(str) - 1), tls_TFLAG_VFY | tls_TFLAG_SERVER, flag}

/*
 * Opaque structure containing tls configuration context.
 */

struct tls_conf_ctx_st {
    /*
     * Various flags indicating (among other things) which options we will
     * recognise.
     */
    unsigned int flags;
    /* Prefix and length of commands */
    char *prefix;
    size_t prefixlen;
    /* tls_CTX or tls structure to perform operations on */
    tls_CTX *ctx;
    tls *tls;
    /* Pointer to tls or tls_CTX options field or NULL if none */
    uint32_t *poptions;
    /* Certificate filenames for each type */
    char *cert_filename[tls_PKEY_NUM];
    /* Pointer to tls or tls_CTX cert_flags or NULL if none */
    uint32_t *pcert_flags;
    /* Pointer to tls or tls_CTX verify_mode or NULL if none */
    uint32_t *pvfy_flags;
    /* Pointer to tls or tls_CTX min_version field or NULL if none */
    int *min_version;
    /* Pointer to tls or tls_CTX max_version field or NULL if none */
    int *max_version;
    /* Current flag table being worked on */
    const tls_flag_tbl *tbl;
    /* Size of table */
    size_t ntbl;
    /* Client CA names */
    STACK_OF(X509_NAME) *canames;
};

static void tls_set_option(tls_CONF_CTX *cctx, unsigned int name_flags,
                           unsigned long option_value, int onoff)
{
    uint32_t *pflags;
    if (cctx->poptions == NULL)
        return;
    if (name_flags & tls_TFLAG_INV)
        onoff ^= 1;
    switch (name_flags & tls_TFLAG_TYPE_MASK) {

    case tls_TFLAG_CERT:
        pflags = cctx->pcert_flags;
        break;

    case tls_TFLAG_VFY:
        pflags = cctx->pvfy_flags;
        break;

    case tls_TFLAG_OPTION:
        pflags = cctx->poptions;
        break;

    default:
        return;

    }
    if (onoff)
        *pflags |= option_value;
    else
        *pflags &= ~option_value;
}

static int tls_match_option(tls_CONF_CTX *cctx, const tls_flag_tbl *tbl,
                            const char *name, int namelen, int onoff)
{
    /* If name not relevant for context skip */
    if (!(cctx->flags & tbl->name_flags & tls_TFLAG_BOTH))
        return 0;
    if (namelen == -1) {
        if (strcmp(tbl->name, name))
            return 0;
    } else if (tbl->namelen != namelen || strncasecmp(tbl->name, name, namelen))
        return 0;
    tls_set_option(cctx, tbl->name_flags, tbl->option_value, onoff);
    return 1;
}

static int tls_set_option_list(const char *elem, int len, void *usr)
{
    tls_CONF_CTX *cctx = usr;
    size_t i;
    const tls_flag_tbl *tbl;
    int onoff = 1;
    /*
     * len == -1 indicates not being called in list context, just for single
     * command line switches, so don't allow +, -.
     */
    if (elem == NULL)
        return 0;
    if (len != -1) {
        if (*elem == '+') {
            elem++;
            len--;
            onoff = 1;
        } else if (*elem == '-') {
            elem++;
            len--;
            onoff = 0;
        }
    }
    for (i = 0, tbl = cctx->tbl; i < cctx->ntbl; i++, tbl++) {
        if (tls_match_option(cctx, tbl, elem, len, onoff))
            return 1;
    }
    return 0;
}

/* Set supported signature algorithms */
static int cmd_SignatureAlgorithms(tls_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->tls)
        rv = tls_set1_sigalgs_list(cctx->tls, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = tls_CTX_set1_sigalgs_list(cctx->ctx, value);
    return rv > 0;
}

/* Set supported client signature algorithms */
static int cmd_ClientSignatureAlgorithms(tls_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->tls)
        rv = tls_set1_client_sigalgs_list(cctx->tls, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = tls_CTX_set1_client_sigalgs_list(cctx->ctx, value);
    return rv > 0;
}

static int cmd_Groups(tls_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->tls)
        rv = tls_set1_groups_list(cctx->tls, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = tls_CTX_set1_groups_list(cctx->ctx, value);
    return rv > 0;
}

/* This is the old name for cmd_Groups - retained for backwards compatibility */
static int cmd_Curves(tls_CONF_CTX *cctx, const char *value)
{
    return cmd_Groups(cctx, value);
}

#ifndef OPENtls_NO_EC
/* ECDH temporary parameters */
static int cmd_ECDHParameters(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    int nid;

    /* Ignore values supported by 1.0.2 for the automatic selection */
    if ((cctx->flags & tls_CONF_FLAG_FILE)
            && (strcasecmp(value, "+automatic") == 0
                || strcasecmp(value, "automatic") == 0))
        return 1;
    if ((cctx->flags & tls_CONF_FLAG_CMDLINE) &&
        strcmp(value, "auto") == 0)
        return 1;

    nid = EC_curve_nist2nid(value);
    if (nid == NID_undef)
        nid = OBJ_sn2nid(value);
    if (nid == 0)
        return 0;

    if (cctx->ctx)
        rv = tls_CTX_set1_groups(cctx->ctx, &nid, 1);
    else if (cctx->tls)
        rv = tls_set1_groups(cctx->tls, &nid, 1);

    return rv > 0;
}
#endif
static int cmd_CipherString(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 1;

    if (cctx->ctx)
        rv = tls_CTX_set_cipher_list(cctx->ctx, value);
    if (cctx->tls)
        rv = tls_set_cipher_list(cctx->tls, value);
    return rv > 0;
}

static int cmd_Ciphersuites(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 1;

    if (cctx->ctx)
        rv = tls_CTX_set_ciphersuites(cctx->ctx, value);
    if (cctx->tls)
        rv = tls_set_ciphersuites(cctx->tls, value);
    return rv > 0;
}

static int cmd_Protocol(tls_CONF_CTX *cctx, const char *value)
{
    static const tls_flag_tbl tls_protocol_list[] = {
        tls_FLAG_TBL_INV("ALL", tls_OP_NO_tls_MASK),
        tls_FLAG_TBL_INV("tlsv2", tls_OP_NO_tlsv2),
        tls_FLAG_TBL_INV("tlsv3", tls_OP_NO_tlsv3),
        tls_FLAG_TBL_INV("TLSv1", tls_OP_NO_TLSv1),
        tls_FLAG_TBL_INV("TLSv1.1", tls_OP_NO_TLSv1_1),
        tls_FLAG_TBL_INV("TLSv1.2", tls_OP_NO_TLSv1_2),
        tls_FLAG_TBL_INV("TLSv1.3", tls_OP_NO_TLSv1_3),
        tls_FLAG_TBL_INV("DTLSv1", tls_OP_NO_DTLSv1),
        tls_FLAG_TBL_INV("DTLSv1.2", tls_OP_NO_DTLSv1_2)
    };
    cctx->tbl = tls_protocol_list;
    cctx->ntbl = Otls_NELEM(tls_protocol_list);
    return CONF_parse_list(value, ',', 1, tls_set_option_list, cctx);
}

/*
 * protocol_from_string - converts a protocol version string to a number
 *
 * Returns -1 on failure or the version on success
 */
static int protocol_from_string(const char *value)
{
    struct protocol_versions {
        const char *name;
        int version;
    };
    static const struct protocol_versions versions[] = {
        {"None", 0},
        {"tlsv3", tls3_VERSION},
        {"TLSv1", TLS1_VERSION},
        {"TLSv1.1", TLS1_1_VERSION},
        {"TLSv1.2", TLS1_2_VERSION},
        {"TLSv1.3", TLS1_3_VERSION},
        {"DTLSv1", DTLS1_VERSION},
        {"DTLSv1.2", DTLS1_2_VERSION}
    };
    size_t i;
    size_t n = Otls_NELEM(versions);

    for (i = 0; i < n; i++)
        if (strcmp(versions[i].name, value) == 0)
            return versions[i].version;
    return -1;
}

static int min_max_proto(tls_CONF_CTX *cctx, const char *value, int *bound)
{
    int method_version;
    int new_version;

    if (cctx->ctx != NULL)
        method_version = cctx->ctx->method->version;
    else if (cctx->tls != NULL)
        method_version = cctx->tls->ctx->method->version;
    else
        return 0;
    if ((new_version = protocol_from_string(value)) < 0)
        return 0;
    return tls_set_version_bound(method_version, new_version, bound);
}

/*
 * cmd_MinProtocol - Set min protocol version
 * @cctx: config structure to save settings in
 * @value: The min protocol version in string form
 *
 * Returns 1 on success and 0 on failure.
 */
static int cmd_MinProtocol(tls_CONF_CTX *cctx, const char *value)
{
    return min_max_proto(cctx, value, cctx->min_version);
}

/*
 * cmd_MaxProtocol - Set max protocol version
 * @cctx: config structure to save settings in
 * @value: The max protocol version in string form
 *
 * Returns 1 on success and 0 on failure.
 */
static int cmd_MaxProtocol(tls_CONF_CTX *cctx, const char *value)
{
    return min_max_proto(cctx, value, cctx->max_version);
}

static int cmd_Options(tls_CONF_CTX *cctx, const char *value)
{
    static const tls_flag_tbl tls_option_list[] = {
        tls_FLAG_TBL_INV("SessionTicket", tls_OP_NO_TICKET),
        tls_FLAG_TBL_INV("EmptyFragments",
                         tls_OP_DONT_INSERT_EMPTY_FRAGMENTS),
        tls_FLAG_TBL("Bugs", tls_OP_ALL),
        tls_FLAG_TBL_INV("Compression", tls_OP_NO_COMPRESSION),
        tls_FLAG_TBL_SRV("ServerPreference", tls_OP_CIPHER_SERVER_PREFERENCE),
        tls_FLAG_TBL_SRV("NoResumptionOnRenegotiation",
                         tls_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION),
        tls_FLAG_TBL_SRV("DHSingle", tls_OP_SINGLE_DH_USE),
        tls_FLAG_TBL_SRV("ECDHSingle", tls_OP_SINGLE_ECDH_USE),
        tls_FLAG_TBL("UnsafeLegacyRenegotiation",
                     tls_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION),
        tls_FLAG_TBL_INV("EncryptThenMac", tls_OP_NO_ENCRYPT_THEN_MAC),
        tls_FLAG_TBL("NoRenegotiation", tls_OP_NO_RENEGOTIATION),
        tls_FLAG_TBL("AllowNoDHEKEX", tls_OP_ALLOW_NO_DHE_KEX),
        tls_FLAG_TBL("PrioritizeChaCha", tls_OP_PRIORITIZE_CHACHA),
        tls_FLAG_TBL("MiddleboxCompat", tls_OP_ENABLE_MIDDLEBOX_COMPAT),
        tls_FLAG_TBL_INV("AntiReplay", tls_OP_NO_ANTI_REPLAY),
        tls_FLAG_TBL_INV("ExtendedMasterSecret", tls_OP_NO_EXTENDED_MASTER_SECRET)
    };
    if (value == NULL)
        return -3;
    cctx->tbl = tls_option_list;
    cctx->ntbl = Otls_NELEM(tls_option_list);
    return CONF_parse_list(value, ',', 1, tls_set_option_list, cctx);
}

static int cmd_VerifyMode(tls_CONF_CTX *cctx, const char *value)
{
    static const tls_flag_tbl tls_vfy_list[] = {
        tls_FLAG_VFY_CLI("Peer", tls_VERIFY_PEER),
        tls_FLAG_VFY_SRV("Request", tls_VERIFY_PEER),
        tls_FLAG_VFY_SRV("Require",
                         tls_VERIFY_PEER | tls_VERIFY_FAIL_IF_NO_PEER_CERT),
        tls_FLAG_VFY_SRV("Once", tls_VERIFY_PEER | tls_VERIFY_CLIENT_ONCE),
        tls_FLAG_VFY_SRV("RequestPostHandshake",
                         tls_VERIFY_PEER | tls_VERIFY_POST_HANDSHAKE),
        tls_FLAG_VFY_SRV("RequirePostHandshake",
                         tls_VERIFY_PEER | tls_VERIFY_POST_HANDSHAKE |
                         tls_VERIFY_FAIL_IF_NO_PEER_CERT),
    };
    if (value == NULL)
        return -3;
    cctx->tbl = tls_vfy_list;
    cctx->ntbl = Otls_NELEM(tls_vfy_list);
    return CONF_parse_list(value, ',', 1, tls_set_option_list, cctx);
}

static int cmd_Certificate(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    CERT *c = NULL;
    if (cctx->ctx) {
        rv = tls_CTX_use_certificate_chain_file(cctx->ctx, value);
        c = cctx->ctx->cert;
    }
    if (cctx->tls) {
        rv = tls_use_certificate_chain_file(cctx->tls, value);
        c = cctx->tls->cert;
    }
    if (rv > 0 && c && cctx->flags & tls_CONF_FLAG_REQUIRE_PRIVATE) {
        char **pfilename = &cctx->cert_filename[c->key - c->pkeys];
        OPENtls_free(*pfilename);
        *pfilename = OPENtls_strdup(value);
        if (*pfilename == NULL)
            rv = 0;
    }

    return rv > 0;
}

static int cmd_PrivateKey(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (!(cctx->flags & tls_CONF_FLAG_CERTIFICATE))
        return -2;
    if (cctx->ctx)
        rv = tls_CTX_use_PrivateKey_file(cctx->ctx, value, tls_FILETYPE_PEM);
    if (cctx->tls)
        rv = tls_use_PrivateKey_file(cctx->tls, value, tls_FILETYPE_PEM);
    return rv > 0;
}

static int cmd_ServerInfoFile(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (cctx->ctx)
        rv = tls_CTX_use_serverinfo_file(cctx->ctx, value);
    return rv > 0;
}

static int do_store(tls_CONF_CTX *cctx,
                    const char *CAfile, const char *CApath, const char *CAstore,
                    int verify_store)
{
    CERT *cert;
    X509_STORE **st;

    if (cctx->ctx)
        cert = cctx->ctx->cert;
    else if (cctx->tls)
        cert = cctx->tls->cert;
    else
        return 1;
    st = verify_store ? &cert->verify_store : &cert->chain_store;
    if (*st == NULL) {
        *st = X509_STORE_new();
        if (*st == NULL)
            return 0;
    }

    if (CAfile != NULL && !X509_STORE_load_file(*st, CAfile))
        return 0;
    if (CApath != NULL && !X509_STORE_load_path(*st, CApath))
        return 0;
    if (CAstore != NULL && !X509_STORE_load_store(*st, CAstore))
        return 0;
    return 1;
}

static int cmd_ChainCAPath(tls_CONF_CTX *cctx, const char *value)
{
    return do_store(cctx, NULL, value, NULL, 0);
}

static int cmd_ChainCAFile(tls_CONF_CTX *cctx, const char *value)
{
    return do_store(cctx, value, NULL, NULL, 0);
}

static int cmd_ChainCAStore(tls_CONF_CTX *cctx, const char *value)
{
    return do_store(cctx, NULL, NULL, value, 0);
}

static int cmd_VerifyCAPath(tls_CONF_CTX *cctx, const char *value)
{
    return do_store(cctx, NULL, value, NULL, 1);
}

static int cmd_VerifyCAFile(tls_CONF_CTX *cctx, const char *value)
{
    return do_store(cctx, value, NULL, NULL, 1);
}

static int cmd_VerifyCAStore(tls_CONF_CTX *cctx, const char *value)
{
    return do_store(cctx, NULL, NULL, value, 1);
}

static int cmd_RequestCAFile(tls_CONF_CTX *cctx, const char *value)
{
    if (cctx->canames == NULL)
        cctx->canames = sk_X509_NAME_new_null();
    if (cctx->canames == NULL)
        return 0;
    return tls_add_file_cert_subjects_to_stack(cctx->canames, value);
}

static int cmd_ClientCAFile(tls_CONF_CTX *cctx, const char *value)
{
    return cmd_RequestCAFile(cctx, value);
}

static int cmd_RequestCAPath(tls_CONF_CTX *cctx, const char *value)
{
    if (cctx->canames == NULL)
        cctx->canames = sk_X509_NAME_new_null();
    if (cctx->canames == NULL)
        return 0;
    return tls_add_dir_cert_subjects_to_stack(cctx->canames, value);
}

static int cmd_ClientCAPath(tls_CONF_CTX *cctx, const char *value)
{
    return cmd_RequestCAPath(cctx, value);
}

static int cmd_RequestCAStore(tls_CONF_CTX *cctx, const char *value)
{
    if (cctx->canames == NULL)
        cctx->canames = sk_X509_NAME_new_null();
    if (cctx->canames == NULL)
        return 0;
    return tls_add_store_cert_subjects_to_stack(cctx->canames, value);
}

static int cmd_ClientCAStore(tls_CONF_CTX *cctx, const char *value)
{
    return cmd_RequestCAStore(cctx, value);
}

#ifndef OPENtls_NO_DH
static int cmd_DHParameters(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 0;
    DH *dh = NULL;
    BIO *in = NULL;
    if (cctx->ctx || cctx->tls) {
        in = BIO_new(BIO_s_file());
        if (in == NULL)
            goto end;
        if (BIO_read_filename(in, value) <= 0)
            goto end;
        dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
        if (dh == NULL)
            goto end;
    } else
        return 1;
    if (cctx->ctx)
        rv = tls_CTX_set_tmp_dh(cctx->ctx, dh);
    if (cctx->tls)
        rv = tls_set_tmp_dh(cctx->tls, dh);
 end:
    DH_free(dh);
    BIO_free(in);
    return rv > 0;
}
#endif

static int cmd_RecordPadding(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 0;
    int block_size = atoi(value);

    /*
     * All we care about is a non-negative value,
     * the setters check the range
     */
    if (block_size >= 0) {
        if (cctx->ctx)
            rv = tls_CTX_set_block_padding(cctx->ctx, block_size);
        if (cctx->tls)
            rv = tls_set_block_padding(cctx->tls, block_size);
    }
    return rv;
}


static int cmd_NumTickets(tls_CONF_CTX *cctx, const char *value)
{
    int rv = 0;
    int num_tickets = atoi(value);

    if (num_tickets >= 0) {
        if (cctx->ctx)
            rv = tls_CTX_set_num_tickets(cctx->ctx, num_tickets);
        if (cctx->tls)
            rv = tls_set_num_tickets(cctx->tls, num_tickets);
    }
    return rv;
}

typedef struct {
    int (*cmd) (tls_CONF_CTX *cctx, const char *value);
    const char *str_file;
    const char *str_cmdline;
    unsigned short flags;
    unsigned short value_type;
} tls_conf_cmd_tbl;

/* Table of supported parameters */

#define tls_CONF_CMD(name, cmdopt, flags, type) \
        {cmd_##name, #name, cmdopt, flags, type}

#define tls_CONF_CMD_STRING(name, cmdopt, flags) \
        tls_CONF_CMD(name, cmdopt, flags, tls_CONF_TYPE_STRING)

#define tls_CONF_CMD_SWITCH(name, flags) \
        {0, NULL, name, flags, tls_CONF_TYPE_NONE}

/* See apps/apps.h if you change this table. */
static const tls_conf_cmd_tbl tls_conf_cmds[] = {
    tls_CONF_CMD_SWITCH("no_tls3", 0),
    tls_CONF_CMD_SWITCH("no_tls1", 0),
    tls_CONF_CMD_SWITCH("no_tls1_1", 0),
    tls_CONF_CMD_SWITCH("no_tls1_2", 0),
    tls_CONF_CMD_SWITCH("no_tls1_3", 0),
    tls_CONF_CMD_SWITCH("bugs", 0),
    tls_CONF_CMD_SWITCH("no_comp", 0),
    tls_CONF_CMD_SWITCH("comp", 0),
    tls_CONF_CMD_SWITCH("ecdh_single", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_SWITCH("no_ticket", 0),
    tls_CONF_CMD_SWITCH("serverpref", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_SWITCH("legacy_renegotiation", 0),
    tls_CONF_CMD_SWITCH("legacy_server_connect", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_SWITCH("no_renegotiation", 0),
    tls_CONF_CMD_SWITCH("no_resumption_on_reneg", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_SWITCH("no_legacy_server_connect", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_SWITCH("allow_no_dhe_kex", 0),
    tls_CONF_CMD_SWITCH("prioritize_chacha", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_SWITCH("strict", 0),
    tls_CONF_CMD_SWITCH("no_middlebox", 0),
    tls_CONF_CMD_SWITCH("anti_replay", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_SWITCH("no_anti_replay", tls_CONF_FLAG_SERVER),
    tls_CONF_CMD_STRING(SignatureAlgorithms, "sigalgs", 0),
    tls_CONF_CMD_STRING(ClientSignatureAlgorithms, "client_sigalgs", 0),
    tls_CONF_CMD_STRING(Curves, "curves", 0),
    tls_CONF_CMD_STRING(Groups, "groups", 0),
#ifndef OPENtls_NO_EC
    tls_CONF_CMD_STRING(ECDHParameters, "named_curve", tls_CONF_FLAG_SERVER),
#endif
    tls_CONF_CMD_STRING(CipherString, "cipher", 0),
    tls_CONF_CMD_STRING(Ciphersuites, "ciphersuites", 0),
    tls_CONF_CMD_STRING(Protocol, NULL, 0),
    tls_CONF_CMD_STRING(MinProtocol, "min_protocol", 0),
    tls_CONF_CMD_STRING(MaxProtocol, "max_protocol", 0),
    tls_CONF_CMD_STRING(Options, NULL, 0),
    tls_CONF_CMD_STRING(VerifyMode, NULL, 0),
    tls_CONF_CMD(Certificate, "cert", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
    tls_CONF_CMD(PrivateKey, "key", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
    tls_CONF_CMD(ServerInfoFile, NULL,
                 tls_CONF_FLAG_SERVER | tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
    tls_CONF_CMD(ChainCAPath, "chainCApath", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_DIR),
    tls_CONF_CMD(ChainCAFile, "chainCAfile", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
    tls_CONF_CMD(ChainCAStore, "chainCAstore", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_STORE),
    tls_CONF_CMD(VerifyCAPath, "verifyCApath", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_DIR),
    tls_CONF_CMD(VerifyCAFile, "verifyCAfile", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
    tls_CONF_CMD(VerifyCAStore, "verifyCAstore", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_STORE),
    tls_CONF_CMD(RequestCAFile, "requestCAFile", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
    tls_CONF_CMD(ClientCAFile, NULL,
                 tls_CONF_FLAG_SERVER | tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
    tls_CONF_CMD(RequestCAPath, NULL, tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_DIR),
    tls_CONF_CMD(ClientCAPath, NULL,
                 tls_CONF_FLAG_SERVER | tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_DIR),
    tls_CONF_CMD(RequestCAStore, "requestCAStore", tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_STORE),
    tls_CONF_CMD(ClientCAStore, NULL,
                 tls_CONF_FLAG_SERVER | tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_STORE),
#ifndef OPENtls_NO_DH
    tls_CONF_CMD(DHParameters, "dhparam",
                 tls_CONF_FLAG_SERVER | tls_CONF_FLAG_CERTIFICATE,
                 tls_CONF_TYPE_FILE),
#endif
    tls_CONF_CMD_STRING(RecordPadding, "record_padding", 0),
    tls_CONF_CMD_STRING(NumTickets, "num_tickets", tls_CONF_FLAG_SERVER),
};

/* Supported switches: must match order of switches in tls_conf_cmds */
static const tls_switch_tbl tls_cmd_switches[] = {
    {tls_OP_NO_tlsv3, 0},       /* no_tls3 */
    {tls_OP_NO_TLSv1, 0},       /* no_tls1 */
    {tls_OP_NO_TLSv1_1, 0},     /* no_tls1_1 */
    {tls_OP_NO_TLSv1_2, 0},     /* no_tls1_2 */
    {tls_OP_NO_TLSv1_3, 0},     /* no_tls1_3 */
    {tls_OP_ALL, 0},            /* bugs */
    {tls_OP_NO_COMPRESSION, 0}, /* no_comp */
    {tls_OP_NO_COMPRESSION, tls_TFLAG_INV}, /* comp */
    {tls_OP_SINGLE_ECDH_USE, 0}, /* ecdh_single */
    {tls_OP_NO_TICKET, 0},      /* no_ticket */
    {tls_OP_CIPHER_SERVER_PREFERENCE, 0}, /* serverpref */
    /* legacy_renegotiation */
    {tls_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION, 0},
    /* legacy_server_connect */
    {tls_OP_LEGACY_SERVER_CONNECT, 0},
    /* no_renegotiation */
    {tls_OP_NO_RENEGOTIATION, 0},
    /* no_resumption_on_reneg */
    {tls_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION, 0},
    /* no_legacy_server_connect */
    {tls_OP_LEGACY_SERVER_CONNECT, tls_TFLAG_INV},
    /* allow_no_dhe_kex */
    {tls_OP_ALLOW_NO_DHE_KEX, 0},
    /* chacha reprioritization */
    {tls_OP_PRIORITIZE_CHACHA, 0},
    {tls_CERT_FLAG_TLS_STRICT, tls_TFLAG_CERT}, /* strict */
    /* no_middlebox */
    {tls_OP_ENABLE_MIDDLEBOX_COMPAT, tls_TFLAG_INV},
    /* anti_replay */
    {tls_OP_NO_ANTI_REPLAY, tls_TFLAG_INV},
    /* no_anti_replay */
    {tls_OP_NO_ANTI_REPLAY, 0},
};

static int tls_conf_cmd_skip_prefix(tls_CONF_CTX *cctx, const char **pcmd)
{
    if (pcmd == NULL || *pcmd == NULL)
        return 0;
    /* If a prefix is set, check and skip */
    if (cctx->prefix) {
        if (strlen(*pcmd) <= cctx->prefixlen)
            return 0;
        if (cctx->flags & tls_CONF_FLAG_CMDLINE &&
            strncmp(*pcmd, cctx->prefix, cctx->prefixlen))
            return 0;
        if (cctx->flags & tls_CONF_FLAG_FILE &&
            strncasecmp(*pcmd, cctx->prefix, cctx->prefixlen))
            return 0;
        *pcmd += cctx->prefixlen;
    } else if (cctx->flags & tls_CONF_FLAG_CMDLINE) {
        if (**pcmd != '-' || !(*pcmd)[1])
            return 0;
        *pcmd += 1;
    }
    return 1;
}

/* Determine if a command is allowed according to cctx flags */
static int tls_conf_cmd_allowed(tls_CONF_CTX *cctx, const tls_conf_cmd_tbl * t)
{
    unsigned int tfl = t->flags;
    unsigned int cfl = cctx->flags;
    if ((tfl & tls_CONF_FLAG_SERVER) && !(cfl & tls_CONF_FLAG_SERVER))
        return 0;
    if ((tfl & tls_CONF_FLAG_CLIENT) && !(cfl & tls_CONF_FLAG_CLIENT))
        return 0;
    if ((tfl & tls_CONF_FLAG_CERTIFICATE)
        && !(cfl & tls_CONF_FLAG_CERTIFICATE))
        return 0;
    return 1;
}

static const tls_conf_cmd_tbl *tls_conf_cmd_lookup(tls_CONF_CTX *cctx,
                                                   const char *cmd)
{
    const tls_conf_cmd_tbl *t;
    size_t i;
    if (cmd == NULL)
        return NULL;

    /* Look for matching parameter name in table */
    for (i = 0, t = tls_conf_cmds; i < Otls_NELEM(tls_conf_cmds); i++, t++) {
        if (tls_conf_cmd_allowed(cctx, t)) {
            if (cctx->flags & tls_CONF_FLAG_CMDLINE) {
                if (t->str_cmdline && strcmp(t->str_cmdline, cmd) == 0)
                    return t;
            }
            if (cctx->flags & tls_CONF_FLAG_FILE) {
                if (t->str_file && strcasecmp(t->str_file, cmd) == 0)
                    return t;
            }
        }
    }
    return NULL;
}

static int ctrl_switch_option(tls_CONF_CTX *cctx, const tls_conf_cmd_tbl * cmd)
{
    /* Find index of command in table */
    size_t idx = cmd - tls_conf_cmds;
    const tls_switch_tbl *scmd;
    /* Sanity check index */
    if (idx >= Otls_NELEM(tls_cmd_switches))
        return 0;
    /* Obtain switches entry with same index */
    scmd = tls_cmd_switches + idx;
    tls_set_option(cctx, scmd->name_flags, scmd->option_value, 1);
    return 1;
}

int tls_CONF_cmd(tls_CONF_CTX *cctx, const char *cmd, const char *value)
{
    const tls_conf_cmd_tbl *runcmd;
    if (cmd == NULL) {
        tlserr(tls_F_tls_CONF_CMD, tls_R_INVALID_NULL_CMD_NAME);
        return 0;
    }

    if (!tls_conf_cmd_skip_prefix(cctx, &cmd))
        return -2;

    runcmd = tls_conf_cmd_lookup(cctx, cmd);

    if (runcmd) {
        int rv;
        if (runcmd->value_type == tls_CONF_TYPE_NONE) {
            return ctrl_switch_option(cctx, runcmd);
        }
        if (value == NULL)
            return -3;
        rv = runcmd->cmd(cctx, value);
        if (rv > 0)
            return 2;
        if (rv == -2)
            return -2;
        if (cctx->flags & tls_CONF_FLAG_SHOW_ERRORS) {
            tlserr(tls_F_tls_CONF_CMD, tls_R_BAD_VALUE);
            ERR_add_error_data(4, "cmd=", cmd, ", value=", value);
        }
        return 0;
    }

    if (cctx->flags & tls_CONF_FLAG_SHOW_ERRORS) {
        tlserr(tls_F_tls_CONF_CMD, tls_R_UNKNOWN_CMD_NAME);
        ERR_add_error_data(2, "cmd=", cmd);
    }

    return -2;
}

int tls_CONF_cmd_argv(tls_CONF_CTX *cctx, int *pargc, char ***pargv)
{
    int rv;
    const char *arg = NULL, *argn;

    if (pargc != NULL && *pargc == 0)
        return 0;
    if (pargc == NULL || *pargc > 0)
        arg = **pargv;
    if (arg == NULL)
        return 0;
    if (pargc == NULL || *pargc > 1)
        argn = (*pargv)[1];
    else
        argn = NULL;
    cctx->flags &= ~tls_CONF_FLAG_FILE;
    cctx->flags |= tls_CONF_FLAG_CMDLINE;
    rv = tls_CONF_cmd(cctx, arg, argn);
    if (rv > 0) {
        /* Success: update pargc, pargv */
        (*pargv) += rv;
        if (pargc)
            (*pargc) -= rv;
        return rv;
    }
    /* Unknown switch: indicate no arguments processed */
    if (rv == -2)
        return 0;
    /* Some error occurred processing command, return fatal error */
    if (rv == 0)
        return -1;
    return rv;
}

int tls_CONF_cmd_value_type(tls_CONF_CTX *cctx, const char *cmd)
{
    if (tls_conf_cmd_skip_prefix(cctx, &cmd)) {
        const tls_conf_cmd_tbl *runcmd;
        runcmd = tls_conf_cmd_lookup(cctx, cmd);
        if (runcmd)
            return runcmd->value_type;
    }
    return tls_CONF_TYPE_UNKNOWN;
}

tls_CONF_CTX *tls_CONF_CTX_new(void)
{
    tls_CONF_CTX *ret = OPENtls_zalloc(sizeof(*ret));

    return ret;
}

int tls_CONF_CTX_finish(tls_CONF_CTX *cctx)
{
    /* See if any certificates are missing private keys */
    size_t i;
    CERT *c = NULL;
    if (cctx->ctx)
        c = cctx->ctx->cert;
    else if (cctx->tls)
        c = cctx->tls->cert;
    if (c && cctx->flags & tls_CONF_FLAG_REQUIRE_PRIVATE) {
        for (i = 0; i < tls_PKEY_NUM; i++) {
            const char *p = cctx->cert_filename[i];
            /*
             * If missing private key try to load one from certificate file
             */
            if (p && !c->pkeys[i].privatekey) {
                if (!cmd_PrivateKey(cctx, p))
                    return 0;
            }
        }
    }
    if (cctx->canames) {
        if (cctx->tls)
            tls_set0_CA_list(cctx->tls, cctx->canames);
        else if (cctx->ctx)
            tls_CTX_set0_CA_list(cctx->ctx, cctx->canames);
        else
            sk_X509_NAME_pop_free(cctx->canames, X509_NAME_free);
        cctx->canames = NULL;
    }
    return 1;
}

void tls_CONF_CTX_free(tls_CONF_CTX *cctx)
{
    if (cctx) {
        size_t i;
        for (i = 0; i < tls_PKEY_NUM; i++)
            OPENtls_free(cctx->cert_filename[i]);
        OPENtls_free(cctx->prefix);
        sk_X509_NAME_pop_free(cctx->canames, X509_NAME_free);
        OPENtls_free(cctx);
    }
}

unsigned int tls_CONF_CTX_set_flags(tls_CONF_CTX *cctx, unsigned int flags)
{
    cctx->flags |= flags;
    return cctx->flags;
}

unsigned int tls_CONF_CTX_clear_flags(tls_CONF_CTX *cctx, unsigned int flags)
{
    cctx->flags &= ~flags;
    return cctx->flags;
}

int tls_CONF_CTX_set1_prefix(tls_CONF_CTX *cctx, const char *pre)
{
    char *tmp = NULL;
    if (pre) {
        tmp = OPENtls_strdup(pre);
        if (tmp == NULL)
            return 0;
    }
    OPENtls_free(cctx->prefix);
    cctx->prefix = tmp;
    if (tmp)
        cctx->prefixlen = strlen(tmp);
    else
        cctx->prefixlen = 0;
    return 1;
}

void tls_CONF_CTX_set_tls(tls_CONF_CTX *cctx, tls *tls)
{
    cctx->tls = tls;
    cctx->ctx = NULL;
    if (tls) {
        cctx->poptions = &tls->options;
        cctx->min_version = &tls->min_proto_version;
        cctx->max_version = &tls->max_proto_version;
        cctx->pcert_flags = &tls->cert->cert_flags;
        cctx->pvfy_flags = &tls->verify_mode;
    } else {
        cctx->poptions = NULL;
        cctx->min_version = NULL;
        cctx->max_version = NULL;
        cctx->pcert_flags = NULL;
        cctx->pvfy_flags = NULL;
    }
}

void tls_CONF_CTX_set_tls_ctx(tls_CONF_CTX *cctx, tls_CTX *ctx)
{
    cctx->ctx = ctx;
    cctx->tls = NULL;
    if (ctx) {
        cctx->poptions = &ctx->options;
        cctx->min_version = &ctx->min_proto_version;
        cctx->max_version = &ctx->max_proto_version;
        cctx->pcert_flags = &ctx->cert->cert_flags;
        cctx->pvfy_flags = &ctx->verify_mode;
    } else {
        cctx->poptions = NULL;
        cctx->min_version = NULL;
        cctx->max_version = NULL;
        cctx->pcert_flags = NULL;
        cctx->pvfy_flags = NULL;
    }
}
