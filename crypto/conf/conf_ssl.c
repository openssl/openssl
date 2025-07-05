/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include "internal/sslconf.h"
#include "internal/thread_once.h"
#include "conf_local.h"

/*
 * SSL library configuration module placeholder. We load it here but defer
 * all decisions about its contents to libssl.
 */

struct ssl_conf_name_st {
    /* Name of this set of commands */
    char *name;
    /* List of commands */
    SSL_CONF_CMD *cmds;
    /* Number of commands */
    size_t cmd_count;
};

struct ssl_conf_cmd_st {
    /* Command */
    char *cmd;
    /* Argument */
    char *arg;
};

static CRYPTO_ONCE init_ssl_names_lock = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *ssl_names_lock;
static struct ssl_conf_name_st *ssl_names;
static size_t ssl_names_count;

DEFINE_RUN_ONCE_STATIC(do_init_ssl_names_lock)
{
    ssl_names_lock = CRYPTO_THREAD_lock_new();
    if (ssl_names_lock == NULL) {
        ERR_raise(ERR_LIB_CONF, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static void ssl_module_free_unlocked(CONF_IMODULE *md)
{
    size_t i, j;

    if (ssl_names == NULL)
        return;
    for (i = 0; i < ssl_names_count; i++) {
        struct ssl_conf_name_st *tname = ssl_names + i;

        OPENSSL_free(tname->name);
        for (j = 0; j < tname->cmd_count; j++) {
            OPENSSL_free(tname->cmds[j].cmd);
            OPENSSL_free(tname->cmds[j].arg);
        }
        OPENSSL_free(tname->cmds);
    }
    OPENSSL_free(ssl_names);
    ssl_names = NULL;
    ssl_names_count = 0;
}

static void ssl_module_free(CONF_IMODULE *md)
{
    if (!CRYPTO_THREAD_write_lock(ssl_names_lock))
        return;
    ssl_module_free_unlocked(md);
    CRYPTO_THREAD_unlock(ssl_names_lock);
}

static int ssl_module_init(CONF_IMODULE *md, const CONF *cnf)
{
    size_t i, j, cnt;
    int rv = 0;
    const char *ssl_conf_section;
    STACK_OF(CONF_VALUE) *cmd_lists;

    if (!RUN_ONCE(&init_ssl_names_lock, do_init_ssl_names_lock))
        return 0;

    if (!CRYPTO_THREAD_write_lock(ssl_names_lock))
        return 0;

    ssl_conf_section = CONF_imodule_get_value(md);
    cmd_lists = NCONF_get_section(cnf, ssl_conf_section);
    if (sk_CONF_VALUE_num(cmd_lists) <= 0) {
        int rcode =
            cmd_lists == NULL
            ? CONF_R_SSL_SECTION_NOT_FOUND
            : CONF_R_SSL_SECTION_EMPTY;

        ERR_raise_data(ERR_LIB_CONF, rcode, "section=%s", ssl_conf_section);
        goto err;
    }
    cnt = sk_CONF_VALUE_num(cmd_lists);
    ssl_module_free_unlocked(md);
    ssl_names = OPENSSL_zalloc(sizeof(*ssl_names) * cnt);
    if (ssl_names == NULL)
        goto err;
    ssl_names_count = cnt;
    for (i = 0; i < ssl_names_count; i++) {
        struct ssl_conf_name_st *ssl_name = ssl_names + i;
        CONF_VALUE *sect = sk_CONF_VALUE_value(cmd_lists, (int)i);
        STACK_OF(CONF_VALUE) *cmds = NCONF_get_section(cnf, sect->value);

        if (sk_CONF_VALUE_num(cmds) <= 0) {
            int rcode =
                cmds == NULL
                ? CONF_R_SSL_COMMAND_SECTION_NOT_FOUND
                : CONF_R_SSL_COMMAND_SECTION_EMPTY;

            ERR_raise_data(ERR_LIB_CONF, rcode,
                           "name=%s, value=%s", sect->name, sect->value);
            goto err;
        }
        ssl_name->name = OPENSSL_strdup(sect->name);
        if (ssl_name->name == NULL)
            goto err;
        cnt = sk_CONF_VALUE_num(cmds);
        ssl_name->cmds = OPENSSL_zalloc(cnt * sizeof(struct ssl_conf_cmd_st));
        if (ssl_name->cmds == NULL)
            goto err;
        ssl_name->cmd_count = cnt;
        for (j = 0; j < cnt; j++) {
            const char *name;
            CONF_VALUE *cmd_conf = sk_CONF_VALUE_value(cmds, (int)j);
            struct ssl_conf_cmd_st *cmd = ssl_name->cmds + j;

            /* Skip any initial dot in name */
            name = strchr(cmd_conf->name, '.');
            if (name != NULL)
                name++;
            else
                name = cmd_conf->name;
            cmd->cmd = OPENSSL_strdup(name);
            cmd->arg = OPENSSL_strdup(cmd_conf->value);
            if (cmd->cmd == NULL || cmd->arg == NULL)
                goto err;
        }

    }
    rv = 1;
 err:
    if (rv == 0)
        ssl_module_free_unlocked(md);
    CRYPTO_THREAD_unlock(ssl_names_lock);
    return rv;
}

/*
 * Returns the set of commands with index |idx| previously searched for via
 * conf_ssl_name_find. Also stores the name of the set of commands in |*name|
 * and the number of commands in the set in |*cnt|.
 */
const SSL_CONF_CMD *conf_ssl_get(size_t idx, const char **name, size_t *cnt)
{
    const SSL_CONF_CMD *cmds;

    if (!RUN_ONCE(&init_ssl_names_lock, do_init_ssl_names_lock))
        goto err;

    if (!CRYPTO_THREAD_read_lock(ssl_names_lock))
        goto err;

    if (idx >= ssl_names_count) {
        CRYPTO_THREAD_unlock(ssl_names_lock);
        goto err;
    }

    *name = ssl_names[idx].name;
    *cnt = ssl_names[idx].cmd_count;
    cmds = ssl_names[idx].cmds;
    CRYPTO_THREAD_unlock(ssl_names_lock);

    return cmds;

err:
    *name = NULL;
    *cnt = 0;
    return NULL;
}

/*
 * Search for the named set of commands given in |name|. On success return the
 * index for the command set in |*idx|.
 * Returns 1 on success or 0 on failure.
 */
int conf_ssl_name_find(const char *name, size_t *idx)
{
    size_t i;
    const struct ssl_conf_name_st *nm;

    if (name == NULL)
        return 0;
    if (!RUN_ONCE(&init_ssl_names_lock, do_init_ssl_names_lock))
        return 0;
    if (!CRYPTO_THREAD_read_lock(ssl_names_lock))
        return 0;

    for (i = 0, nm = ssl_names; i < ssl_names_count; i++, nm++) {
        if (strcmp(nm->name, name) == 0) {
            *idx = i;
            CRYPTO_THREAD_unlock(ssl_names_lock);
            return 1;
        }
    }
    CRYPTO_THREAD_unlock(ssl_names_lock);
    return 0;
}

/*
 * Given a command set |cmd|, return details on the command at index |idx| which
 * must be less than the number of commands in the set (as returned by
 * conf_ssl_get). The name of the command will be returned in |*cmdstr| and the
 * argument is returned in |*arg|.
 */
void conf_ssl_get_cmd(const SSL_CONF_CMD *cmd, size_t idx, char **cmdstr,
                      char **arg)
{
    *cmdstr = cmd[idx].cmd;
    *arg = cmd[idx].arg;
}

void ossl_config_add_ssl_module(void)
{
    CONF_module_add("ssl_conf", ssl_module_init, ssl_module_free);
}
