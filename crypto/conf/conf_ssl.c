/*
 * Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <opentls/conf.h>
#include <opentls/err.h>
#include "internal/tlsconf.h"
#include "conf_local.h"

/*
 * tls library configuration module placeholder. We load it here but defer
 * all decisions about its contents to libtls.
 */

struct tls_conf_name_st {
    /* Name of this set of commands */
    char *name;
    /* List of commands */
    tls_CONF_CMD *cmds;
    /* Number of commands */
    size_t cmd_count;
};

struct tls_conf_cmd_st {
    /* Command */
    char *cmd;
    /* Argument */
    char *arg;
};

static struct tls_conf_name_st *tls_names;
static size_t tls_names_count;

static void tls_module_free(CONF_IMODULE *md)
{
    size_t i, j;
    if (tls_names == NULL)
        return;
    for (i = 0; i < tls_names_count; i++) {
        struct tls_conf_name_st *tname = tls_names + i;

        OPENtls_free(tname->name);
        for (j = 0; j < tname->cmd_count; j++) {
            OPENtls_free(tname->cmds[j].cmd);
            OPENtls_free(tname->cmds[j].arg);
        }
        OPENtls_free(tname->cmds);
    }
    OPENtls_free(tls_names);
    tls_names = NULL;
    tls_names_count = 0;
}

static int tls_module_init(CONF_IMODULE *md, const CONF *cnf)
{
    size_t i, j, cnt;
    int rv = 0;
    const char *tls_conf_section;
    STACK_OF(CONF_VALUE) *cmd_lists;

    tls_conf_section = CONF_imodule_get_value(md);
    cmd_lists = NCONF_get_section(cnf, tls_conf_section);
    if (sk_CONF_VALUE_num(cmd_lists) <= 0) {
        if (cmd_lists == NULL)
            CONFerr(CONF_F_tls_MODULE_INIT, CONF_R_tls_SECTION_NOT_FOUND);
        else
            CONFerr(CONF_F_tls_MODULE_INIT, CONF_R_tls_SECTION_EMPTY);
        ERR_add_error_data(2, "section=", tls_conf_section);
        goto err;
    }
    cnt = sk_CONF_VALUE_num(cmd_lists);
    tls_module_free(md);
    tls_names = OPENtls_zalloc(sizeof(*tls_names) * cnt);
    if (tls_names == NULL)
        goto err;
    tls_names_count = cnt;
    for (i = 0; i < tls_names_count; i++) {
        struct tls_conf_name_st *tls_name = tls_names + i;
        CONF_VALUE *sect = sk_CONF_VALUE_value(cmd_lists, (int)i);
        STACK_OF(CONF_VALUE) *cmds = NCONF_get_section(cnf, sect->value);

        if (sk_CONF_VALUE_num(cmds) <= 0) {
            if (cmds == NULL)
                CONFerr(CONF_F_tls_MODULE_INIT,
                        CONF_R_tls_COMMAND_SECTION_NOT_FOUND);
            else
                CONFerr(CONF_F_tls_MODULE_INIT,
                        CONF_R_tls_COMMAND_SECTION_EMPTY);
            ERR_add_error_data(4, "name=", sect->name, ", value=", sect->value);
            goto err;
        }
        tls_name->name = OPENtls_strdup(sect->name);
        if (tls_name->name == NULL)
            goto err;
        cnt = sk_CONF_VALUE_num(cmds);
        tls_name->cmds = OPENtls_zalloc(cnt * sizeof(struct tls_conf_cmd_st));
        if (tls_name->cmds == NULL)
            goto err;
        tls_name->cmd_count = cnt;
        for (j = 0; j < cnt; j++) {
            const char *name;
            CONF_VALUE *cmd_conf = sk_CONF_VALUE_value(cmds, (int)j);
            struct tls_conf_cmd_st *cmd = tls_name->cmds + j;

            /* Skip any initial dot in name */
            name = strchr(cmd_conf->name, '.');
            if (name != NULL)
                name++;
            else
                name = cmd_conf->name;
            cmd->cmd = OPENtls_strdup(name);
            cmd->arg = OPENtls_strdup(cmd_conf->value);
            if (cmd->cmd == NULL || cmd->arg == NULL)
                goto err;
        }

    }
    rv = 1;
 err:
    if (rv == 0)
        tls_module_free(md);
    return rv;
}

/*
 * Returns the set of commands with index |idx| previously searched for via
 * conf_tls_name_find. Also stores the name of the set of commands in |*name|
 * and the number of commands in the set in |*cnt|.
 */
const tls_CONF_CMD *conf_tls_get(size_t idx, const char **name, size_t *cnt)
{
    *name = tls_names[idx].name;
    *cnt = tls_names[idx].cmd_count;
    return tls_names[idx].cmds;
}

/*
 * Search for the named set of commands given in |name|. On success return the
 * index for the command set in |*idx|.
 * Returns 1 on success or 0 on failure.
 */
int conf_tls_name_find(const char *name, size_t *idx)
{
    size_t i;
    const struct tls_conf_name_st *nm;

    if (name == NULL)
        return 0;
    for (i = 0, nm = tls_names; i < tls_names_count; i++, nm++) {
        if (strcmp(nm->name, name) == 0) {
            *idx = i;
            return 1;
        }
    }
    return 0;
}

/*
 * Given a command set |cmd|, return details on the command at index |idx| which
 * must be less than the number of commands in the set (as returned by
 * conf_tls_get). The name of the command will be returned in |*cmdstr| and the
 * argument is returned in |*arg|.
 */
void conf_tls_get_cmd(const tls_CONF_CMD *cmd, size_t idx, char **cmdstr,
                      char **arg)
{
    *cmdstr = cmd[idx].cmd;
    *arg = cmd[idx].arg;
}

void conf_add_tls_module(void)
{
    CONF_module_add("tls_conf", tls_module_init, tls_module_free);
}
