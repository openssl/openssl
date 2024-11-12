/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <windows.h>
#include <processenv.h>
#include <stringapiset.h>
#include <shellapi.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include <openssl/crypto.h>

#if defined(CP_UTF8)

static UINT saved_cp;
static int newargc;
static char **newargv;

static void win32_cleanup_argv(int argc, char **argv)
{
    int i;

    for (i = 0; i < argc; i++)
        OPENSSL_free(argv[i]);

    OPENSSL_free(argv);
}

static void win32_cleanup_argv_atexit(void)
{
    win32_cleanup_argv(newargc, newargv);
    newargv = NULL;
    newargc = 0;
}

void win32_utf8argv(int *argc_out, char ***argv_out)
{
    LPWSTR  cmd_line_args;
    LPWSTR *cmd_args;
    int     argc, argc_used, i, sz;
    char  **argv;

    *argc_out = 0;
    *argv_out = NULL;

    if (GetEnvironmentVariableW(L"OPENSSL_WIN32_UTF8", NULL, 0) == 0)
        return;

    cmd_line_args = GetCommandLineW();
    if (cmd_line_args == NULL)
        return;

    cmd_args = CommandLineToArgvW(cmd_line_args, &argc);
    if (cmd_args == NULL)
        return; /* no need to free cmd_line_args */

    if (argc == 0) {
        LocalFree(cmd_args);
        return;
    }

    argv = (char **) OPENSSL_zalloc(sizeof(char *) * argc);
    if (argv == NULL)
        return;

    argc_used = 0;
    for (i = 0; i < argc; i++) {
        sz = WideCharToMultiByte(CP_UTF8, 0, cmd_args[i], -1, NULL,
                                 0, NULL, NULL);
        if (sz > 0) {
            argv[argc_used] = (char *) OPENSSL_malloc(sz);
            if (argv[argc_used] == NULL) {
                LocalFree(cmd_args);
                win32_cleanup_argv(argc_used, argv);
                return;
            }

            argc_used++;
        }

        WideCharToMultiByte(CP_UTF8, 0, cmd_args[i], -1, argv[argc_used], sz,
            NULL, NULL);
    }

    OPENSSL_atexit(win32_cleanup_argv_atexit);
    LocalFree(cmd_args);
    win32_cleanup_argv_atexit();
    newargv = argv;
    newargc = argc_used;

    *argc_out = argc_used;
    *argv_out = argv;
}
#else
void win32_utf8argv(int *argc_out, char ***argv_out)
{   return;   }
#endif
