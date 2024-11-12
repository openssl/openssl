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

static void cleanup(void)
{
    int i;

    SetConsoleOutputCP(saved_cp);

    for (i = 0; i < newargc; i++)
        free(newargv[i]);

    free(newargv);
}

/*
 * Incrementally [re]allocate newargv and keep it NULL-terminated.
 */
static int validate_argv(int argc)
{
    static int size = 0;

    if (argc >= size) {
        char **ptr;

        while (argc >= size)
            size += 64;

        ptr = realloc(newargv, size * sizeof(newargv[0]));
        if (ptr == NULL)
            return 0;

        (newargv = ptr)[argc] = NULL;
    } else {
        newargv[argc] = NULL;
    }

    return 1;
}

static int process_glob(WCHAR *wstr, int wlen)
{
    int i, slash, udlen;
    WCHAR saved_char;
    WIN32_FIND_DATAW data;
    HANDLE h;

    /*
     * Note that we support wildcard characters only in filename part
     * of the path, and not in directories. Windows users are used to
     * this, that's why recursive glob processing is not implemented.
     */
    /*
     * Start by looking for last slash or backslash, ...
     */
    for (slash = 0, i = 0; i < wlen; i++)
        if (wstr[i] == L'/' || wstr[i] == L'\\')
            slash = i + 1;
    /*
     * ... then look for asterisk or question mark in the file name.
     */
    for (i = slash; i < wlen; i++)
        if (wstr[i] == L'*' || wstr[i] == L'?')
            break;

    if (i == wlen)
        return 0;   /* definitely not a glob */

    saved_char = wstr[wlen];
    wstr[wlen] = L'\0';
    h = FindFirstFileW(wstr, &data);
    wstr[wlen] = saved_char;
    if (h == INVALID_HANDLE_VALUE)
        return 0;   /* not a valid glob, just pass... */

    if (slash)
        udlen = WideCharToMultiByte(CP_UTF8, 0, wstr, slash,
                                    NULL, 0, NULL, NULL);
    else
        udlen = 0;

    do {
        int uflen;
        char *arg;

        /*
         * skip over . and ..
         */
        if (data.cFileName[0] == L'.') {
            if ((data.cFileName[1] == L'\0') ||
                (data.cFileName[1] == L'.' && data.cFileName[2] == L'\0'))
                continue;
        }

        if (!validate_argv(newargc + 1))
            break;

        /*
         * -1 below means "scan for trailing '\0' *and* count it",
         * so that |uflen| covers even trailing '\0'.
         */
        uflen = WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1,
                                    NULL, 0, NULL, NULL);

        arg = malloc(udlen + uflen);
        if (arg == NULL)
            break;

        if (udlen)
            WideCharToMultiByte(CP_UTF8, 0, wstr, slash,
                                arg, udlen, NULL, NULL);

        WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1,
                            arg + udlen, uflen, NULL, NULL);

        newargv[newargc++] = arg;
    } while (FindNextFileW(h, &data));

    CloseHandle(h);

    return 1;
}

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
    if (cmd_args == NULL)
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
    if (i = 0; i < argc; i++) {
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

    OPENSSL_atexit(win32_cleanup_argv);
    LocalFree(cmd_args);
    win32_cleanup_argv();
    newargv = argv;
    newargc = argc_used;

    *argc_out = argc_used;
    *argv_out = argv;
}
#else
void win32_utf8argv(void)
{   return;   }
#endif
