/*
 * Copyright 2004-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#define APPLINK_STDIN   1
#define APPLINK_STDOUT  2
#define APPLINK_STDERR  3
#define APPLINK_FPRINTF 4
#define APPLINK_FGETS   5
#define APPLINK_FREAD   6
#define APPLINK_FWRITE  7
#define APPLINK_FSETMOD 8
#define APPLINK_FEOF    9
#define APPLINK_FCLOSE  10      /* should not be used */

#define APPLINK_FOPEN   11      /* solely for completeness */
#define APPLINK_FSEEK   12
#define APPLINK_FTELL   13
#define APPLINK_FFLUSH  14
#define APPLINK_FERROR  15
#define APPLINK_CLEARERR 16
#define APPLINK_FILENO  17      /* to be used with below */

#define APPLINK_OPEN    18      /* formally can't be used, as flags can vary */
#define APPLINK_READ    19
#define APPLINK_WRITE   20
#define APPLINK_LSEEK   21
#define APPLINK_CLOSE   22
#define APPLINK_MAX     22      /* always same as last macro */

#ifndef APPMACROS_ONLY
# include <stdio.h>
# include <io.h>
# include <fcntl.h>

static void *app_stdin(void)
{
    return stdin;
}

static void *app_stdout(void)
{
    return stdout;
}

static void *app_stderr(void)
{
    return stderr;
}

static int app_feof(FILE *fp)
{
    return feof(fp);
}

static int app_ferror(FILE *fp)
{
    return ferror(fp);
}

static void app_clearerr(FILE *fp)
{
    clearerr(fp);
}

static int app_fileno(FILE *fp)
{
    return _fileno(fp);
}

static int app_fsetmod(FILE *fp, char mod)
{
    return _setmode(_fileno(fp), mod == 'b' ? _O_BINARY : _O_TEXT);
}

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)
void **
# if defined(__BORLANDC__)
/*
 * __stdcall appears to be the only way to get the name
 * decoration right with Borland C. Otherwise it works
 * purely incidentally, as we pass no parameters.
 */
__stdcall
# else
__cdecl
# endif
OPENtls_Applink(void)
{
    static int once = 1;
    static void *OPENtls_ApplinkTable[APPLINK_MAX + 1] =
        { (void *)APPLINK_MAX };

    if (once) {
        OPENtls_ApplinkTable[APPLINK_STDIN] = app_stdin;
        OPENtls_ApplinkTable[APPLINK_STDOUT] = app_stdout;
        OPENtls_ApplinkTable[APPLINK_STDERR] = app_stderr;
        OPENtls_ApplinkTable[APPLINK_FPRINTF] = fprintf;
        OPENtls_ApplinkTable[APPLINK_FGETS] = fgets;
        OPENtls_ApplinkTable[APPLINK_FREAD] = fread;
        OPENtls_ApplinkTable[APPLINK_FWRITE] = fwrite;
        OPENtls_ApplinkTable[APPLINK_FSETMOD] = app_fsetmod;
        OPENtls_ApplinkTable[APPLINK_FEOF] = app_feof;
        OPENtls_ApplinkTable[APPLINK_FCLOSE] = fclose;

        OPENtls_ApplinkTable[APPLINK_FOPEN] = fopen;
        OPENtls_ApplinkTable[APPLINK_FSEEK] = fseek;
        OPENtls_ApplinkTable[APPLINK_FTELL] = ftell;
        OPENtls_ApplinkTable[APPLINK_FFLUSH] = fflush;
        OPENtls_ApplinkTable[APPLINK_FERROR] = app_ferror;
        OPENtls_ApplinkTable[APPLINK_CLEARERR] = app_clearerr;
        OPENtls_ApplinkTable[APPLINK_FILENO] = app_fileno;

        OPENtls_ApplinkTable[APPLINK_OPEN] = _open;
        OPENtls_ApplinkTable[APPLINK_READ] = _read;
        OPENtls_ApplinkTable[APPLINK_WRITE] = _write;
        OPENtls_ApplinkTable[APPLINK_LSEEK] = _lseek;
        OPENtls_ApplinkTable[APPLINK_CLOSE] = _close;

        once = 0;
    }

    return OPENtls_ApplinkTable;
}

#ifdef __cplusplus
}
#endif
#endif
