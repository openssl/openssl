/* test/fips_algvs.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2011
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
# include <stdio.h>

int main(int argc, char **argv)
{
    printf("No FIPS ALGVS support\n");
    return 0;
}
#else

# define FIPS_ALGVS

extern int fips_aesavs_main(int argc, char **argv);
extern int fips_cmactest_main(int argc, char **argv);
extern int fips_desmovs_main(int argc, char **argv);
extern int fips_dhvs_main(int argc, char **argv);
extern int fips_drbgvs_main(int argc, char **argv);
extern int fips_dssvs_main(int argc, char **argv);
extern int fips_ecdhvs_main(int argc, char **argv);
extern int fips_ecdsavs_main(int argc, char **argv);
extern int fips_gcmtest_main(int argc, char **argv);
extern int fips_hmactest_main(int argc, char **argv);
extern int fips_rngvs_main(int argc, char **argv);
extern int fips_rsagtest_main(int argc, char **argv);
extern int fips_rsastest_main(int argc, char **argv);
extern int fips_rsavtest_main(int argc, char **argv);
extern int fips_shatest_main(int argc, char **argv);
extern int fips_test_suite_main(int argc, char **argv);

# include "fips_aesavs.c"
# include "fips_cmactest.c"
# include "fips_desmovs.c"
# include "fips_dhvs.c"
# include "fips_drbgvs.c"
# include "fips_dssvs.c"
# include "fips_ecdhvs.c"
# include "fips_ecdsavs.c"
# include "fips_gcmtest.c"
# include "fips_hmactest.c"
# include "fips_rngvs.c"
# include "fips_rsagtest.c"
# include "fips_rsastest.c"
# include "fips_rsavtest.c"
# include "fips_shatest.c"
# include "fips_test_suite.c"

typedef struct {
    const char *name;
    int (*func) (int argc, char **argv);
} ALGVS_FUNCTION;

static ALGVS_FUNCTION algvs[] = {
    {"fips_aesavs", fips_aesavs_main},
    {"fips_cmactest", fips_cmactest_main},
    {"fips_desmovs", fips_desmovs_main},
    {"fips_dhvs", fips_dhvs_main},
    {"fips_drbgvs", fips_drbgvs_main},
    {"fips_dssvs", fips_dssvs_main},
    {"fips_ecdhvs", fips_ecdhvs_main},
    {"fips_ecdsavs", fips_ecdsavs_main},
    {"fips_gcmtest", fips_gcmtest_main},
    {"fips_hmactest", fips_hmactest_main},
    {"fips_rngvs", fips_rngvs_main},
    {"fips_rsagtest", fips_rsagtest_main},
    {"fips_rsastest", fips_rsastest_main},
    {"fips_rsavtest", fips_rsavtest_main},
    {"fips_shatest", fips_shatest_main},
    {"fips_test_suite", fips_test_suite_main},
    {NULL, 0}
};

/* Argument parsing taken from apps/apps.c */

typedef struct args_st {
    char **data;
    int count;
} ARGS;

static int chopup_args(ARGS *arg, char *buf, int *argc, char **argv[])
{
    int num, i;
    char *p;

    *argc = 0;
    *argv = NULL;

    i = 0;
    if (arg->count == 0) {
        arg->count = 20;
        arg->data = (char **)OPENSSL_malloc(sizeof(char *) * arg->count);
    }
    for (i = 0; i < arg->count; i++)
        arg->data[i] = NULL;

    num = 0;
    p = buf;
    for (;;) {
        /* first scan over white space */
        if (!*p)
            break;
        while (*p && ((*p == ' ') || (*p == '\t') || (*p == '\n')))
            p++;
        if (!*p)
            break;

        /* The start of something good :-) */
        if (num >= arg->count) {
            fprintf(stderr, "Too many arguments!!\n");
            return 0;
        }
        arg->data[num++] = p;

        /* now look for the end of this */
        if ((*p == '\'') || (*p == '\"')) { /* scan for closing quote */
            i = *(p++);
            arg->data[num - 1]++; /* jump over quote */
            while (*p && (*p != i))
                p++;
            *p = '\0';
        } else {
            while (*p && ((*p != ' ') && (*p != '\t') && (*p != '\n')))
                p++;

            if (*p == '\0')
                p--;
            else
                *p = '\0';
        }
        p++;
    }
    *argc = num;
    *argv = arg->data;
    return (1);
}

static int run_prg(int argc, char **argv)
{
    ALGVS_FUNCTION *t;
    const char *prg_name;
    prg_name = strrchr(argv[0], '/');
    if (prg_name)
        prg_name++;
    else
        prg_name = argv[0];
    for (t = algvs; t->name; t++) {
        if (!strcmp(prg_name, t->name))
            return t->func(argc, argv);
    }
    return -100;
}

int main(int argc, char **argv)
{
    char buf[1024];
    char **args = argv + 1;
    const char *sname = "fipstests.sh";
    ARGS arg;
    int xargc;
    char **xargv;
    int lineno = 0, badarg = 0;
    int nerr = 0, quiet = 0, verbose = 0;
    int rv;
    FILE *in = NULL;
# ifdef FIPS_ALGVS_MEMCHECK
    CRYPTO_malloc_debug_init();
    OPENSSL_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
# endif

    if (*args && *args[0] != '-') {
        rv = run_prg(argc - 1, args);
# ifdef FIPS_ALGVS_MEMCHECK
        CRYPTO_mem_leaks_fp(stderr);
# endif
        return rv;
    }
    while (!badarg && *args && *args[0] == '-') {
        if (!strcmp(*args, "-script")) {
            if (args[1]) {
                args++;
                sname = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "-quiet"))
            quiet = 1;
        else if (!strcmp(*args, "-verbose"))
            verbose = 1;
        else
            badarg = 1;
        args++;
    }

    if (badarg) {
        fprintf(stderr, "Error processing arguments\n");
        return 1;
    }

    in = fopen(sname, "r");
    if (!in) {
        fprintf(stderr, "Error opening script file \"%s\"\n", sname);
        return 1;
    }

    arg.data = NULL;
    arg.count = 0;

    while (fgets(buf, sizeof(buf), in)) {
        lineno++;
        if (!chopup_args(&arg, buf, &xargc, &xargv))
            fprintf(stderr, "Error processing line %d\n", lineno);
        else {
            if (!quiet) {
                int i;
                int narg = verbose ? xargc : xargc - 2;
                printf("Running command line:");
                for (i = 0; i < narg; i++)
                    printf(" %s", xargv[i]);
                printf("\n");
            }
            rv = run_prg(xargc, xargv);
            if (FIPS_module_mode())
                FIPS_module_mode_set(0, NULL);
            if (rv != 0)
                nerr++;
            if (rv == -100)
                fprintf(stderr, "ERROR: Command not found\n");
            else if (rv != 0)
                fprintf(stderr, "ERROR: returned %d\n", rv);
            else if (verbose)
                printf("\tCommand run successfully\n");
        }
    }

    if (!quiet)
        printf("Completed with %d errors\n", nerr);

    if (arg.data)
        OPENSSL_free(arg.data);

    fclose(in);
# ifdef FIPS_ALGVS_MEMCHECK
    CRYPTO_mem_leaks_fp(stderr);
# endif
    if (nerr == 0)
        return 0;
    return 1;
}
#endif
