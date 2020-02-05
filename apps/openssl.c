/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <internal/cryptlib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/trace.h>
#include <openssl/lhash.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include <openssl/err.h>
/* Needed to get the other O_xxx flags. */
#ifdef OPENSSL_SYS_VMS
# include <unixio.h>
#endif
#include "apps.h"
#include "progs.h"

/* Special sentinel to exit the program. */
#define EXIT_THE_PROGRAM (-1)

/*
 * The LHASH callbacks ("hash" & "cmp") have been replaced by functions with
 * the base prototypes (we cast each variable inside the function to the
 * required type of "FUNCTION*"). This removes the necessity for
 * macro-generated wrapper functions.
 */
static LHASH_OF(FUNCTION) *prog_init(void);
static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[]);
char *default_config_file = NULL;

BIO *bio_in = NULL;
BIO *bio_out = NULL;
BIO *bio_err = NULL;

static void warn_deprecated(const char *pname,
                            const char *deprecated_alternative)
{
    BIO_printf(bio_err, "The command %s is deprecated.", pname);
    if (strcmp(deprecated_alternative, DEPRECATED_NO_ALTERNATIVE) != 0)
        BIO_printf(bio_err, " Use '%s' instead.", deprecated_alternative);
    BIO_printf(bio_err, "\n");
}

static int apps_startup(void)
{
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Set non-default library initialisation settings */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN
                          | OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;

    setup_ui_method();

    return 1;
}

static void apps_shutdown(void)
{
    destroy_ui_method();
}

static char *make_config_name(void)
{
    const char *t;
    size_t len;
    char *p;

    if ((t = getenv("OPENSSL_CONF")) != NULL)
        return OPENSSL_strdup(t);

    t = X509_get_default_cert_area();
    len = strlen(t) + 1 + strlen(OPENSSL_CONF) + 1;
    p = app_malloc(len, "config filename buffer");
    strcpy(p, t);
#ifndef OPENSSL_SYS_VMS
    strcat(p, "/");
#endif
    strcat(p, OPENSSL_CONF);

    return p;
}


#ifndef OPENSSL_NO_TRACE
typedef struct tracedata_st {
    BIO *bio;
    unsigned int ingroup:1;
} tracedata;

static size_t internal_trace_cb(const char *buf, size_t cnt,
                                int category, int cmd, void *vdata)
{
    int ret = 0;
    tracedata *trace_data = vdata;
    char buffer[256], *hex;
    CRYPTO_THREAD_ID tid;

    switch (cmd) {
    case OSSL_TRACE_CTRL_BEGIN:
        if (!ossl_assert(!trace_data->ingroup))
            return 0;
        trace_data->ingroup = 1;

        tid = CRYPTO_THREAD_get_current_id();
        hex = OPENSSL_buf2hexstr((const unsigned char *)&tid, sizeof(tid));
        BIO_snprintf(buffer, sizeof(buffer), "TRACE[%s]:%s: ",
                     hex == NULL ? "<null>" : hex,
                     OSSL_trace_get_category_name(category));
        OPENSSL_free(hex);
        BIO_set_prefix(trace_data->bio, buffer);
        break;
    case OSSL_TRACE_CTRL_WRITE:
        if (!ossl_assert(trace_data->ingroup))
            return 0;

        ret = BIO_write(trace_data->bio, buf, cnt);
        break;
    case OSSL_TRACE_CTRL_END:
        if (!ossl_assert(trace_data->ingroup))
            return 0;
        trace_data->ingroup = 0;

        BIO_set_prefix(trace_data->bio, NULL);

        break;
    }

    return ret < 0 ? 0 : ret;
}

DEFINE_STACK_OF(tracedata)
static STACK_OF(tracedata) *trace_data_stack;

static void tracedata_free(tracedata *data)
{
    BIO_free_all(data->bio);
    OPENSSL_free(data);
}

static STACK_OF(tracedata) *trace_data_stack;

static void cleanup_trace(void)
{
    sk_tracedata_pop_free(trace_data_stack, tracedata_free);
}

static void setup_trace_category(int category)
{
    BIO *channel;
    tracedata *trace_data;

    if (OSSL_trace_enabled(category))
        return;

    channel = BIO_push(BIO_new(BIO_f_prefix()), dup_bio_err(FORMAT_TEXT));
    trace_data = OPENSSL_zalloc(sizeof(*trace_data));

    if (trace_data == NULL
        || (trace_data->bio = channel) == NULL
        || OSSL_trace_set_callback(category, internal_trace_cb,
                                   trace_data) == 0
        || sk_tracedata_push(trace_data_stack, trace_data) == 0) {

        fprintf(stderr,
                "warning: unable to setup trace callback for category '%s'.\n",
                OSSL_trace_get_category_name(category));

        OSSL_trace_set_callback(category, NULL, NULL);
        BIO_free_all(channel);
    }
}

static void setup_trace(const char *str)
{
    char *val;

    /*
     * We add this handler as early as possible to ensure it's executed
     * as late as possible, i.e. after the TRACE code has done its cleanup
     * (which happens last in OPENSSL_cleanup).
     */
    atexit(cleanup_trace);

    trace_data_stack = sk_tracedata_new_null();
    val = OPENSSL_strdup(str);

    if (val != NULL) {
        char *valp = val;
        char *item;

        for (valp = val; (item = strtok(valp, ",")) != NULL; valp = NULL) {
            int category = OSSL_trace_get_category_num(item);

            if (category == OSSL_TRACE_CATEGORY_ALL) {
                while (++category < OSSL_TRACE_CATEGORY_NUM)
                    setup_trace_category(category);
                break;
            } else if (category > 0) {
                setup_trace_category(category);
            } else {
                fprintf(stderr,
                        "warning: unknown trace category: '%s'.\n", item);
            }
        }
    }

    OPENSSL_free(val);
}
#endif /* OPENSSL_NO_TRACE */

int main(int argc, char *argv[])
{
    FUNCTION f, *fp;
    LHASH_OF(FUNCTION) *prog = NULL;
    char *p, *pname;
    char buf[1024];
    const char *prompt;
    ARGS arg;
    int first, n, i, ret = 0;

    arg.argv = NULL;
    arg.size = 0;

    /* Set up some of the environment. */
    default_config_file = make_config_name();
    bio_in = dup_bio_in(FORMAT_TEXT);
    bio_out = dup_bio_out(FORMAT_TEXT);
    bio_err = dup_bio_err(FORMAT_TEXT);

#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
    argv = copy_argv(&argc, argv);
#elif defined(_WIN32)
    /*
     * Replace argv[] with UTF-8 encoded strings.
     */
    win32_utf8argv(&argc, &argv);
#endif

#ifndef OPENSSL_NO_TRACE
    setup_trace(getenv("OPENSSL_TRACE"));
#endif

    if (getenv("OPENSSL_FIPS")) {
        BIO_printf(bio_err, "FIPS mode not supported.\n");
        return 1;
    }

    if (!apps_startup()) {
        BIO_printf(bio_err,
                   "FATAL: Startup failure (dev note: apps_startup() failed)\n");
        ERR_print_errors(bio_err);
        ret = 1;
        goto end;
    }

    prog = prog_init();
    if (prog == NULL) {
        BIO_printf(bio_err,
                   "FATAL: Startup failure (dev note: prog_init() failed)\n");
        ERR_print_errors(bio_err);
        ret = 1;
        goto end;
    }
    pname = opt_progname(argv[0]);

    /* first check the program name */
    f.name = pname;
    fp = lh_FUNCTION_retrieve(prog, &f);
    if (fp != NULL) {
        argv[0] = pname;
        if (fp->deprecated_alternative != NULL)
            warn_deprecated(pname, fp->deprecated_alternative);
        ret = fp->func(argc, argv);
        goto end;
    }

    /* If there is stuff on the command line, run with that. */
    if (argc != 1) {
        argc--;
        argv++;
        ret = do_cmd(prog, argc, argv);
        if (ret < 0)
            ret = 0;
        goto end;
    }

    /* ok, lets enter interactive mode */
    for (;;) {
        ret = 0;
        /* Read a line, continue reading if line ends with \ */
        for (p = buf, n = sizeof(buf), i = 0, first = 1; n > 0; first = 0) {
            prompt = first ? "OpenSSL> " : "> ";
            p[0] = '\0';
#ifndef READLINE
            fputs(prompt, stdout);
            fflush(stdout);
            if (!fgets(p, n, stdin))
                goto end;
            if (p[0] == '\0')
                goto end;
            i = strlen(p);
            if (i <= 1)
                break;
            if (p[i - 2] != '\\')
                break;
            i -= 2;
            p += i;
            n -= i;
#else
            {
                extern char *readline(const char *);
                extern void add_history(const char *cp);
                char *text;

                text = readline(prompt);
                if (text == NULL)
                    goto end;
                i = strlen(text);
                if (i == 0 || i > n)
                    break;
                if (text[i - 1] != '\\') {
                    p += strlen(strcpy(p, text));
                    free(text);
                    add_history(buf);
                    break;
                }

                text[i - 1] = '\0';
                p += strlen(strcpy(p, text));
                free(text);
                n -= i;
            }
#endif
        }

        if (!chopup_args(&arg, buf)) {
            BIO_printf(bio_err, "Can't parse (no memory?)\n");
            break;
        }

        ret = do_cmd(prog, arg.argc, arg.argv);
        if (ret == EXIT_THE_PROGRAM) {
            ret = 0;
            goto end;
        }
        if (ret != 0)
            BIO_printf(bio_err, "error in %s\n", arg.argv[0]);
        (void)BIO_flush(bio_out);
        (void)BIO_flush(bio_err);
    }
    ret = 1;
 end:
    OPENSSL_free(default_config_file);
    lh_FUNCTION_free(prog);
    OPENSSL_free(arg.argv);
    app_RAND_write();

    BIO_free(bio_in);
    BIO_free_all(bio_out);
    apps_shutdown();
    BIO_free(bio_err);
    EXIT(ret);
}

typedef enum HELP_CHOICE {
    OPT_hERR = -1, OPT_hEOF = 0, OPT_hHELP
} HELP_CHOICE;

const OPTIONS help_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: help [options] [command]\n"},

    OPT_SECTION("General"),
    {"help", OPT_hHELP, '-', "Display this summary"},

    OPT_PARAMETERS(),
    {"command", 0, 0, "Name of command to display help (optional)"},
    {NULL}
};


int help_main(int argc, char **argv)
{
    FUNCTION *fp;
    int i, nl;
    FUNC_TYPE tp;
    char *prog;
    HELP_CHOICE o;
    DISPLAY_COLUMNS dc;

    prog = opt_init(argc, argv, help_options);
    while ((o = opt_next()) != OPT_hEOF) {
        switch (o) {
        case OPT_hERR:
        case OPT_hEOF:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            return 1;
        case OPT_hHELP:
            opt_help(help_options);
            return 0;
        }
    }

    if (opt_num_rest() == 1) {
        char *new_argv[3];

        new_argv[0] = opt_rest()[0];
        new_argv[1] = "--help";
        new_argv[2] = NULL;
        return do_cmd(prog_init(), 2, new_argv);
    }
    if (opt_num_rest() != 0) {
        BIO_printf(bio_err, "Usage: %s\n", prog);
        return 1;
    }

    calculate_columns(functions, &dc);
    BIO_printf(bio_err, "Standard commands");
    i = 0;
    tp = FT_none;
    for (fp = functions; fp->name != NULL; fp++) {
        nl = 0;
        if (i++ % dc.columns == 0) {
            BIO_printf(bio_err, "\n");
            nl = 1;
        }
        if (fp->type != tp) {
            tp = fp->type;
            if (!nl)
                BIO_printf(bio_err, "\n");
            if (tp == FT_md) {
                i = 1;
                BIO_printf(bio_err,
                           "\nMessage Digest commands (see the `dgst' command for more details)\n");
            } else if (tp == FT_cipher) {
                i = 1;
                BIO_printf(bio_err,
                           "\nCipher commands (see the `enc' command for more details)\n");
            }
        }
        BIO_printf(bio_err, "%-*s", dc.width, fp->name);
    }
    BIO_printf(bio_err, "\n\n");
    return 0;
}

static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[])
{
    FUNCTION f, *fp;

    if (argc <= 0 || argv[0] == NULL)
        return 0;
    f.name = argv[0];
    fp = lh_FUNCTION_retrieve(prog, &f);
    if (fp == NULL) {
        if (EVP_get_digestbyname(argv[0])) {
            f.type = FT_md;
            f.func = dgst_main;
            fp = &f;
        } else if (EVP_get_cipherbyname(argv[0])) {
            f.type = FT_cipher;
            f.func = enc_main;
            fp = &f;
        }
    }
    if (fp != NULL) {
        if (fp->deprecated_alternative != NULL)
            warn_deprecated(fp->name, fp->deprecated_alternative);
        return fp->func(argc, argv);
    }
    if ((strncmp(argv[0], "no-", 3)) == 0) {
        /*
         * User is asking if foo is unsupported, by trying to "run" the
         * no-foo command.  Strange.
         */
        f.name = argv[0] + 3;
        if (lh_FUNCTION_retrieve(prog, &f) == NULL) {
            BIO_printf(bio_out, "%s\n", argv[0]);
            return 0;
        }
        BIO_printf(bio_out, "%s\n", argv[0] + 3);
        return 1;
    }
    if (strcmp(argv[0], "quit") == 0 || strcmp(argv[0], "q") == 0 ||
        strcmp(argv[0], "exit") == 0 || strcmp(argv[0], "bye") == 0)
        /* Special value to mean "exit the program. */
        return EXIT_THE_PROGRAM;

    BIO_printf(bio_err, "Invalid command '%s'; type \"help\" for a list.\n",
               argv[0]);
    return 1;
}

static int function_cmp(const FUNCTION * a, const FUNCTION * b)
{
    return strncmp(a->name, b->name, 8);
}

static unsigned long function_hash(const FUNCTION * a)
{
    return OPENSSL_LH_strhash(a->name);
}

static int SortFnByName(const void *_f1, const void *_f2)
{
    const FUNCTION *f1 = _f1;
    const FUNCTION *f2 = _f2;

    if (f1->type != f2->type)
        return f1->type - f2->type;
    return strcmp(f1->name, f2->name);
}

static LHASH_OF(FUNCTION) *prog_init(void)
{
    static LHASH_OF(FUNCTION) *ret = NULL;
    static int prog_inited = 0;
    FUNCTION *f;
    size_t i;

    if (prog_inited)
        return ret;

    prog_inited = 1;

    /* Sort alphabetically within category. For nicer help displays. */
    for (i = 0, f = functions; f->name != NULL; ++f, ++i)
        ;
    qsort(functions, i, sizeof(*functions), SortFnByName);

    if ((ret = lh_FUNCTION_new(function_hash, function_cmp)) == NULL)
        return NULL;

    for (f = functions; f->name != NULL; f++)
        (void)lh_FUNCTION_insert(ret, f);
    return ret;
}
