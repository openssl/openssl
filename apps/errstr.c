/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/lhash.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_STATS
} OPTION_CHOICE;

OPTIONS errstr_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] errnum...\n"},
    {OPT_HELP_STR, 1, '-', "  errnum  Error number\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"stats", OPT_STATS, '-',
     "Print internal hashtable statistics (long!)"},
    {NULL}
};

int errstr_main(int argc, char **argv)
{
    OPTION_CHOICE o;
    char buf[256], *prog;
    int ret = 1;
    unsigned long l;

    prog = opt_init(argc, argv, errstr_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(errstr_options);
            ret = 0;
            goto end;
        case OPT_STATS:
            lh_ERR_STRING_DATA_node_stats_bio(ERR_get_string_table(),
                                              bio_out);
            lh_ERR_STRING_DATA_stats_bio(ERR_get_string_table(), bio_out);
            lh_ERR_STRING_DATA_node_usage_stats_bio(ERR_get_string_table(),
                                                    bio_out);
            ret = 0;
            goto end;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    ret = 0;
    for (argv = opt_rest(); *argv; argv++) {
        if (!opt_ulong(*argv, &l))
            ret++;
        else {
            ERR_error_string_n(l, buf, sizeof buf);
            BIO_printf(bio_out, "%s\n", buf);
        }
    }
 end:
    return (ret);
}
