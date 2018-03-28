/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Given a list of files, run each of them through the fuzzer.  Note that
 * failure will be indicated by some kind of crash. Switching on things like
 * asan improves the test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include "fuzzer.h"
#include "cpio_rdr.h"

int main(int argc, char **argv) {
    int n;
    int wantcpio = 0;

    if (argc > 1 && strcmp(argv[1], "-cpio") == 0) {
        wantcpio = 1;
        argc--;
        argv++;
    }

    FuzzerInitialize(&argc, &argv);

    for (n = 1; n < argc; ++n) {
        unsigned char *buf;
        size_t s;

        if (wantcpio) {
            CPIO *cpio = cpio_open(argv[n]);
            size_t size = 0;

            if (cpio == NULL)
                continue;
            while (!cpio_eof(cpio) && !cpio_error(cpio)) {
                const char *pathname = cpio_readentry(cpio, &size);

                if (cpio_eof(cpio))
                    break;

                printf("%s (%zu)\n", pathname, size);
                fflush(stdout);
                OPENSSL_assert(pathname != NULL);
                buf = malloc(size);
                if (buf == NULL)
                    continue;
                s = cpio_read(cpio, buf, size);
                OPENSSL_assert(s == size);
                FuzzerTestOneInput(buf, s);
                free(buf);
                OPENSSL_assert(!cpio_error(cpio));
                cpio_clearerr(cpio);
            }
            cpio_close(cpio);
        } else {
            struct stat st;
            FILE *f;

            stat(argv[n], &st);
            f = fopen(argv[n], "rb");
            if (f == NULL)
                continue;
            buf = malloc(st.st_size);
            if (buf == NULL)
                continue;
            s = fread(buf, 1, st.st_size, f);
            OPENSSL_assert(s == (size_t)st.st_size);
            FuzzerTestOneInput(buf, s);
            free(buf);
            fclose(f);
        }
    }

    FuzzerCleanup();

    return 0;
}
