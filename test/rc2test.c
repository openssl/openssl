/* crypto/rc2/rc2test.c */
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

/*
 * This has been a quickly hacked 'ideatest.c'.  When I add tests for other
 * RC2 modes, more of the code will be uncommented.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_RC2
int main(int argc, char *argv[])
{
    printf("No RC2 support\n");
    return (0);
}
#else
# include <openssl/rc2.h>

static unsigned char RC2key[4][16] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
};

static unsigned char RC2plain[4][8] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

static unsigned char RC2cipher[4][8] = {
    {0x1C, 0x19, 0x8A, 0x83, 0x8D, 0xF0, 0x28, 0xB7},
    {0x21, 0x82, 0x9C, 0x78, 0xA9, 0xF9, 0xC0, 0x74},
    {0x13, 0xDB, 0x35, 0x17, 0xD3, 0x21, 0x86, 0x9E},
    {0x50, 0xDC, 0x01, 0x62, 0xBD, 0x75, 0x7F, 0x31},
};

int main(int argc, char *argv[])
{
    int i, n, err = 0;
    RC2_KEY key;
    unsigned char buf[8], buf2[8];

    for (n = 0; n < 4; n++) {
        RC2_set_key(&key, 16, &(RC2key[n][0]), 0 /* or 1024 */ );

        RC2_ecb_encrypt(&(RC2plain[n][0]), buf, &key, RC2_ENCRYPT);
        if (memcmp(&(RC2cipher[n][0]), buf, 8) != 0) {
            printf("ecb rc2 error encrypting\n");
            printf("got     :");
            for (i = 0; i < 8; i++)
                printf("%02X ", buf[i]);
            printf("\n");
            printf("expected:");
            for (i = 0; i < 8; i++)
                printf("%02X ", RC2cipher[n][i]);
            err = 20;
            printf("\n");
        }

        RC2_ecb_encrypt(buf, buf2, &key, RC2_DECRYPT);
        if (memcmp(&(RC2plain[n][0]), buf2, 8) != 0) {
            printf("ecb RC2 error decrypting\n");
            printf("got     :");
            for (i = 0; i < 8; i++)
                printf("%02X ", buf[i]);
            printf("\n");
            printf("expected:");
            for (i = 0; i < 8; i++)
                printf("%02X ", RC2plain[n][i]);
            printf("\n");
            err = 3;
        }
    }

    if (err == 0)
        printf("ecb RC2 ok\n");

# ifdef OPENSSL_SYS_NETWARE
    if (err)
        printf("ERROR: %d\n", err);
# endif
    EXIT(err);
}

#endif
