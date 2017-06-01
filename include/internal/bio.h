/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_INTERNAL_BIO_H
# define HEADER_INTERNAL_BIO_H

#include <openssl/bio.h>

struct bio_method_st {
    int type;
    char *name;
    int (*bwrite) (BIO *, const char *, size_t, size_t *);
    int (*bwrite_old) (BIO *, const char *, int);
    int (*bread) (BIO *, char *, size_t, size_t *);
    int (*bread_old) (BIO *, char *, int);
    int (*bputs) (BIO *, const char *);
    int (*bgets) (BIO *, char *, int);
    long (*ctrl) (BIO *, int, long, void *);
    int (*create) (BIO *);
    int (*destroy) (BIO *);
    long (*callback_ctrl) (BIO *, int, BIO_info_cb *);
};

void bio_free_ex_data(BIO *bio);
void bio_cleanup(void);


/* Old style to new style BIO_METHOD conversion functions */
int bwrite_conv(BIO *bio, const char *data, size_t datal, size_t *written);
int bread_conv(BIO *bio, char *data, size_t datal, size_t *read);

# define BIO_CTRL_SET_KTLS_SEND                 72
# define BIO_CTRL_SET_KTLS_SEND_CTRL_MSG        74
# define BIO_CTRL_CLEAR_KTLS_CTRL_MSG      75

/*
 * This is used with socket BIOs:
 * BIO_FLAGS_KTLS means we are using ktls with this BIO.
 * BIO_FLAGS_KTLS_CTRL_MSG means we are about to send a ctrl message next.
 */
# define BIO_FLAGS_KTLS          0x800
# define BIO_FLAGS_KTLS_CTRL_MSG 0x1000

/* KTLS related controls and flags */
# define BIO_set_ktls_flag(b) \
    BIO_set_flags(b, BIO_FLAGS_KTLS)
# define BIO_should_ktls_flag(b) \
    BIO_test_flags(b, BIO_FLAGS_KTLS)
# define BIO_set_ktls_ctrl_msg_flag(b) \
    BIO_set_flags(b, BIO_FLAGS_KTLS_CTRL_MSG)
# define BIO_should_ktls_ctrl_msg_flag(b) \
    BIO_test_flags(b, (BIO_FLAGS_KTLS_CTRL_MSG))
# define BIO_clear_ktls_ctrl_msg_flag(b) \
    BIO_clear_flags(b, (BIO_FLAGS_KTLS_CTRL_MSG))

#  define BIO_set_ktls(b, keyblob, is_tx)   \
     BIO_ctrl(b, BIO_CTRL_SET_KTLS_SEND, is_tx, keyblob)
#  define BIO_set_ktls_ctrl_msg(b, record_type)   \
     BIO_ctrl(b, BIO_CTRL_SET_KTLS_SEND_CTRL_MSG, record_type, NULL)
#  define BIO_clear_ktls_ctrl_msg(b) \
     BIO_ctrl(b, BIO_CTRL_CLEAR_KTLS_CTRL_MSG, 0, NULL)

#endif
