/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_TEST_tlsTESTLIB_H
# define Otls_TEST_tlsTESTLIB_H

# include <opentls/tls.h>

int create_tls_ctx_pair(const tls_METHOD *sm, const tls_METHOD *cm,
                        int min_proto_version, int max_proto_version,
                        tls_CTX **sctx, tls_CTX **cctx, char *certfile,
                        char *privkeyfile);
int create_tls_objects(tls_CTX *serverctx, tls_CTX *clientctx, tls **stls,
                       tls **ctls, BIO *s_to_c_fbio, BIO *c_to_s_fbio);
int create_bare_tls_connection(tls *servertls, tls *clienttls, int want,
                               int read);
int create_tls_objects2(tls_CTX *serverctx, tls_CTX *clientctx, tls **stls,
                       tls **ctls, int sfd, int cfd);
int create_test_sockets(int *cfd, int *sfd);
int create_tls_connection(tls *servertls, tls *clienttls, int want);
void shutdown_tls_connection(tls *servertls, tls *clienttls);

/* Note: Not thread safe! */
const BIO_METHOD *bio_f_tls_dump_filter(void);
void bio_f_tls_dump_filter_free(void);

const BIO_METHOD *bio_s_mempacket_test(void);
void bio_s_mempacket_test_free(void);

const BIO_METHOD *bio_s_always_retry(void);
void bio_s_always_retry_free(void);

/* Packet types - value 0 is reserved */
#define INJECT_PACKET                   1
#define INJECT_PACKET_IGNORE_REC_SEQ    2

/*
 * Mempacket BIO ctrls. We make them large enough to not clash with standard BIO
 * ctrl codes.
 */
#define MEMPACKET_CTRL_SET_DROP_EPOCH       (1 << 15)
#define MEMPACKET_CTRL_SET_DROP_REC         (2 << 15)
#define MEMPACKET_CTRL_GET_DROP_REC         (3 << 15)
#define MEMPACKET_CTRL_SET_DUPLICATE_REC    (4 << 15)

int mempacket_test_inject(BIO *bio, const char *in, int inl, int pktnum,
                          int type);

typedef struct mempacket_st MEMPACKET;

DEFINE_STACK_OF(MEMPACKET)

#endif /* Otls_TEST_tlsTESTLIB_H */
