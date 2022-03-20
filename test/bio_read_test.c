/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include "testutil/output.h"
#include "testutil.h"

#if defined(_WIN32)
int setup_tests(void)
{
    return 1;
}
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/*
 * this test case opens a pair of v4 or v6 sockets, bound to localhost.
 * A process is forked to do the writing. The write path is tested in
 * bio_write_test case.
 *
 * This code exercises the BIO_read side of things in the parent task.
 *
 * The foreground process reads 5 packets from the socket and discards
 * them.
 *
 * The packets being sent to the other destination are just ignored for now.
 */

#include "bio_dgram_test_helpers.h"

/* this runs in the parent process */
int read_socket_and_discard(int fd, int count, unsigned short portnum)
{
  char buf[512];
  BIO  *in;
  int  ret = 0;
  BIO_ADDR *ba;
  unsigned short port;

  /* do not wait forever! */
  alarm(60);

  ba = BIO_ADDR_new();

  in = BIO_new_dgram(fd, BIO_CLOSE);

  while(--count > 0 && (ret = BIO_read(in, buf, 512)) > 0) {

    /* now check out the bio structure for the origin of the packet */
    BIO_get_dgram_origin(in, ba);
    port = ntohs(BIO_ADDR_rawport(ba));
    if(port != 0 && port != portnum)
      TEST_error("packet from wrong port. Got %u, expected %u\n", port, portnum);
  }

  if(ret <= 0) {
    test_printf_stderr("BIO_read returned %d\n", ret);
  }

  BIO_ADDR_free(ba);

  return count;
}

static int test_bio_read_v4(int idx)
{
  int outfd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd1 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd2 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  BIO_ADDR          *dsthost1, *dsthost2;
  int ret = 0;
  int portnum;

  dsthost1 = BIO_ADDR_new();
  dsthost2 = BIO_ADDR_new();

  portnum = bind_v4_socket(infd1, dsthost1);
  if(portnum == -1 ||
     bind_v4_socket(infd2, dsthost2) == -1) return 0;

  ret = fork_and_read_write_packets(infd1, outfd, portnum, dsthost1, dsthost2);
  BIO_ADDR_free(dsthost1);
  BIO_ADDR_free(dsthost2);
  return ret;
}

static int test_bio_read_v6(int idx)
{
    int outfd = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
    int infd1 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
    int infd2 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
    BIO_ADDR *dsthost1;
    BIO_ADDR *dsthost2;
    int ret = 0;
    int portnum;

    dsthost1 = BIO_ADDR_new();
    dsthost2 = BIO_ADDR_new();

    portnum = bind_v6_socket(infd1, dsthost1, 0);
    if(portnum == -1 ||
       bind_v6_socket(infd2, dsthost2, 0) == -1) return 0;

    ret = fork_and_read_write_packets(infd1, outfd,
                                      portnum, dsthost1, dsthost2);
    BIO_ADDR_free(dsthost1);
    BIO_ADDR_free(dsthost2);

    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_bio_read_v4, 1);
    ADD_ALL_TESTS(test_bio_read_v6, 1);
    return 1;
}

#endif
