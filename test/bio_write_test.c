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
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bio_dgram_test_helpers.h"

/*
 * this test case opens a pair of v4 or v6 sockets, bound to localhost.
 * A process is forked to do the *writing*, which is where the BIO code
 * is really exercised.  It writes alternately to two destinations.
 *
 * The foreground process reads 5 packets from the socket and discards
 * them.  This is done in the foreground because it's easier to count the
 * packets and exit sanely.
 *
 * The packets being send to the other destination are just ignored for now.
 */

/* this is done with non BIO code because it is not the side that is being tested */
int read_socket_and_discard(int fd, int count, unsigned short portnum)
{
  char buf[512];

  /* do not wait forever! */
  alarm(60);

  while(--count > 0 && read(fd, buf, 512) > 0);
  return count;
}

static int test_bio_write_v4(int idx)
{
  int outfd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd1 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd2 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  BIO_ADDR          *dsthost1, *dsthost2;
  int ret = 0;
  short portnum1;

  dsthost1 = BIO_ADDR_new();
  dsthost2 = BIO_ADDR_new();

  portnum1 = bind_v4_socket(infd1, dsthost1);
  bind_v4_socket(infd2, dsthost2);

  ret = fork_and_read_write_packets(infd1, outfd, portnum1, dsthost1, dsthost2);
  BIO_ADDR_free(dsthost1);
  BIO_ADDR_free(dsthost2);
  return ret;
}

static int test_bio_write_v6(int idx)
{
  int outfd = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  int infd1 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  int infd2 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  BIO_ADDR   *dsthost1;
  BIO_ADDR   *dsthost2;
  int ret = 0;
  int portnum1;

  dsthost1 = BIO_ADDR_new();
  dsthost2 = BIO_ADDR_new();

  portnum1 = bind_v6_socket(infd1, dsthost1, 0);
  if(portnum1 == -1 ||
     bind_v6_socket(infd2, dsthost2, portnum1) == -1) goto end;

  ret = fork_and_read_write_packets(infd1, outfd, portnum1, dsthost1, dsthost2);
 end:
  BIO_ADDR_free(dsthost1);
  BIO_ADDR_free(dsthost2);
  return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_bio_write_v4, 1);
    ADD_ALL_TESTS(test_bio_write_v6, 1);
    return 1;
}

#endif /* !WIN32 */
