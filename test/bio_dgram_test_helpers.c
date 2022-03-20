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

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "bio_dgram_test_helpers.h"

int write_packets(BIO *bio, int count, BIO_ADDR *dst1, BIO_ADDR *dst2)
{
  const char hello[]="hellohellohello";
  int toggle = 0;
  int ret;

  while(--count > 0) {
    const int sizeofhello = sizeof(hello);

    if(toggle && dst2 != NULL) {
      BIO_set_dgram_dest(bio, dst2);
    } else {
      BIO_set_dgram_dest(bio, dst1);
    }

    ret = BIO_write(bio, hello, sizeofhello);
    if(ret != sizeofhello)
      TEST_error("did not write entire hello packet, tried %u, processed: %d\n", sizeofhello, ret);

    toggle = !toggle;
  }

  return 0;
}

int fork_and_read_write_packets(int infd, int outfd,
                                unsigned portnum,
                                BIO_ADDR *dsthost1, BIO_ADDR *dsthost2)
{
  BIO *out;
  int expected_count = PACKET_COUNT;

  pid_t pid = fork();
  int   count;

  switch(pid) {
  case 0:   /* child */
    out = BIO_new_dgram(outfd, BIO_CLOSE);
    write_packets(out, PACKET_COUNT, dsthost1, dsthost2);
    exit(0);

  case -1:  /* failure */
    TEST_error("fork failed, %s\n", strerror(errno));
    return 0;

  default:  /* parent */
    if(dsthost2 != NULL)
      expected_count = expected_count / 2;
    count = read_socket_and_discard(infd, expected_count, portnum);
    TEST_int_ne(count, 0);
  }

  return 1;
}

static int reusesock(int infd) {
  int val;

#ifdef SO_REUSEADDR
  val = 1;
  if (setsockopt(infd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1) {
    TEST_error("failed to set SO_REUSEADDR on v6 socket: %s\n", strerror(errno));
    return -1;
  }
#endif
#ifdef SO_REUSEPORT
  val = 1;
  if (setsockopt(infd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)) == -1) {
    TEST_error("failed to set SO_REUSEPORT on v6 socket: %s\n", strerror(errno));
    return -1;
  }
#endif

  return 0;
}

int bind_v4_socket(int infd,
                   BIO_ADDR *dsthost)
{
  struct sockaddr_in localhost;
  socklen_t          sin_len;

  memset(&localhost, 0, sizeof(localhost));
  localhost.sin_family = AF_INET;
  localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  localhost.sin_port = 0;

  if(reusesock(infd) == -1) return(-1);

  /* do not set port, let kernel pick. */
  if(bind(infd, (struct sockaddr *)&localhost, sizeof(localhost)) != 0) {
    TEST_error("failed to v4 bind socket: %s\n", strerror(errno));
    return -1;
  }

  /* extract port number, stuff it into dsthost1 */
  sin_len = sizeof(localhost);
  if(getsockname(infd, (struct sockaddr *)&localhost, &sin_len) != 0) {
    TEST_error("failed to call getsockname on socket: %s\n", strerror(errno));
    return -1;
  }

  BIO_ADDR_rawmake(dsthost, AF_INET,
                   &localhost.sin_addr, sizeof(localhost.sin_addr),
                   localhost.sin_port);

  return ntohs(localhost.sin_port);
}

int bind_v6_socket(int infd,
                   BIO_ADDR *dsthost,
                   unsigned short portnum)
{
  struct sockaddr_in6 localhost;
  socklen_t           sin_len;

  memset(&localhost, 0, sizeof(localhost));
  localhost.sin6_family = AF_INET6;
  localhost.sin6_addr   = in6addr_loopback;
  localhost.sin6_port   = portnum;

  if(reusesock(infd) == -1) return(-1);

  /* portnum may be 0, which lets kernel pick. */
  if(bind(infd, (struct sockaddr *)&localhost, sizeof(localhost)) != 0) {
    TEST_error("failed to v6 bind socket: %s\n", strerror(errno));
    return -1;
  }

  /* extract port number */
  sin_len = sizeof(localhost);
  if(getsockname(infd, (struct sockaddr *)&localhost, &sin_len) != 0) {
    TEST_error("failed to call getsockname6 on socket: %s\n", strerror(errno));
    return -1;
  }

  BIO_ADDR_rawmake(dsthost, AF_INET6,
                   &localhost.sin6_addr, sizeof(localhost.sin6_addr),
                   localhost.sin6_port);

  return ntohs(localhost.sin6_port);
}

