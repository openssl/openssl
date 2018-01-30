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
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "testutil/output.h"
#include "testutil.h"

#define PACKET_COUNT 10

/*
 * this test case opens a pair of v4 or v6 sockets, bound to localhost.
 * A process is forked to do the writing, which is where the BIO code
 * is really exercised.
 *
 * The foreground process reads 10 packets from the socket and discards
 * them.  This is done in the foreground because it's easier to count the
 * packets and exit sanely.
 */

static int read_socket_and_discard(int fd, int count)
{
  char buf[512];

  while(--count > 0 && read(fd, buf, 512)>0);
  return count;
}

static int write_packets(BIO *bio, int count)
{
  const char hello[]="hellohellohello";

  while(--count > 0) {
    const int sizeofhello = sizeof(hello);
    int ret = BIO_write(bio, hello, sizeofhello);
    if(ret != sizeofhello) {
      exit(3);
    }
  }

  return 0;
}

static int fork_and_read_write_packets(int infd, int outfd,
                                       BIO_ADDR *dsthost)
{
  BIO *out;

  pid_t pid = fork();
  int   count;
  switch(pid) {
  case 0:   /* child */
    out = BIO_new_dgram(outfd, BIO_CLOSE);
    BIO_set_dgram_dest(out, dsthost);
    write_packets(out, PACKET_COUNT);
    exit(0);

  case -1:  /* failure */
    exit(10);

  default:  /* parent */
    count = read_socket_and_discard(infd, PACKET_COUNT);
    if(count != 0) {
      test_printf_stderr("failed receive all packets: %d\n", count);
      exit(2);
    }
  }

  return 1;
}

static int test_bio_write_v4(int idx)
{
  int outfd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd  = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  BIO_ADDR          *dsthost;
  struct sockaddr_in localhost;
  socklen_t          sin_len;
  int ret = 0;

  memset(&localhost, 0, sizeof(localhost));
  localhost.sin_family = AF_INET;
  localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dsthost = BIO_ADDR_new();

  /* do not set port, let kernel pick. */
  if(bind(infd, (struct sockaddr *)&localhost, sizeof(localhost)) != 0) {
    perror("bind infd");
    exit(4);
  }

  /* extract port number */
  sin_len = sizeof(localhost);
  if(getsockname(infd, (struct sockaddr *)&localhost, &sin_len) != 0) {
    perror("getsockname");
    exit(5);
  }

  //printf("bound to port: %u\n", ntohs(localhost.sin_port));

  BIO_ADDR_rawmake(dsthost, AF_INET,
                   &localhost.sin_addr, sizeof(localhost.sin_addr),
                   localhost.sin_port);

  ret = fork_and_read_write_packets(infd, outfd, dsthost);
  BIO_ADDR_free(dsthost);
  return ret;
}

static int test_bio_write_v6(int idx)
{
  int outfd = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  int infd  = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  BIO_ADDR          *dsthost;
  struct sockaddr_in6 localhost;
  socklen_t          sin_len;
  int ret = 0;

  memset(&localhost, 0, sizeof(localhost));
  localhost.sin6_family = AF_INET6;
  localhost.sin6_addr   = in6addr_loopback;
  dsthost = BIO_ADDR_new();

  /* do not set port, let kernel pick. */
  if(bind(infd, (struct sockaddr *)&localhost, sizeof(localhost)) != 0) {
    perror("bind in6fd");
    exit(4);
  }

  /* extract port number */
  sin_len = sizeof(localhost);
  if(getsockname(infd, (struct sockaddr *)&localhost, &sin_len) != 0) {
    perror("getsockname6");
    exit(5);
  }

#if 0
  printf("bound to v6 port: %u\n", ntohs(localhost.sin6_port));
#endif

  BIO_ADDR_rawmake(dsthost, AF_INET6,
                   &localhost.sin6_addr, sizeof(localhost.sin6_addr),
                   localhost.sin6_port);

  ret = fork_and_read_write_packets(infd, outfd, dsthost);
  BIO_ADDR_free(dsthost);
  return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_bio_write_v4, 1);
    ADD_ALL_TESTS(test_bio_write_v6, 1);
    return 1;
}

