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

#if defined(_WIN32)
int setup_tests(void)
{
    return 1;
}
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "testutil/output.h"
#include "testutil.h"

#define PACKET_COUNT 10

/*
 * this test case opens a pair of v4 or v6 sockets, bound to localhost.
 * A process is forked to do the writing, which is where the BIO code
 * is really exercised.  It writes alternately to two destinations.
 *
 * The foreground process reads 5 packets from the socket and discards
 * them.  This is done in the foreground because it's easier to count the
 * packets and exit sanely.
 *
 * The packets being send to the other destination are just ignored for now.
 */

static int read_socket_and_discard(int fd, int count)
{
  char buf[512];

  /* do not wait forever! */
  alarm(60);

  while(--count > 0 && read(fd, buf, 512)>0);
  return count;
}

static int write_packets(BIO *bio, int count, BIO_ADDR *dst1, BIO_ADDR *dst2)
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
    if(ret != sizeofhello) {
      exit(3);
    }

    toggle = !toggle;
  }

  return 0;
}

static int fork_and_read_write_packets(int infd, int outfd,
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
    exit(10);

  default:  /* parent */
    if(dsthost2 != NULL) {
      expected_count = expected_count / 2;
    }
    count = read_socket_and_discard(infd, expected_count);
    if(count != 0) {
      test_printf_stderr("failed receive all packets: %d\n", count);
      exit(2);
    }
  }

  return 1;
}

static void bind_v4_socket(int infd,
                          BIO_ADDR *dsthost)
{
  struct sockaddr_in localhost;
  socklen_t          sin_len;

  memset(&localhost, 0, sizeof(localhost));
  localhost.sin_family = AF_INET;
  localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  localhost.sin_port = 0;

  /* do not set port, let kernel pick. */
  if(bind(infd, (struct sockaddr *)&localhost, sizeof(localhost)) != 0) {
    perror("bind infd");
    exit(4);
  }

  /* extract port number, stuff it into dsthost1 */
  sin_len = sizeof(localhost);
  if(getsockname(infd, (struct sockaddr *)&localhost, &sin_len) != 0) {
    perror("getsockname");
    exit(5);
  }
  BIO_ADDR_rawmake(dsthost, AF_INET,
                   &localhost.sin_addr, sizeof(localhost.sin_addr),
                   localhost.sin_port);
}

static int test_bio_write_v4(int idx)
{
  int outfd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd1 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd2 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  BIO_ADDR          *dsthost1, *dsthost2;
  int ret = 0;

  dsthost1 = BIO_ADDR_new();
  dsthost2 = BIO_ADDR_new();

  bind_v4_socket(infd1, dsthost1);
  bind_v4_socket(infd2, dsthost2);

  ret = fork_and_read_write_packets(infd1, outfd, dsthost1, dsthost2);
  BIO_ADDR_free(dsthost1);
  BIO_ADDR_free(dsthost2);
  return ret;
}

static void bind_v6_socket(int infd,
                           BIO_ADDR *dsthost)
{
  struct sockaddr_in6 localhost;
  socklen_t          sin_len;

  memset(&localhost, 0, sizeof(localhost));
  localhost.sin6_family = AF_INET6;
  localhost.sin6_addr   = in6addr_loopback;
  localhost.sin6_port = 0;

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

  BIO_ADDR_rawmake(dsthost, AF_INET6,
                   &localhost.sin6_addr, sizeof(localhost.sin6_addr),
                   localhost.sin6_port);
}

static int test_bio_write_v6(int idx)
{
  int outfd = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  int infd1 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  int infd2 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
  BIO_ADDR   *dsthost1;
  BIO_ADDR   *dsthost2;
  int ret = 0;

  if(getenv("TRAVISCI_NO_IPV6")==NULL) {
    dsthost1 = BIO_ADDR_new();
    dsthost2 = BIO_ADDR_new();

    bind_v6_socket(infd1, dsthost1);
    bind_v6_socket(infd2, dsthost2);

    ret = fork_and_read_write_packets(infd1, outfd, dsthost1, dsthost2);
    BIO_ADDR_free(dsthost1);
    BIO_ADDR_free(dsthost2);
  } else {
    ret = 1;
  }
  return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_bio_write_v4, 1);
    ADD_ALL_TESTS(test_bio_write_v6, 1);
    return 1;
}

#endif /* !WIN32 */
