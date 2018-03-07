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
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "testutil/output.h"
#include "testutil.h"

#define PACKET_COUNT 10

/*
 * this test case opens a pair of v4 or v6 sockets, bound to localhost.
 * A process is forked to do the writing. The write path is tested in
 * bio_write_test case.
 *
 * This code exercises the BIO_read side of things.
 *
 * The foreground process reads 5 packets from the socket and discards
 * them.
 *
 * The packets being send to the other destination are just ignored for now.
 */

static int read_socket_and_discard(int fd, int count, unsigned portnum)
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

  while(--count > 0 && (ret=BIO_read(in, buf, 512))>0) {

    /* now check out the bio structure for the origin of the packet */
    BIO_get_dgram_origin(in, ba);
    port = ntohs(BIO_ADDR_rawport(ba));
    if(port!=0 && port != portnum) { exit(5); }
  }

  if(ret <= 0) {
    test_printf_stderr("BIO_read returned %d\n", ret);
  }

  BIO_ADDR_free(ba);

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
    exit(10);

  default:  /* parent */
    if(dsthost2 != NULL) {
      expected_count = expected_count / 2;
    }
    count = read_socket_and_discard(infd, expected_count, portnum);
    if(count != 0) {
      test_printf_stderr("failed receive all packets: %d\n", count);
      exit(2);
    }
  }

  return 1;
}

static unsigned int bind_v4_socket(int infd,
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

  return ntohs(localhost.sin_port);
}

static int test_bio_read_v4(int idx)
{
  int outfd = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd1 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  int infd2 = BIO_socket(AF_INET, SOCK_DGRAM, 0, 0);
  BIO_ADDR          *dsthost1, *dsthost2;
  int ret = 0;
  unsigned int portnum;

  dsthost1 = BIO_ADDR_new();
  dsthost2 = BIO_ADDR_new();

  portnum = bind_v4_socket(infd1, dsthost1);
  bind_v4_socket(infd2, dsthost2);

  ret = fork_and_read_write_packets(infd1, outfd, portnum, dsthost1, dsthost2);
  BIO_ADDR_free(dsthost1);
  BIO_ADDR_free(dsthost2);
  return ret;
}

static unsigned int bind_v6_socket(int infd,
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

  return ntohs(localhost.sin6_port);
}

static int test_bio_read_v6(int idx)
{
    int outfd = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
    int infd1 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
    int infd2 = BIO_socket(AF_INET6, SOCK_DGRAM, 0, 0);
    BIO_ADDR *dsthost1;
    BIO_ADDR *dsthost2;
    int ret = 0;
    unsigned int portnum;

    if(getenv("TRAVISCI_NO_IPV6")==NULL) {
      dsthost1 = BIO_ADDR_new();
      dsthost2 = BIO_ADDR_new();

      portnum = bind_v6_socket(infd1, dsthost1);
      bind_v6_socket(infd2, dsthost2);

      ret =
        fork_and_read_write_packets(infd1, outfd, portnum, dsthost1, dsthost2);
      BIO_ADDR_free(dsthost1);
      BIO_ADDR_free(dsthost2);
    } else {
      test_printf_stdout("not running IPv6 tests due to travis-ci environment\n");
      ret = 1;
    }

    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_bio_read_v4, 1);
    ADD_ALL_TESTS(test_bio_read_v6, 1);
    return 1;
}

#endif
