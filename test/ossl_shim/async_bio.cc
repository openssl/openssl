/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "async_bio.h"

#include <errno.h>
#include <string.h>

#include <openssl/crypto.h>


namespace {

struct AsyncBio {
  bool datagram;
  bool enforce_write_quota;
  size_t read_quota;
  size_t write_quota;
};

AsyncBio *GetData(BIO *bio) {
  /*
   * TODO: Missing accessor? This probably needs a BIO_get_method() in OpenSSL
   *       For now skip this check
   */
#if 0
  if (bio->method != &g_async_bio_method) {
    return NULL;
  }
#endif
  return (AsyncBio *)BIO_get_data(bio);
}

static int AsyncWrite(BIO *bio, const char *in, int inl) {
  AsyncBio *a = GetData(bio);
  if (a == NULL || BIO_next(bio) == NULL) {
    return 0;
  }

  if (!a->enforce_write_quota) {
    return BIO_write(BIO_next(bio), in, inl);
  }

  BIO_clear_retry_flags(bio);

  if (a->write_quota == 0) {
    BIO_set_retry_write(bio);
    errno = EAGAIN;
    return -1;
  }

  if (!a->datagram && (size_t)inl > a->write_quota) {
    inl = a->write_quota;
  }
  int ret = BIO_write(BIO_next(bio), in, inl);
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
  } else {
    a->write_quota -= (a->datagram ? 1 : ret);
  }
  return ret;
}

static int AsyncRead(BIO *bio, char *out, int outl) {
  AsyncBio *a = GetData(bio);
  if (a == NULL || BIO_next(bio) == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  if (a->read_quota == 0) {
    BIO_set_retry_read(bio);
    errno = EAGAIN;
    return -1;
  }

  if (!a->datagram && (size_t)outl > a->read_quota) {
    outl = a->read_quota;
  }
  int ret = BIO_read(BIO_next(bio), out, outl);
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
  } else {
    a->read_quota -= (a->datagram ? 1 : ret);
  }
  return ret;
}

static long AsyncCtrl(BIO *bio, int cmd, long num, void *ptr) {
  if (BIO_next(bio) == NULL) {
    return 0;
  }
  BIO_clear_retry_flags(bio);
  int ret = BIO_ctrl(BIO_next(bio), cmd, num, ptr);
  BIO_copy_next_retry(bio);
  return ret;
}

static int AsyncNew(BIO *bio) {
  AsyncBio *a = (AsyncBio *)OPENSSL_malloc(sizeof(*a));
  if (a == NULL) {
    return 0;
  }
  memset(a, 0, sizeof(*a));
  a->enforce_write_quota = true;
  BIO_set_init(bio, 1);
  BIO_set_data(bio, a);
  return 1;
}

static int AsyncFree(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }

  OPENSSL_free(BIO_get_data(bio));
  BIO_set_data(bio, NULL);
  BIO_set_init(bio, 0);
  return 1;
}

static long AsyncCallbackCtrl(BIO *bio, int cmd, bio_info_cb fp) {
  if (BIO_next(bio) == NULL) {
    return 0;
  }
  return BIO_callback_ctrl(BIO_next(bio), cmd, fp);
}

static BIO_METHOD *g_async_bio_method = NULL;

static const BIO_METHOD *AsyncMethod(void)
{
  if (g_async_bio_method == NULL) {
    g_async_bio_method = BIO_meth_new(BIO_TYPE_FILTER, "async bio");
    if (   g_async_bio_method == NULL
        || !BIO_meth_set_write(g_async_bio_method, AsyncWrite)
        || !BIO_meth_set_read(g_async_bio_method, AsyncRead)
        || !BIO_meth_set_ctrl(g_async_bio_method, AsyncCtrl)
        || !BIO_meth_set_create(g_async_bio_method, AsyncNew)
        || !BIO_meth_set_destroy(g_async_bio_method, AsyncFree)
        || !BIO_meth_set_callback_ctrl(g_async_bio_method, AsyncCallbackCtrl))
    return NULL;
  }
  return g_async_bio_method;
}

}  // namespace

ScopedBIO AsyncBioCreate() {
  return ScopedBIO(BIO_new(AsyncMethod()));
}

ScopedBIO AsyncBioCreateDatagram() {
  ScopedBIO ret(BIO_new(AsyncMethod()));
  if (!ret) {
    return nullptr;
  }
  GetData(ret.get())->datagram = true;
  return ret;
}

void AsyncBioAllowRead(BIO *bio, size_t count) {
  AsyncBio *a = GetData(bio);
  if (a == NULL) {
    return;
  }
  a->read_quota += count;
}

void AsyncBioAllowWrite(BIO *bio, size_t count) {
  AsyncBio *a = GetData(bio);
  if (a == NULL) {
    return;
  }
  a->write_quota += count;
}

void AsyncBioEnforceWriteQuota(BIO *bio, bool enforce) {
  AsyncBio *a = GetData(bio);
  if (a == NULL) {
    return;
  }
  a->enforce_write_quota = enforce;
}
