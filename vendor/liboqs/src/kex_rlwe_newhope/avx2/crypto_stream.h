#ifndef CRYPTO_STREAM_H
#define CRYPTO_STREAM_H

#ifdef TESTVECTORS
  #include "crypto_stream_chacha20.h"
  #define CRYPTO_STREAM_KEYBYTES 32
  #define CRYPTO_STREAM_NONCEBYTES 8
  #define crypto_stream crypto_stream_chacha20
#else
  #include "crypto_stream_aes256ctr.h"
  #define CRYPTO_STREAM_KEYBYTES 32
  #define CRYPTO_STREAM_NONCEBYTES 16
  #define crypto_stream crypto_stream_aes256ctr
#endif

#endif
