#ifndef HEADER_OPENSSLV_H
#define HEADER_OPENSSLV_H

/* Numeric release version identifier:
 * MMNNFFRBB: major minor fix final beta/patch
 * For example:
 * 0.9.3-dev	  0x00903000
 * 0.9.3beta1	  0x00903001
 * 0.9.3beta2-dev 0x00903002
 * 0.9.3beta2     0x00903002
 * 0.9.3	  0x00903100
 * 0.9.3a	  0x00903101
 * 0.9.4 	  0x00904100
 * 1.2.3z	  0x1020311a
 * (Prior to 0.9.3-dev a different scheme was used: 0.9.2b is 0x0922.)
 */
#define OPENSSL_VERSION_NUMBER	0x00904100L
#define OPENSSL_VERSION_TEXT	"OpenSSL 0.9.4 09 Aug 1999"
#define OPENSSL_VERSION_PTEXT	" part of " OPENSSL_VERSION_TEXT

#endif /* HEADER_OPENSSLV_H */
