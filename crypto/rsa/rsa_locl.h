/* $OpenBSD: rsa_locl.h,v 1.2 2014/06/12 15:49:30 deraadt Exp $ */
extern int int_rsa_verify(int dtype, const unsigned char *m,
    unsigned int m_len, unsigned char *rm, size_t *prm_len,
    const unsigned char *sigbuf, size_t siglen, RSA *rsa);
