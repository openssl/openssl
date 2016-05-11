#ifndef __PPC_ARCH_H__
# define __PPC_ARCH_H__

extern unsigned int OPENSSL_ppccap_P;

/*
 * Flags' usage can appear ambiguous, because they are set rather
 * to reflect OpenSSL performance preferences than actual processor
 * capabilities.
 */
# define PPC_FPU64       (1<<0)
# define PPC_ALTIVEC     (1<<1)
# define PPC_CRYPTO207   (1<<2)
# define PPC_FPU         (1<<3)
# define PPC_MADD300     (1<<4)

#endif
