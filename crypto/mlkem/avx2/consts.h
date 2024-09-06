#ifndef CONSTS_H
#define CONSTS_H

#include "params.h"

#define _16XQ            0
#define _16XQINV        16
#define _16XV           32
#define _16XFLO         48
#define _16XFHI         64
#define _16XMONTSQLO    80
#define _16XMONTSQHI    96
#define _16XMASK       112
#define _REVIDXB       128
#define _REVIDXD       144
#define _ZETAS_EXP     160
#define	_16XSHIFT      624

/* The C ABI on MacOS exports all symbols with a leading
 * underscore. This means that any symbols we refer to from
 * C files (functions) can't be found, and all symbols we
 * refer to from ASM also can't be found.
 *
 * This define helps us get around this
 */
#ifdef __ASSEMBLER__
#if defined(__WIN32__) || defined(__APPLE__)
#define decorate(s) _##s
#define cdecl2(s) decorate(s)
#define cdecl(s) cdecl2(KYBER_NAMESPACE(##s))
#else
#define cdecl(s) KYBER_NAMESPACE(##s)
#endif
#endif

#ifndef __ASSEMBLER__
#include "align.h"
typedef ALIGNED_INT16(640) qdata_t;
#define qdata KYBER_NAMESPACE(qdata)
extern const qdata_t qdata;
#endif

#endif
