/* Attribution notice: Rainbow have generously allowed me to reproduce
 * the necessary definitions here from their API. This means the support
 * can build independantly of whether application builders have the
 * API or hardware. This will allow developers to easily produce software
 * that has latent hardware support for any users that have accelertors
 * installed, without the developers themselves needing anything extra.
 *
 * I have only clipped the parts from the CryptoSwift header files that
 * are (or seem) relevant to the CryptoSwift support code. This is
 * simply to keep the file sizes reasonable.
 * [Geoff]
 */


/* NB: These type widths do *not* seem right in general, in particular
 * they're not terribly friendly to 64-bit architectures (unsigned long)
 * will be 64-bit on IA-64 for a start. I'm leaving these alone as they
 * agree with Rainbow's API and this will only be called into question
 * on platforms with Rainbow support anyway! ;-) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef long              SW_STATUS;              /* status           */
typedef unsigned char     SW_BYTE;                /* 8 bit byte       */
typedef unsigned short    SW_U16;                 /* 16 bit number    */
#if defined(_IRIX)
#include <sgidefs.h>
typedef __uint32_t        SW_U32;
#else
typedef unsigned long     SW_U32;                 /* 32 bit integer   */
#endif
 
#if defined(WIN32)
  typedef struct _SW_U64 {
      SW_U32 low32;
      SW_U32 high32;
  } SW_U64;                                         /* 64 bit integer   */
#elif defined(MAC)
  typedef longlong SW_U64
#else /* Unix variants */
  typedef struct _SW_U64 {
      SW_U32 low32;
      SW_U32 high32;
  } SW_U64;                                         /* 64 bit integer   */
#endif

#define SW_OK                 (0L)

  /* algorithm type */
#define SW_ALG_CRT          1
#define SW_ALG_EXP          2
#define SW_ALG_DSA          3
#define SW_ALG_NVDATA       4

  /* command code */
#define SW_CMD_MODEXP_CRT   1 /* perform Modular Exponentiation using  */
                              /*  Chinese Remainder Theorem (CRT)      */
#define SW_CMD_MODEXP       2 /* perform Modular Exponentiation        */
#define SW_CMD_DSS_SIGN     3 /* perform DSS sign                      */
#define SW_CMD_DSS_VERIFY   4 /* perform DSS verify                    */
#define SW_CMD_RAND         5 /* perform random number generation      */
#define SW_CMD_NVREAD       6 /* perform read to nonvolatile RAM       */
#define SW_CMD_NVWRITE      7 /* perform write to nonvolatile RAM      */

typedef SW_U32            SW_ALGTYPE;             /* alogrithm type   */
typedef SW_U32            SW_STATE;               /* state            */
typedef SW_U32            SW_COMMAND_CODE;        /* command code     */
typedef SW_U32            SW_COMMAND_BITMAP[4];   /* bitmap           */

typedef struct _SW_LARGENUMBER {
    SW_U32    nbytes;       /* number of bytes in the buffer "value"  */
    SW_BYTE*  value;        /* the large integer as a string of       */
                            /*   bytes in network (big endian) order  */
} SW_LARGENUMBER;               

typedef struct _SW_CRT {
    SW_LARGENUMBER  p;      /* prime number p                         */
    SW_LARGENUMBER  q;      /* prime number q                         */
    SW_LARGENUMBER  dmp1;   /* exponent1                              */
    SW_LARGENUMBER  dmq1;   /* exponent2                              */
    SW_LARGENUMBER  iqmp;   /* CRT coefficient                        */
} SW_CRT;

typedef struct _SW_EXP {
    SW_LARGENUMBER  modulus; /* modulus                                */
    SW_LARGENUMBER  exponent;/* exponent                               */
} SW_EXP;

typedef struct _SW_DSA {
    SW_LARGENUMBER  p;      /*                                        */
    SW_LARGENUMBER  q;      /*                                        */
    SW_LARGENUMBER  g;      /*                                        */
    SW_LARGENUMBER  key;    /* private/public key                     */
} SW_DSA;

typedef struct _SW_NVDATA {
    SW_U32 accnum;          /* accelerator board number               */
    SW_U32 offset;          /* offset in byte                         */
} SW_NVDATA;

typedef struct _SW_PARAM {
    SW_ALGTYPE    type;     /* type of the alogrithm                  */
    union {
        SW_CRT    crt;
        SW_EXP    exp;
        SW_DSA    dsa;
        SW_NVDATA nvdata;
    } up;
} SW_PARAM;

typedef SW_U32 SW_CONTEXT_HANDLE; /* opaque context handle */


/* Now the OpenSSL bits, these function types are the for the function
 * pointers that will bound into the Rainbow shared libraries. */
typedef SW_STATUS t_swAcquireAccContext(SW_CONTEXT_HANDLE *hac);
typedef SW_STATUS t_swAttachKeyParam(SW_CONTEXT_HANDLE hac,
				SW_PARAM *key_params);
typedef SW_STATUS t_swSimpleRequest(SW_CONTEXT_HANDLE hac,
				SW_COMMAND_CODE cmd,
				SW_LARGENUMBER pin[],
				SW_U32 pin_count,
				SW_LARGENUMBER pout[],
				SW_U32 pout_count);
typedef SW_STATUS t_swReleaseAccContext(SW_CONTEXT_HANDLE hac);

#ifdef __cplusplus
}
#endif /* __cplusplus */

