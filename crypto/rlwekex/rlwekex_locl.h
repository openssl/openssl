/* crypto/rlwekex/rlwekex_locl.h */

#ifndef HEADER_RLWEKEX_LOCL_H
#define HEADER_RLWEKEX_LOCL_H

#include <openssl/rlwekex.h>
#include "rlwekexlib/fft.h"

#define CONSTANT_TIME 1

#ifdef  __cplusplus
extern "C" {
#endif

struct rlwe_param_st {
	int version;
	uint32_t *a;
	int references;
	int	flags;
};

struct rlwe_pub_st {
	int version;
	RLWE_PARAM *param;
	uint32_t *b;
	int references;
	int	flags;
};

struct rlwe_pair_st {
	int version;
	RLWE_PUB *pub;
	uint32_t *s;
	uint32_t *e;
	int references;
	int	flags;
};

struct rlwe_rec_st {
	int version;
	uint64_t *c;
	int references;
	int	flags;
};

struct rlwe_ctx_st {
	int version;
	FFT_CTX *fft_ctx;
	int references;
	int	flags;
};

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_RLWEKEX_LOCL_H */
