
#ifndef HEADER_COMP_H
#define HEADER_COMP_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "crypto.h"

typedef struct comp_method_st
	{
	int type;		/* NID for compression library */
	char *name;		/* A text string to identify the library */
	int (*init)();
	void (*finish)();
	int (*compress)();
	int (*expand)();
	long (*ctrl)();
	} COMP_METHOD;

typedef struct comp_ctx_st
	{
	COMP_METHOD *meth;
	unsigned long compress_in;
	unsigned long compress_out;
	unsigned long expand_in;
	unsigned long expand_out;

	CRYPTO_EX_DATA	ex_data;
	} COMP_CTX;

#ifndef NOPROTO

COMP_CTX *COMP_CTX_new(COMP_METHOD *meth);
void COMP_CTX_free(COMP_CTX *ctx);
int COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
	unsigned char *in, int ilen);
int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
	unsigned char *in, int ilen);
COMP_METHOD *COMP_rle(void );
#ifdef ZLIB
COMP_METHOD *COMP_zlib(void );
#endif

#else

COMP_CTX *COMP_CTX_new();
void COMP_CTX_free();
int COMP_compress_block();
int COMP_expand_block();
COMP_METHOD *COMP_rle();
#ifdef ZLIB
COMP_METHOD *COMP_zlib();
#endif

#endif
/* BEGIN ERROR CODES */
 
#ifdef  __cplusplus
}
#endif
#endif

