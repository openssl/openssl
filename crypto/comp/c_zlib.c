#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>
#include <openssl/comp.h>
#include <openssl/err.h>

COMP_METHOD *COMP_zlib(void );

static COMP_METHOD zlib_method_nozlib={
	NID_undef,
	"(undef)",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	};

#ifndef ZLIB
#undef ZLIB_SHARED
#else

#include <zlib.h>

static int zlib_stateful_init(COMP_CTX *ctx);
static void zlib_stateful_finish(COMP_CTX *ctx);
static int zlib_stateful_compress_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen);
static int zlib_stateful_expand_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen);

#if 0
static int zlib_compress_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen);
static int zlib_expand_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen);

static int zz_uncompress(Bytef *dest, uLongf *destLen, const Bytef *source,
	uLong sourceLen);

static COMP_METHOD zlib_stateless_method={
	NID_zlib_compression,
	LN_zlib_compression,
	NULL,
	NULL,
	zlib_compress_block,
	zlib_expand_block,
	NULL,
	NULL,
	};
#endif

static COMP_METHOD zlib_stateful_method={
	NID_zlib_compression,
	LN_zlib_compression,
	zlib_stateful_init,
	zlib_stateful_finish,
	zlib_stateful_compress_block,
	zlib_stateful_expand_block,
	NULL,
	NULL,
	};

/* 
 * When OpenSSL is built on Windows, we do not want to require that
 * the ZLIB.DLL be available in order for the OpenSSL DLLs to
 * work.  Therefore, all ZLIB routines are loaded at run time
 * and we do not link to a .LIB file.
 */
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
# include <windows.h>

# define Z_CALLCONV _stdcall
# ifndef ZLIB_SHARED
#  define ZLIB_SHARED
# endif
#else
# define Z_CALLCONV
#endif /* !(OPENSSL_SYS_WINDOWS || OPENSSL_SYS_WIN32) */

#ifdef ZLIB_SHARED
#include <openssl/dso.h>

/* Prototypes for built in stubs */
#if 0
static int stub_compress(Bytef *dest,uLongf *destLen,
	const Bytef *source, uLong sourceLen);
#endif
static int stub_inflateEnd(z_streamp strm);
static int stub_inflate(z_streamp strm, int flush);
static int stub_inflateInit_(z_streamp strm, const char * version,
	int stream_size);
static int stub_deflateEnd(z_streamp strm);
static int stub_deflate(z_streamp strm, int flush);
static int stub_deflateInit_(z_streamp strm, int level,
	const char * version, int stream_size);

/* Function pointers */
typedef int (Z_CALLCONV *compress_ft)(Bytef *dest,uLongf *destLen,
	const Bytef *source, uLong sourceLen);
typedef int (Z_CALLCONV *inflateEnd_ft)(z_streamp strm);
typedef int (Z_CALLCONV *inflate_ft)(z_streamp strm, int flush);
typedef int (Z_CALLCONV *inflateInit__ft)(z_streamp strm,
	const char * version, int stream_size);
typedef int (Z_CALLCONV *deflateEnd_ft)(z_streamp strm);
typedef int (Z_CALLCONV *deflate_ft)(z_streamp strm, int flush);
typedef int (Z_CALLCONV *deflateInit__ft)(z_streamp strm, int level,
	const char * version, int stream_size);
static compress_ft	p_compress=NULL;
static inflateEnd_ft	p_inflateEnd=NULL;
static inflate_ft	p_inflate=NULL;
static inflateInit__ft	p_inflateInit_=NULL;
static deflateEnd_ft	p_deflateEnd=NULL;
static deflate_ft	p_deflate=NULL;
static deflateInit__ft	p_deflateInit_=NULL;

static int zlib_loaded = 0;     /* only attempt to init func pts once */
static DSO *zlib_dso = NULL;

#define compress                stub_compress
#define inflateEnd              stub_inflateEnd
#define inflate                 stub_inflate
#define inflateInit_            stub_inflateInit_
#define deflateEnd              stub_deflateEnd
#define deflate                 stub_deflate
#define deflateInit_            stub_deflateInit_
#endif /* ZLIB_SHARED */

struct zlib_state
	{
	z_stream istream;
	z_stream ostream;
	};

static int zlib_stateful_ex_idx = -1;

static void zlib_stateful_free_ex_data(void *obj, void *item,
	CRYPTO_EX_DATA *ad, int ind,long argl, void *argp)
	{
	struct zlib_state *state = (struct zlib_state *)item;
	inflateEnd(&state->istream);
	deflateEnd(&state->ostream);
	OPENSSL_free(state);
	}

static int zlib_stateful_init(COMP_CTX *ctx)
	{
	int err;
	struct zlib_state *state =
		(struct zlib_state *)OPENSSL_malloc(sizeof(struct zlib_state));

	if (state == NULL)
		goto err;

	state->istream.zalloc = Z_NULL;
	state->istream.zfree = Z_NULL;
	state->istream.opaque = Z_NULL;
	state->istream.next_in = Z_NULL;
	state->istream.next_out = Z_NULL;
	state->istream.avail_in = 0;
	state->istream.avail_out = 0;
	err = inflateInit_(&state->istream,
		ZLIB_VERSION, sizeof(z_stream));
	if (err != Z_OK)
		goto err;

	state->ostream.zalloc = Z_NULL;
	state->ostream.zfree = Z_NULL;
	state->ostream.opaque = Z_NULL;
	state->ostream.next_in = Z_NULL;
	state->ostream.next_out = Z_NULL;
	state->ostream.avail_in = 0;
	state->ostream.avail_out = 0;
	err = deflateInit_(&state->ostream,Z_DEFAULT_COMPRESSION,
		ZLIB_VERSION, sizeof(z_stream));
	if (err != Z_OK)
		goto err;

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_COMP,ctx,&ctx->ex_data);
	if (zlib_stateful_ex_idx == -1)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_COMP);
		if (zlib_stateful_ex_idx == -1)
			zlib_stateful_ex_idx =
				CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_COMP,
					0,NULL,NULL,NULL,zlib_stateful_free_ex_data);
		CRYPTO_w_unlock(CRYPTO_LOCK_COMP);
		if (zlib_stateful_ex_idx == -1)
			goto err;
		}
	CRYPTO_set_ex_data(&ctx->ex_data,zlib_stateful_ex_idx,state);
	return 1;
 err:
	if (state) OPENSSL_free(state);
	return 0;
	}

static void zlib_stateful_finish(COMP_CTX *ctx)
	{
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_COMP,ctx,&ctx->ex_data);
	}

static int zlib_stateful_compress_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
	{
	int err = Z_OK;
	struct zlib_state *state =
		(struct zlib_state *)CRYPTO_get_ex_data(&ctx->ex_data,
			zlib_stateful_ex_idx);

	if (state == NULL)
		return -1;

	state->ostream.next_in = in;
	state->ostream.avail_in = ilen;
	state->ostream.next_out = out;
	state->ostream.avail_out = olen;
	if (ilen > 0)
		err = deflate(&state->ostream, Z_SYNC_FLUSH);
	if (err != Z_OK)
		return -1;
#ifdef DEBUG_ZLIB
	fprintf(stderr,"compress(%4d)->%4d %s\n",
		ilen,olen - state->ostream.avail_out,
		(ilen != olen - state->ostream.avail_out)?"zlib":"clear");
#endif
	return olen - state->ostream.avail_out;
	}

static int zlib_stateful_expand_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
	{
	int err = Z_OK;

	struct zlib_state *state =
		(struct zlib_state *)CRYPTO_get_ex_data(&ctx->ex_data,
			zlib_stateful_ex_idx);

	if (state == NULL)
		return 0;

	state->istream.next_in = in;
	state->istream.avail_in = ilen;
	state->istream.next_out = out;
	state->istream.avail_out = olen;
	if (ilen > 0)
		err = inflate(&state->istream, Z_SYNC_FLUSH);
	if (err != Z_OK)
		return -1;
#ifdef DEBUG_ZLIB
	fprintf(stderr,"expand(%4d)->%4d %s\n",
		ilen,olen - state->istream.avail_out,
		(ilen != olen - state->istream.avail_out)?"zlib":"clear");
#endif
	return olen - state->istream.avail_out;
	}

#if 0
static int zlib_compress_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
	{
	unsigned long l;
	int i;
	int clear=1;

	if (ilen > 128)
		{
		out[0]=1;
		l=olen-1;
		i=compress(&(out[1]),&l,in,(unsigned long)ilen);
		if (i != Z_OK)
			return(-1);
		if (ilen > l)
			{
			clear=0;
			l++;
			}
		}
	if (clear)
		{
		out[0]=0;
		memcpy(&(out[1]),in,ilen);
		l=ilen+1;
		}
#ifdef DEBUG_ZLIB
	fprintf(stderr,"compress(%4d)->%4d %s\n",
		ilen,(int)l,(clear)?"clear":"zlib");
#endif
	return((int)l);
	}

static int zlib_expand_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen)
	{
	unsigned long l;
	int i;

	if (in[0])
		{
		l=olen;
		i=zz_uncompress(out,&l,&(in[1]),(unsigned long)ilen-1);
		if (i != Z_OK)
			return(-1);
		}
	else
		{
		memcpy(out,&(in[1]),ilen-1);
		l=ilen-1;
		}
#ifdef DEBUG_ZLIB
        fprintf(stderr,"expand  (%4d)->%4d %s\n",
		ilen,(int)l,in[0]?"zlib":"clear");
#endif
	return((int)l);
	}

static int zz_uncompress (Bytef *dest, uLongf *destLen, const Bytef *source,
	     uLong sourceLen)
{
    z_stream stream;
    int err;

    stream.next_in = (Bytef*)source;
    stream.avail_in = (uInt)sourceLen;
    /* Check for source > 64K on 16-bit machine: */
    if ((uLong)stream.avail_in != sourceLen) return Z_BUF_ERROR;

    stream.next_out = dest;
    stream.avail_out = (uInt)*destLen;
    if ((uLong)stream.avail_out != *destLen) return Z_BUF_ERROR;

    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;

    err = inflateInit_(&stream,
	    ZLIB_VERSION, sizeof(z_stream));
    if (err != Z_OK) return err;

    err = inflate(&stream, Z_FINISH);
    if (err != Z_STREAM_END) {
        inflateEnd(&stream);
        return err;
    }
    *destLen = stream.total_out;

    err = inflateEnd(&stream);
    return err;
}
#endif

#endif

COMP_METHOD *COMP_zlib(void)
	{
	COMP_METHOD *meth = &zlib_method_nozlib;

#ifdef ZLIB_SHARED
	if (!zlib_loaded)
		{
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)
		zlib_dso = DSO_load(NULL, "ZLIB1", NULL, 0);
		if (!zlib_dso)
			{
			zlib_dso = DSO_load(NULL, "ZLIB", NULL, 0);
			if (zlib_dso)
				{
				/* Clear the errors from the first failed
				   DSO_load() */
				ERR_clear_error();
				}
			}
#else
		zlib_dso = DSO_load(NULL, "z", NULL, 0);
#endif
		if (zlib_dso != NULL)
			{
			p_compress
				= (compress_ft) DSO_bind_func(zlib_dso,
					"compress");
			p_inflateEnd
				= (inflateEnd_ft) DSO_bind_func(zlib_dso,
					"inflateEnd");
			p_inflate
				= (inflate_ft) DSO_bind_func(zlib_dso,
					"inflate");
			p_inflateInit_
				= (inflateInit__ft) DSO_bind_func(zlib_dso,
					"inflateInit_");
			p_deflateEnd
				= (deflateEnd_ft) DSO_bind_func(zlib_dso,
					"deflateEnd");
			p_deflate
				= (deflate_ft) DSO_bind_func(zlib_dso,
					"deflate");
			p_deflateInit_
				= (deflateInit__ft) DSO_bind_func(zlib_dso,
					"deflateInit_");
			zlib_loaded++;
			}
		}

#endif
#if defined(ZLIB) || defined(ZLIB_SHARED)
	meth = &zlib_stateful_method;
#endif

	return(meth);
	}

#ifdef ZLIB_SHARED
#if 0
/* Stubs for each function to be dynamicly loaded */
static int 
stub_compress(Bytef *dest,uLongf *destLen,const Bytef *source, uLong sourceLen)
	{
	if (p_compress)
		return(p_compress(dest,destLen,source,sourceLen));
	else
		return(Z_MEM_ERROR);
	}
#endif

static int
stub_inflateEnd(z_streamp strm)
	{
	if ( p_inflateEnd )
		return(p_inflateEnd(strm));
	else
		return(Z_MEM_ERROR);
	}

static int
stub_inflate(z_streamp strm, int flush)
	{
	if ( p_inflate )
		return(p_inflate(strm,flush));
	else
		return(Z_MEM_ERROR);
	}

static int
stub_inflateInit_(z_streamp strm, const char * version, int stream_size)
	{
	if ( p_inflateInit_ )
		return(p_inflateInit_(strm,version,stream_size));
	else
		return(Z_MEM_ERROR);
	}

static int
stub_deflateEnd(z_streamp strm)
	{
	if ( p_deflateEnd )
		return(p_deflateEnd(strm));
	else
		return(Z_MEM_ERROR);
	}

static int
stub_deflate(z_streamp strm, int flush)
	{
	if ( p_deflate )
		return(p_deflate(strm,flush));
	else
		return(Z_MEM_ERROR);
	}

static int
stub_deflateInit_(z_streamp strm, int level,
	const char * version, int stream_size)
	{
	if ( p_deflateInit_ )
		return(p_deflateInit_(strm,level,version,stream_size));
	else
		return(Z_MEM_ERROR);
	}

#endif /* ZLIB_SHARED */
