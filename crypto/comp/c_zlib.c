#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>
#include <openssl/comp.h>

COMP_METHOD *COMP_zlib(void );

#ifndef ZLIB

static COMP_METHOD zlib_method={
	NID_undef,
	"(null)",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	};

#else

#include <zlib.h>

static int zlib_compress_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen);
static int zlib_expand_block(COMP_CTX *ctx, unsigned char *out,
	unsigned int olen, unsigned char *in, unsigned int ilen);

static int zz_uncompress(Bytef *dest, uLongf *destLen, const Bytef *source,
	uLong sourceLen);

static COMP_METHOD zlib_method={
	NID_zlib_compression,
	LN_zlib_compression,
	NULL,
	NULL,
	zlib_compress_block,
	zlib_expand_block,
	NULL,
	};

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
fprintf(stderr,"compress(%4d)->%4d %s\n",ilen,(int)l,(clear)?"clear":"zlib");
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
        fprintf(stderr,"expand  (%4d)->%4d %s\n",ilen,(int)l,in[0]?"zlib":"clear");
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

    err = inflateInit(&stream);
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

COMP_METHOD *COMP_zlib(void)
	{
	return(&zlib_method);
	}

