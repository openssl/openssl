/* crypto/bio/bss_bio.c  -*- Mode: C; c-file-style: "eay" -*- */

/*  *** Not yet finished (or even tested). *** */

/* Special method for a BIO where the other endpoint is also a BIO
 * of this kind, handled by the same thread.
 * Such "BIO pairs" are mainly for using the SSL library with I/O interfaces
 * for which no specific BIO method is available. */

#include <assert.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

static int bio_new(BIO *bio);
static int bio_free(BIO *bio);
static int bio_read(BIO *bio, char *buf, int size);
static int bio_write(BIO *bio, char *buf, int num);
static long bio_ctrl(BIO *bio, int cmd, long num, char *ptr);
static int bio_puts(BIO *bio, char *str);

static int bio_make_pair(BIO *bio1, BIO *bio2);
static void bio_destroy_pair(BIO *bio);

static BIO_METHOD methods_biop =
{
	BIO_TYPE_BIO,
	"BIO pair",
	bio_write,
	bio_read,
	bio_puts,
	NULL /* no bio_gets */,
	bio_ctrl,
	bio_new,
	bio_free
};

BIO_METHOD *BIO_s_bio(void)
	{
	return &methods_biop;
	}

struct bio_bio_st
{
	BIO *peer;     /* NULL if buf == NULL.
					* If peer != NULL, then peer->ptr is also a bio_bio_st,
					* and its "peer" member points back to us.
					* peer != NULL iff init != 0 in the BIO. */
	
	/* This is for what we write (i.e. reading uses peer's struct): */
	int closed;    /* valid iff peer != NULL */
	size_t len;    /* valid iff buf != NULL; 0 if peer == NULL */
	size_t offset; /* valid iff buf != NULL; 0 if len == 0 */
	size_t size;
	char *buf;     /* "size" elements (if != NULL) */
};

static int bio_new(BIO *bio)
	{
	struct bio_bio_st *b;
	
	b = Malloc(sizeof *b);
	if (b == NULL)
		return 0;

	b->peer = NULL;
	b->size = 17*1024; /* enough for one TLS record (just a default) */
	b->buf = NULL;

	return 1;
	}


static int bio_free(BIO *bio)
	{
	struct bio_bio_st *b;

	if (bio == NULL)
		return 0;
	b = bio->ptr;

	assert(b != NULL);

	if (b->peer)
		bio_destroy_pair(bio);
	
	if (b->buf != NULL)
		{
		Free(b->buf);
		}

	Free(b);

	return 1;
	}



static int bio_read(BIO *bio, char *buf, int size)
	{
	/* XXX */
	return -1;
	}

static int bio_write(BIO *bio, char *buf, int num)
	{
	/* XXX */
	return -1;
	}
	
static long bio_ctrl(BIO *bio, int cmd, long num, char *ptr)
	{
	long ret;
	struct bio_bio_st *b = bio->ptr;
	
	assert(b != NULL);

	switch (cmd)
		{
		/* XXX Additional commands: */
		/* - Set buffer size */
		/* - make pair */
		/* - destroy pair */
		/* - get number of bytes that the next write will accept */
		/* - send "close" */

	case BIO_CTRL_RESET:
		if (b->buf != NULL)
			{
			b->len = 0;
			b->offset = 0;
			}
		ret = 0;
		break;		

	case BIO_CTRL_GET_CLOSE:
		ret = bio->shutdown;
		break;

	case BIO_CTRL_SET_CLOSE:
		bio->shutdown = (int) num;
		ret = 1;
		break;

	case BIO_CTRL_PENDING:
		if (b->peer != NULL)
			{
			struct bio_bio_st *peer_b =b->peer->ptr;
			
			ret = (long) peer_b->len;
			}
		else
			ret = 0;
		break;

	case BIO_CTRL_WPENDING:
		if (b->buf != NULL)
			ret = (long) b->len;
		else
			ret = 0;
		break;

	case BIO_CTRL_DUP:
		/* XXX */

	case BIO_CTRL_FLUSH:
		ret = 1;
		break;

	default:
		ret = 0;
		}
	return ret;
	}

static int bio_puts(BIO *bio, char *str)
	{
	return bio_write(bio, str, strlen(str));
	}



static int bio_make_pair(BIO *bio1, BIO *bio2)
	{
	struct bio_bio_st *b1, *b2;

	assert(bio1 != NULL);
	assert(bio2 != NULL);

	b1 = bio1->ptr;
	b2 = bio2->ptr;
	
	if (b1->peer != NULL || b2->peer != NULL)
		{
		BIOerr(BIO_F_BIO_MAKE_PAIR, BIO_R_IN_USE);
		return 0;
		}
	
	if (b1->buf == NULL)
		{
		b1->buf = Malloc(b1->size);
		if (b1->buf == NULL)
			{
			BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		b1->len = 0;
		b1->offset = 0;
		}
	
	if (b2->buf == NULL)
		{
		b2->buf = Malloc(b2->size);
		if (b2->buf == NULL)
			{
			BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		b2->len = 0;
		b2->offset = 0;
		}
	
	b1->peer = bio2;
	b2->peer = bio1;

	bio1->init = 1;
	bio2->init = 1;

	return 1;
	}

static void bio_destroy_pair(BIO *bio)
	{
	struct bio_bio_st *b = bio->ptr;

	if (b != NULL)
		{
		BIO *peer_bio = b->peer;

		if (peer_bio != NULL)
			{
			struct bio_bio_st *peer_b = peer_bio->ptr;

			assert(peer_b != NULL);
			assert(peer_b->peer == bio);

			peer_b->peer = NULL;
			peer_bio->init = 0;
			assert(peer_b->buf != NULL);
			peer_b->len = 0;
			peer_b->offset = 0;
			
			b->peer = NULL;
			bio->init = 0;
			assert(b->buf != NULL);
			b->len = 0;
			b->offset = 0;
			}
		}
	}
