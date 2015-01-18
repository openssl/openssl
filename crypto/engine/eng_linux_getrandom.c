#include <openssl/opensslconf.h>

#include <unistd.h>
#include <sys/syscall.h>
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifndef SYS_getrandom

#if (defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__))
#ifdef __LP64__
#define SYS_getrandom 318
#else
#define SYS_getrandom 355
#endif // __LP64__
#endif // x86 or amd64

#ifdef __aarch64__
#define SYS_getrandom 384
#endif

#endif // !defined(SYS_getrandom)

#if defined(OPENSSL_SYS_LINUX) && defined(SYS_getrandom)

// see <linux>/include/uapi/linux/random.h
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif
#ifndef GRND_RANDOM
#define GRND_RANDOM 0x0002
#endif

static int sys_getrandom_ex (const unsigned char *buf, size_t buflen,
							 const unsigned int flags)
	{
	int pre_errno = errno;
	unsigned char *p = (unsigned char *)buf;

	while (buflen)
		{
		int ret = 0; // ret < 0 is an error, else: number of bytes returned
		int chunk = buflen > 256 ? 256 : buflen; // min(256, buflen);

		do {
			ret = syscall(SYS_getrandom, p, chunk, flags);
		} while (ret == -1 && errno == EINTR);
		if (ret < 0)
			return ret;

		p += ret;
		buflen -= ret;
		}

	errno = pre_errno;
	return 1;
	}

static int get_random_bytes (unsigned char *buf, int buflen)
	{
		if (buflen < 0)
			return (-1);
		return sys_getrandom_ex(buf, (size_t)buflen, GRND_RANDOM);
	}

static int get_pseudorandom_bytes (unsigned char *buf, int buflen)
	{
		if (buflen < 0)
			return (-1);
		return sys_getrandom_ex(buf, (size_t)buflen, 0);
	}

/* Consumes a few bytes of entropy by issuing the syscall. */
static int linux_has_syscall_getrandom (void)
	{
		int pre_errno = errno;
		unsigned long buf;
		syscall(SYS_getrandom, (unsigned char*)&buf, sizeof(unsigned long),
			GRND_NONBLOCK);
		if (errno == ENOSYS)
			return 0;
		errno = pre_errno;
		return 1;
	}

static int random_status (void)
{	return 1;	}

static RAND_METHOD linux_getrandom_meth =
	{
	NULL,	/* seed */
	get_random_bytes,
	NULL,	/* cleanup */
	NULL,	/* add */
	get_pseudorandom_bytes,
	random_status,
	};

static int linux_getrandom_init(ENGINE *e)
{	return 1;	}

static const char *engine_e_linux_getrandom_id = "linux_getrandom";
static const char *engine_e_linux_getrandom_name = "Linux syscall: getrandom";

static int bind_helper(ENGINE *e)
	{
	if (!ENGINE_set_id(e, engine_e_linux_getrandom_id) ||
	    !ENGINE_set_name(e, engine_e_linux_getrandom_name) ||
	    !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
	    !ENGINE_set_init_function(e, linux_getrandom_init) ||
	    !ENGINE_set_RAND(e, &linux_getrandom_meth) )
		return 0;

	return 1;
	}

static ENGINE *ENGINE_linux_getrandom(void)
	{
	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!bind_helper(ret))
		{
		ENGINE_free(ret);
		return NULL;
		}
	return ret;
	}

void ENGINE_load_linux_getrandom (void)
	{
	if (linux_has_syscall_getrandom() == 1)
		{
		ENGINE *toadd = ENGINE_linux_getrandom();
		if(!toadd) return;
		ENGINE_add(toadd);
		ENGINE_free(toadd);
		ERR_clear_error();
		}
	}
#else // !(defined(OPENSSL_SYS_LINUX) && defined(SYS_getrandom))
void ENGINE_load_linux_getrandom (void) {}
#endif
