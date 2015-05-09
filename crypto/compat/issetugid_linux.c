/*
 * issetugid implementation for Linux
 * Public domain
 */

#include <errno.h>
#include <gnu/libc-version.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Linux-specific glibc 2.16+ interface for determining if a process was
 * launched setuid/setgid or with additional capabilities.
 */
#ifdef HAVE_GETAUXVAL
#include <sys/auxv.h>
#endif

int issetugid(void)
{
#ifdef HAVE_GETAUXVAL
	/*
	 * The API for glibc < 2.19 does not indicate if there is an error with
	 * getauxval. While it should not be the case that any 2.6 or greater
	 * kernel ever does not supply AT_SECURE, an emulated software environment
	 * might rewrite the aux vector.
	 *
	 * See https://sourceware.org/bugzilla/show_bug.cgi?id=15846
	 *
	 * Perhaps this code should just read the aux vector itself, so we have
	 * backward-compatibility and error handling in older glibc versions.
	 * info: http://lwn.net/Articles/519085/
	 *
	 */
	const char *glcv = gnu_get_libc_version();
	if (strverscmp(glcv, "2.19") >= 0) {
		errno = 0;
		if (getauxval(AT_SECURE) == 0) {
			if (errno != ENOENT) {
				return 0;
			}
		}
	}
#endif
	return 1;
}
