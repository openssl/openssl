/* e_os2.h */

#ifndef HEADER_E_OS2_H
#define HEADER_E_OS2_H

#include <openssl/opensslconf.h> /* OPENSSL_UNISTD */

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef MSDOS
# define OPENSSL_UNISTD_IO <io.h>
# define OPENSSL_DECLARE_EXIT extern void exit(int);
#else
# define OPENSSL_UNISTD_IO OPENSSL_UNISTD
# define OPENSSL_DECLARE_EXIT /* declared in unistd.h */
#endif

/* Definitions of OPENSSL_GLOBAL and OPENSSL_EXTERN, to define and declare
   certain global symbols that, with some compilers under VMS, have to be
   defined and declared explicitely with globaldef and globalref.
   Definitions of OPENSSL_EXPORT and OPENSSL_IMPORT, to define and declare
   DLL exports and imports for compilers under Win32.  These are a little
   more complicated to use.  Basically, for any library that exports some
   global variables, the following code must be present in the header file
   that declares them, before OPENSSL_EXTERN is used:

   #ifdef SOME_BUILD_FLAG_MACRO
   # undef OPENSSL_EXTERN
   # define OPENSSL_EXTERN OPENSSL_EXPORT
   #endif

   The default is to have OPENSSL_EXPORT, OPENSSL_IMPORT and OPENSSL_GLOBAL
   have some generally sensible values, and for OPENSSL_EXTERN to have the
   value OPENSSL_IMPORT.
*/

#if defined(VMS) && !defined(__DECC)
# define OPENSSL_EXPORT globalref
# define OPENSSL_IMPORT globalref
# define OPENSSL_GLOBAL globaldef
#elif defined(WINDOWS)
# define OPENSSL_EXPORT extern _declspec(dllexport)
# define OPENSSL_IMPORT extern _declspec(dllimport)
# define OPENSSL_GLOBAL
#else
# define OPENSSL_EXPORT extern
# define OPENSSL_IMPORT extern
# define OPENSSL_GLOBAL
#endif
#define OPENSSL_EXTERN OPENSSL_IMPORT

#ifdef  __cplusplus
}
#endif
#endif
