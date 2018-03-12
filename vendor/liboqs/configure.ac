#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Init
AC_INIT([liboqs], [1.0.0], [])
LT_INIT([disable-shared])
AM_INIT_AUTOMAKE([subdir-objects no-dependencies])

# Configure
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/ds_benchmark.h])
AC_CONFIG_MACRO_DIRS([config])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AS

# Checks for libraries.
AC_ARG_WITH(
  [openssl-dir],
  AS_HELP_STRING([--with-openssl-dir=dir],[openssl dir used locally (default /usr).]),
  [AC_DEFINE_UNQUOTED(OPENSSLDIR, [$withval], [OPENSSL DIR used locally])
   AC_SUBST(OPENSSL_DIR, [$withval])],
  [AC_SUBST(OPENSSL_DIR, /usr)]
)
AC_ARG_WITH(
  [gmp-dir],
  AS_HELP_STRING([--with-gmp-dir=dir],[gmp dir used locally (default /usr).]),
  [AC_DEFINE_UNQUOTED(GMPDIR, [$withval], [GMP DIR used locally])
   AC_SUBST(GMP_DIR, [$withval])],
  [AC_SUBST(GMP_DIR, /usr)]
)
AC_ARG_WITH(
  [sodium-dir],
  AS_HELP_STRING([--with-sodium-dir=dir],[sodium dir used locally (default /usr).]),
  [AC_DEFINE_UNQUOTED(SODIUMDIR, [$withval], [SODIUM DIR used locally])
   AC_SUBST(SODIUM_DIR, [$withval])],
  [AC_SUBST(SODIUM_DIR, /usr)]
)
AC_ARG_WITH(
  [m4ri-dir],
  AS_HELP_STRING([--with-m4ri-dir=dir],[m4ri dir used locally (default /usr).]),
  [AC_DEFINE_UNQUOTED(M4RIDIR, [$withval], [M4RI DIR used locally])
   AC_SUBST(M4RI_DIR, [$withval])],
  [AC_SUBST(M4RI_DIR, /usr)]
)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h stddef.h stdint.h stdlib.h string.h strings.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memmove memset pow sqrt strdup])
AC_CHECK_SIZEOF([size_t])

# Silent rules
#m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

######################################################################
# DOXYGEN SUPPORT
######################################################################
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN([$PACKAGE_NAME],[doxygen.cfg])
######################################################################

ARG_DISBL_SET([aes-ni], [enable AES-NI.])
AM_CONDITIONAL([aes_ni], [test "x$aes_ni" = xtrue]) # disabled on ARM below
AM_CONDITIONAL([USE_AES_NI], [test "x$aes_ni" = xtrue])

ARG_ENABL_SET([openssl], [enable OPENSSL.])
AM_CONDITIONAL([openssl], [test "x$openssl" = xtrue])
AM_CONDITIONAL([USE_OPENSSL], [test "x$openssl" = xtrue])

ARG_ENABL_SET([kex-code-mcbits], [enable KEX-CODE-MCBITS.])
AM_CONDITIONAL([kex_code_mcbits], [test "x$kex_code_mcbits" = xtrue])
AM_CONDITIONAL([USE_MCBITS], [test "x$kex_code_mcbits" = xtrue])

ARG_ENABL_SET([kex-sidh-iqc-ref], [enable KEX-SIDH-IQC-REF.])
AM_CONDITIONAL([kex_sidh_iqc_ref], [test "x$kex_sidh_iqc_ref" = xtrue])
AM_CONDITIONAL([USE_SIDH_IQC], [test "x$kex_sidh_iqc_ref" = xtrue])

ARG_DISBL_SET([kex-lwe-frodo], [disable KEX-LWE-FRODO.])
AM_CONDITIONAL([kex_lwe_frodo], [test "x$kex_lwe_frodo" = xtrue])
AM_CONDITIONAL([USE_KEX_LWE_FRODO], [test "x$kex_lwe_frodo" = xtrue])

ARG_DISBL_SET([kex-ntru], [disable KEX-NTRU.])
AM_CONDITIONAL([kex_ntru], [test "x$kex_ntru" = xtrue])
AM_CONDITIONAL([USE_KEX_NTRU], [test "x$kex_ntru" = xtrue])

ARG_DISBL_SET([kex-rlwe-msrln16], [disable KEX-RLWE-MSRLN16.])
AM_CONDITIONAL([kex_rlwe_msrln16], [test "x$kex_rlwe_msrln16" = xtrue])
AM_CONDITIONAL([USE_KEX_RLWE_MSRLN16], [test "x$kex_rlwe_msrln16" = xtrue])

ARG_DISBL_SET([kex-rlwe-newhope], [disable KEX-RLWE-NEWHOPE.])
AM_CONDITIONAL([kex_rlwe_newhope], [test "x$kex_rlwe_newhope" = xtrue])
AM_CONDITIONAL([USE_KEX_RLWE_NEWHOPE], [test "x$kex_rlwe_newhope" = xtrue])

ARG_DISBL_SET([kex-sidh-msr], [disable KEX-SIDH-MSR.])
AM_CONDITIONAL([kex_sidh_msr], [test "x$kex_sidh_msr" = xtrue])
AM_CONDITIONAL([USE_KEX_SIDH_MSR], [test "x$kex_sidh_msr" = xtrue])

ARG_DISBL_SET([sig-picnic], [disable SIG-PICNIC.])
AM_CONDITIONAL([sig_picnic], [test "x$sig_picnic" = xtrue])
AM_CONDITIONAL([USE_SIG_PICNIC], [test "x$sig_picnic" = xtrue])

ARG_ENABL_SET([kex-rlwe-newhope-avx2], [enable KEX-RLWE-NEWHOPE-AVX2.])
AM_CONDITIONAL([kex_rlwe_newhope_avx2], [test "x$kex_rlwe_newhope_avx2" = xtrue])
AM_CONDITIONAL([USE_KEX_RLWE_NEWHOPE_AVX2], [test "x$kex_rlwe_newhope_avx2" = xtrue])

AC_CANONICAL_HOST

# Check for which host we are on and setup a few things
# specifically based on the host
case $host_os in
  darwin* )
        darwin=true
        ;;
  linux-android*)
        AM_CFLAGS=${AM_CFLAGS}" -pie "
        linux=true
        ;;
  linux*)
        linux=true
        ;;
    *)
        #Default Case
        AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

AM_CONDITIONAL([ON_DARWIN], [test "x$darwin" = xtrue])

# Enable assembly optimizations here
# Appearenly asm optimizations do not work well with darwin
if test x"$linux" = x"true"; then
  case $host_cpu in
    x86_64* )
        AM_CPPFLAGS=${AM_CPPFLAGS}" -DSIDH_ASM -march=x86-64"
        x86_64=true
        ;;
    aarch64* )
        AM_CPPFLAGS=${AM_CPPFLAGS}" -DSIDH_ASM -march=armv8-a+crc"
        arm64=true
        ;;
    arm* )
        AM_CPPFLAGS=${AM_CPPFLAGS}" -DARM"
        AM_CONDITIONAL([aes_ni], [false])
        AM_CONDITIONAL([USE_AES_NI], [false])
        arm=true
        ;;
  esac
fi

AM_CONDITIONAL([X86_64], [test "x$x86_64" = xtrue])
AM_CONDITIONAL([ARM64], [test "x$arm64" = xtrue])
AM_CONDITIONAL([ARM], [test "x$arm" = xtrue])

# Common sources
SRCDIR=" src/common"

# Crypto sources
SRCDIR=${SRCDIR}" src/crypto/aes src/crypto/rand src/crypto/sha3 src/crypto/rand_urandom_aesctr src/crypto/rand_urandom_chacha20"

# KEX
SRCDIR=${SRCDIR}" src/kex"
SRCDIR=${SRCDIR}" src/kex_rlwe_bcns15"

if test x"$kex_lwe_frodo" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_lwe_frodo"
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_KEX_LWE_FRODO"
  AC_DEFINE(ENABLE_KEX_LWE_FRODO, 1, "Define to 1 when FRODO enabled")
fi

if test x"$kex_ntru" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_ntru"
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_KEX_NTRU"
  AC_DEFINE(ENABLE_KEX_NTRU, 1, "Define to 1 when NTRU enabled")
fi

if test x"$kex_rlwe_msrln16" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_rlwe_msrln16"
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_KEX_RLWE_MSRLN16"
  AC_DEFINE(ENABLE_KEX_RLWE_MSRLN16, 1, "Define to 1 when RLWE MSRLN16 enabled")
fi

if test x"$kex_rlwe_newhope" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_rlwe_newhope"
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_KEX_RLWE_NEWHOPE"
  AC_DEFINE(ENABLE_KEX_RLWE_NEWHOPE, 1, "Define to 1 when RLWE NEWHOPE enabled")
fi

if test x"$kex_sidh_msr" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_sidh_msr"
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_KEX_SIDH_MSR"
  AC_DEFINE(ENABLE_KEX_SIDH_MSR, 1, "Define to 1 when SIDH MSR enabled")
fi

# Conditional KEX
if test x"$kex_code_mcbits" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_code_mcbits"
fi
if test x"$kex_sidh_iqc_ref" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_sidh_iqc_ref"
fi

# SIG
SRCDIR=${SRCDIR}" src/sig"

if test x"$sig_picnic" = x"true"; then
  SRCDIR=${SRCDIR}" src/sig_picnic"
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_SIG_PICNIC"
  AC_DEFINE(ENABLE_SIG_PICNIC, 1, "Define to 1 when PICNIC enabled")
fi

# Flags
AM_CPPFLAGS=${AM_CPPFLAGS}" -g -std=gnu11 -Wno-unused-function -Werror -Wpedantic -Wall -Wextra -DCONSTANT_TIME"
# if test x"$aes_ni" = x"true" && test x"$ARM" = x"false"; then
if test -z "${aes_ni_TRUE}"; then
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DAES_ENABLE_NI"
fi
if test x"$openssl" = x"true"; then
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DUSE_OPENSSL"
fi
if test x"$kex_code_mcbits" = x"true"; then
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_CODE_MCBITS"
  AC_DEFINE(ENABLE_CODE_MCBITS, 1, "Define to 1 when MCBITS enabled")
fi
if test x"$kex_sidh_iqc_ref" = x"true"; then
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_SIDH_IQC_REF"
  SRCDIR=${SRCDIR}" src/kex_sidh_iqc_ref"
  AC_DEFINE(ENABLE_SIDH_IQC_REF, 1, "Define to 1 when SIDH IQC enabled")
fi

if test x"$kex_rlwe_newhope_avx2" = x"true"; then
  SRCDIR=${SRCDIR}" src/kex_rlwe_newhope/avx2"
  AM_CPPFLAGS=${AM_CPPFLAGS}" -DENABLE_KEX_RLWE_NEWHOPE_AVX2"
fi

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(SRCDIR)
AC_SUBST(USE_OPENSSL)
AC_SUBST(USE_AES_NI)
AC_SUBST(USE_KEX_NTRU)
AC_SUBST(USE_MCBITS)
AC_SUBST(USE_SIDH_IQC)
AC_SUBST(USE_KEX_LWE_FRODO)
AC_SUBST(USE_KEX_RLWE_MSRLN16)
AC_SUBST(USE_KEX_RLWE_NEWHOPE)
AC_SUBST(USE_KEX_SIDH_MSR)
AC_SUBST(USE_SIG_PICNIC)
AC_SUBST(ON_DARWIN)
AC_SUBST(X86_64)
AC_SUBST(USE_KEX_RLWE_NEWHOPE_AVX2)


AC_CONFIG_FILES([Makefile
                 src/common/Makefile
                 src/kex/Makefile
                 src/crypto/sha3/Makefile
                 src/crypto/rand/Makefile
                 src/crypto/rand_urandom_chacha20/Makefile
                 src/crypto/rand_urandom_aesctr/Makefile
                 src/crypto/aes/Makefile
                 src/kex_rlwe_bcns15/Makefile
                 src/kex_rlwe_newhope/Makefile
                 src/kex_rlwe_msrln16/Makefile
                 src/kex_sidh_msr/Makefile
                 src/kex_code_mcbits/Makefile
                 src/kex_ntru/Makefile
                 src/kex_sidh_iqc_ref/Makefile
                 src/kex_lwe_frodo/Makefile
                 src/sig/Makefile
                 src/sig_picnic/Makefile
                 src/kex_rlwe_newhope/avx2/Makefile])

AC_OUTPUT
