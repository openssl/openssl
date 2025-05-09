Notes for the DOS platform with DJGPP
=====================================

 OpenSSL has been ported to DJGPP, a Unix look-alike 32-bit run-time
 environment for 16-bit DOS, but only with long filename support.
 If you wish to compile on native DOS with 8+3 filenames, you will
 have to tweak the installation yourself, including renaming files
 with illegal or duplicate names.

 You should have a full DJGPP environment installed, including the
 latest versions of DJGPP, GCC, BINUTILS, BASH, etc. This package
 requires that PERL and the PERL module `Text::Template` also be
 installed (see [NOTES-PERL.md](NOTES-PERL.md)).

 All of these can be obtained from the usual DJGPP mirror sites or
 directly at <http://www.delorie.com/pub/djgpp>. For help on which
 files to download, see the DJGPP "ZIP PICKER" page at
 <http://www.delorie.com/djgpp/zip-picker.html>. You also need to have
 the WATT-32 networking package installed before you try to compile
 OpenSSL. This can be obtained from <http://www.watt-32.net/>.
 The Makefile assumes that the WATT-32 code is in the directory
 specified by the environment variable WATT_ROOT. If you have watt-32
 in directory `watt32` under your main DJGPP directory, specify
 `WATT_ROOT="/dev/env/DJDIR/watt32"`.

 To compile OpenSSL, start your BASH shell, then configure for DJGPP by
 running `./Configure` with appropriate arguments:

    ./Configure no-threads --prefix=/dev/env/DJDIR DJGPP

 And finally fire up `make`. You may run out of DPMI selectors when
 running in a DOS box under Windows. If so, just close the BASH
 shell, go back to Windows, and restart BASH. Then run `make` again.

Cross compilation
=================
 To cross compile OpenSSL, first export the necessary ENV variables,
 next compile Watt-32 and then configure for DJGPP by running
 `./Configure` with appropriate arguments. The following is an example
 for i386 targets using a DJGPP build on a Linux platform using
 <https://github.com/jwt27/build-gcc>. Make sure the cross compiler is
 in your PATH:

   export CROSS=i586-pc-msdosdjgpp
   export HOST=${CROSS}
   export CROSS_PLATFORM=i586-pc-msdosdjgpp-
   export CC=${CROSS_PLATFORM}gcc
   export CXX=${CROSS_PLATFORM}g++
   export AR=${CROSS_PLATFORM}ar
   export LD=${CROSS_PLATFORM}ld
   export LN=${CROSS_PLATFORM}gcc
   export STRIP=${CROSS_PLATFORM}strip
   export RANLIB=${CROSS_PLATFORM}ranlib

   cd <YOUR_BUILD_ROOT>/Watt-32/src
   make -f djgpp.mak
   cd <YOUR_BUILD_ROOT>/openssl
   ./Configure no-threads 386 no-sse2 no-shared --prefix="<YOUR_INSTALL_DIR>" DJGPP
   make
   make install


 RUN-TIME CAVEAT LECTOR
 --------------

 Quoting FAQ:

  "Cryptographic software needs a source of unpredictable data to work
   correctly.  Many open source operating systems provide a "randomness
   device" (`/dev/urandom` or `/dev/random`) that serves this purpose."

 As of version 0.9.7f DJGPP port checks upon `/dev/urandom$` for a 3rd
 party "randomness" DOS driver. One such driver, `NOISE.SYS`, can be
 obtained from <http://www.rahul.net/dkaufman/index.html>.
