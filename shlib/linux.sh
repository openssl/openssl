#!/bin/sh

echo "#define DATE      \"`date`\"" >crypto/date.h

major="0"
minor="8.2"
slib=libssl
clib=libcrypto
CC=gcc
CPP='gcc -E'
AS=as
FLAGS='-DX86_ASM -DTERMIO -O3 -DL_ENDIAN -fomit-frame-pointer -m486 -Wall'
#FLAGS='-DTERMIO -g2 -ggdb -DL_ENDIAN -m486 -Wall -DREF_CHECK -DCRYPTO_MDEBUG'
INCLUDE='-Iinclude -Icrypto -Issl'
SHFLAGS='-DPIC -fpic'

CFLAGS="$FLAGS $INCLUDE $SHFLAGS"
ASM_OBJ="";

echo compiling bignum assember
$CPP -DELF crypto/bn/asm/bn86unix.cpp | $AS -o bn_asm.o
CFLAGS="$CFLAGS -DBN_ASM -DX86_ASM"
ASM_OBJ="$ASM_OBJ bn_asm.o"

echo compiling des assember
$CPP -DELF crypto/des/asm/dx86unix.cpp | $AS -o des_enc.o
$CPP -DELF crypto/des/asm/yx86unix.cpp | $AS -o fcrypt-b.o
CFLAGS="$CFLAGS -DDES_ASM"
ASM_OBJ="$ASM_OBJ des_enc.o fcrypt-b.o"

echo compiling blowfish assember
$CPP -DELF crypto/bf/asm/bx86unix.cpp | $AS -o bf_enc.o
CFLAGS="$CFLAGS -DBF_ASM"
ASM_OBJ="$ASM_OBJ bf_enc.o"

echo compiling cast assember
$CPP -DELF crypto/cast/asm/cx86unix.cpp | $AS -o cast_enc.o
CFLAGS="$CFLAGS -DCAST_ASM"
ASM_OBJ="$ASM_OBJ cast_enc.o"

echo compiling rc4 assember
$CPP -DELF crypto/rc4/asm/rx86unix.cpp | $AS -o rc4_enc.o
CFLAGS="$CFLAGS -DRC4_ASM"
ASM_OBJ="$ASM_OBJ rc4_enc.o"

echo compiling md5 assember
$CPP -DELF crypto/md5/asm/mx86unix.cpp | $AS -o md5_enc.o
CFLAGS="$CFLAGS -DMD5_ASM"
ASM_OBJ="$ASM_OBJ md5_enc.o"

echo compiling sha1 assember
$CPP -DELF crypto/sha/asm/sx86unix.cpp | $AS -o sha1_enc.o
CFLAGS="$CFLAGS -DSHA1_ASM"
ASM_OBJ="$ASM_OBJ sha1_enc.o"

echo compiling $clib
$CC -c $CFLAGS -DCFLAGS="\"$FLAGS\"" -o crypto.o crypto/crypto.c

echo linking $clib.so
gcc $CFLAGS -shared -Wl,-soname,$clib.so.$major -o $clib.so.$major.$minor crypto.o $ASM_OBJ
/bin/rm -f $clib.so $clib.so.$major
ln -s $clib.so.$major.$minor $clib.so
ln -s $clib.so.$major.$minor $clib.so.$major

echo compiling $slib.so
$CC -c $CFLAGS -o ssl.o ssl/ssl.c

echo building $slib.so
gcc $CFLAGS -shared -Wl,-soname,$slib.so.$major -o $slib.so.$major.$minor ssl.o
/bin/rm -f $slib.so $slib.so.$major
ln -s $slib.so.$major.$minor $slib.so
ln -s $slib.so.$major.$minor $slib.so.$major

echo building ssleay executable
gcc $CFLAGS -o ssleay apps/eay.c -L. -lssl -lcrypto

