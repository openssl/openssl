#!/bin/bash
# Cross-compile environment for Android on ARMv7 and x86
#
# Contents licensed under the terms of the OpenSSL license
# http://www.openssl.org/source/license.html
#
# See http://wiki.openssl.org/index.php/FIPS_Library_and_Android
#   and http://wiki.openssl.org/index.php/Android

#####################################################################

# Set ANDROID_NDK_ROOT to you NDK location. For example,
# /opt/android-ndk-r8e or /opt/android-ndk-r9. This can be done in a
# login script. If ANDROID_NDK_ROOT is not specified, the script will
# try to pick it up with the value of _ANDROID_NDK_ROOT below. If
# ANDROID_NDK_ROOT is set, then the value is ignored.
# _ANDROID_NDK="android-ndk-r8e"
# _ANDROID_NDK="android-ndk-r9"
# _ANDROID_NDK="android-ndk-r10"

# Set _ANDROID_APP_ABI to one of the supported APP ABIs. It is the same
# that you would assign to APP_ABI variable in Application.mk for Android NDK.
# _ANDROID_APP_ABI="armeabi"
_ANDROID_APP_ABI="armeabi-v7a"
# _ANDROID_APP_ABI="mips"
# _ANDROID_APP_ABI="x86"

# Set _ANDROID_ARCH to the architecture you are building for.
# Set it to the empty string if you want _ANDROID_ARCH to be
# figured out from _ANDROID_APP_ABI.
# This value is always used.
# _ANDROID_ARCH=arch-arm
# _ANDROID_ARCH=arch-mips
# _ANDROID_ARCH=arch-x86
_ANDROID_ARCH=""

# Set Android toolchain version. You can find the list of available
# toolchains in $ANDROID_NDK_ROOT/toolchains. Toolchain version is
# a suffix of a directory containing the toolchain.
# Typical values are "4.6", "4.8", # "clang3.3", "clang3.4".
_ANDROID_TOOLCHAIN_VERSION="4.6"

# Set _ANDROID_EABI to the EABI you want to use. You can find the
# list in $ANDROID_NDK_ROOT/toolchains.
# Set it to the empty string if you want _ANDROID_EABI to be
# figured out from _ANDROID_APP_ABI and _ANDROID_TOOLCHAIN_VERSION.
# _ANDROID_EABI="arm-linux-androideabi-4.6"
# _ANDROID_EABI="mipsel-linux-android-4.6"
# _ANDROID_EABI="x86-4.6"
_ANDROID_EABI=""

# Set _ANDROID_API to the API version you want to use.
_ANDROID_API="android-19"

#####################################################################

# If the user did not specify the NDK location, try and pick it up.
# We expect something like ANDROID_NDK_ROOT=/opt/android-ndk-r8e
# or ANDROID_NDK_ROOT=/usr/local/android-ndk-r8e.

if [ -z "$ANDROID_NDK_ROOT" ]; then

  _ANDROID_NDK_ROOT=""
  if [ -z "$_ANDROID_NDK_ROOT" ] && [ -d "/usr/local/$_ANDROID_NDK" ]; then
    _ANDROID_NDK_ROOT="/usr/local/$_ANDROID_NDK"
  fi

  if [ -z "$_ANDROID_NDK_ROOT" ] && [ -d "/opt/$_ANDROID_NDK" ]; then
    _ANDROID_NDK_ROOT="/opt/$_ANDROID_NDK"
  fi

  if [ -z "$_ANDROID_NDK_ROOT" ] && [ -d "$HOME/$_ANDROID_NDK" ]; then
    _ANDROID_NDK_ROOT="$HOME/$_ANDROID_NDK"
  fi

  if [ -z "$_ANDROID_NDK_ROOT" ] && [ -d "$PWD/$_ANDROID_NDK" ]; then
    _ANDROID_NDK_ROOT="$PWD/$_ANDROID_NDK"
  fi

  # If a path was set, then export it
  if [ ! -z "$_ANDROID_NDK_ROOT" ] && [ -d "$_ANDROID_NDK_ROOT" ]; then
    export ANDROID_NDK_ROOT="$_ANDROID_NDK_ROOT"
  fi
fi

# Error checking
# ANDROID_NDK_ROOT should always be set by the user (even when not running this script)
# http://groups.google.com/group/android-ndk/browse_thread/thread/a998e139aca71d77
if [ -z "$ANDROID_NDK_ROOT" ] || [ ! -d "$ANDROID_NDK_ROOT" ]; then
  echo "Error: ANDROID_NDK_ROOT is not a valid path. Please edit this script."
  # echo "$ANDROID_NDK_ROOT"
  # exit 1
fi

# Error checking
if [ ! -d "$ANDROID_NDK_ROOT/toolchains" ]; then
  echo "Error: ANDROID_NDK_ROOT/toolchains is not a valid path. Please edit this script."
  # echo "$ANDROID_NDK_ROOT/toolchains"
  # exit 1
fi

# Figure out _ANDROID_EABI from _ANDROID_APP_ABI and _ANDROID_TOOLCHAIN_VERSION.
if [ -z "$_ANDROID_EABI" ]
then
  case $_ANDROID_APP_ABI in
    armeabi|armeabi-v7a)  _ANDROID_EABI="arm-linux-androideabi-$_ANDROID_TOOLCHAIN_VERSION";;
    mips)                 _ANDROID_EABI="mipsel-linux-android-$_ANDROID_TOOLCHAIN_VERSION";;
    x86)                  _ANDROID_EABI="x86-$_ANDROID_TOOLCHAIN_VERSION";;
    *) echo "Error: _ANDROID_APP_ABI is not valid. Please edit the script.";;
  esac
fi


# Error checking
if [ ! -d "$ANDROID_NDK_ROOT/toolchains/$_ANDROID_EABI" ]; then
  echo "Error: ANDROID_EABI is not a valid path. Please edit this script."
  # echo "$ANDROID_NDK_ROOT/toolchains/$_ANDROID_EABI"
  # exit 1
fi

#####################################################################

# Based on ANDROID_NDK_ROOT, try and pick up the required toolchain. We expect something like:
# /opt/android-ndk-r83/toolchains/arm-linux-androideabi-4.7/prebuilt/linux-x86_64/bin
# Once we locate the toolchain, we add it to the PATH. Note: this is the 'hard way' of
# doing things according to the NDK documentation for Ice Cream Sandwich.
# https://android.googlesource.com/platform/ndk/+/ics-mr0/docs/STANDALONE-TOOLCHAIN.html

ANDROID_TOOLCHAIN=""
for host in "linux-x86_64" "linux-x86" "darwin-x86_64" "darwin-x86"
do
  if [ -d "$ANDROID_NDK_ROOT/toolchains/$_ANDROID_EABI/prebuilt/$host/bin" ]; then
    ANDROID_TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/$_ANDROID_EABI/prebuilt/$host/bin"
    break
  fi
done

# Error checking
if [ -z "$ANDROID_TOOLCHAIN" ] || [ ! -d "$ANDROID_TOOLCHAIN" ]; then
  echo "Error: ANDROID_TOOLCHAIN is not valid. Please edit this script."
  # echo "$ANDROID_TOOLCHAIN"
  # exit 1
fi

# Figure out _ANDROID_ARCH from _ANDROID_APP_ABI.
if [ -z "$_ANDROID_ARCH" ]
then
  case $_ANDROID_APP_ABI in
    armeabi|armeabi-v7a)  _ANDROID_ARCH="arch-arm";;
    mips)                 _ANDROID_ARCH="arch-mips";;
    x86)                  _ANDROID_ARCH="arch-x86";;
    *) echo "Error: _ANDROID_APP_ABI is not valid. Please edit the script.";;
  esac
fi

ANDROID_TOOLS=""
case $_ANDROID_ARCH in
  arch-arm)   ANDROID_TOOLS="arm-linux-androideabi-gcc arm-linux-androideabi-ranlib arm-linux-androideabi-ld";;
  arch-mips)  ANDROID_TOOLS=" mipsel-linux-android-gcc  mipsel-linux-android-ranlib  mipsel-linux-android-ld";;
  arch-x86)   ANDROID_TOOLS="   i686-linux-android-gcc    i686-linux-android-ranlib    i686-linux-android-ld";;
  *) echo "Error: _ANDROID_ARCH is not valid. Please edit the script.";;
esac

for tool in $ANDROID_TOOLS
do
  # Error checking
  if [ ! -e "$ANDROID_TOOLCHAIN/$tool" ]; then
    echo "Error: Failed to find $tool. Please edit this script."
    # echo "$ANDROID_TOOLCHAIN/$tool"
    # exit 1
  fi
done

# Only modify/export PATH if ANDROID_TOOLCHAIN good
if [ ! -z "$ANDROID_TOOLCHAIN" ]; then
  export ANDROID_TOOLCHAIN="$ANDROID_TOOLCHAIN"
  export PATH="$ANDROID_TOOLCHAIN":"$PATH"
fi

#####################################################################

# For the Android SYSROOT. Can be used on the command line with --sysroot
# https://android.googlesource.com/platform/ndk/+/ics-mr0/docs/STANDALONE-TOOLCHAIN.html
export ANDROID_SYSROOT="$ANDROID_NDK_ROOT/platforms/$_ANDROID_API/$_ANDROID_ARCH"
export SYSROOT="$ANDROID_SYSROOT"
export NDK_SYSROOT="$ANDROID_SYSROOT"

# Error checking
if [ -z "$ANDROID_SYSROOT" ] || [ ! -d "$ANDROID_SYSROOT" ]; then
  echo "Error: ANDROID_SYSROOT is not valid. Please edit this script."
  # echo "$ANDROID_SYSROOT"
  # exit 1
fi

#####################################################################

# If the user did not specify the FIPS_SIG location, try and pick it up
# If the user specified a bad location, then try and pick it up too.
if [ -z "$FIPS_SIG" ] || [ ! -e "$FIPS_SIG" ]; then

  # Try and locate it
  _FIPS_SIG=""
  if [ -d "/usr/local/ssl/$_ANDROID_API" ]; then
    _FIPS_SIG=`find "/usr/local/ssl/$_ANDROID_API" -name incore`
  fi

  if [ ! -e "$_FIPS_SIG" ]; then
    _FIPS_SIG=`find $PWD -name incore`
  fi

  # If a path was set, then export it
  if [ ! -z "$_FIPS_SIG" ] && [ -e "$_FIPS_SIG" ]; then
    export FIPS_SIG="$_FIPS_SIG"
  fi
fi

# Error checking. Its OK to ignore this if you are *not* building for FIPS
if [ -z "$FIPS_SIG" ] || [ ! -e "$FIPS_SIG" ]; then
  : # echo "Error: FIPS_SIG does not specify incore module. Please edit this script."
  # echo "$FIPS_SIG"
  # exit 1
fi

#####################################################################

# Set variables for OpenSSL's "config" script.
export SYSTEM=android
export RELEASE=unknown

case $_ANDROID_APP_ABI in
  armeabi)
    export MACHINE=armv5
    export ARCH=arm
    export CROSS_COMPILE="arm-linux-androideabi-"
    ;;
  armeabi-v7a)
    export MACHINE=armv7
    export ARCH=arm
    export CROSS_COMPILE="arm-linux-androideabi-"
    ;;
  mips)
    export MACHINE=mipsel
    export ARCH=mips32
    export CROSS_COMPILE="mipsel-linux-android-"
    ;;
  x86)
    export MACHINE=i686
    export ARCH=x86
    export CROSS_COMPILE="i686-linux-android-"
    ;;
  *) echo "Error: _ANDROID_APP_ABI is not valid. Please edit the script.";;
esac



# For the Android toolchain
# https://android.googlesource.com/platform/ndk/+/ics-mr0/docs/STANDALONE-TOOLCHAIN.html
export ANDROID_SYSROOT="$ANDROID_NDK_ROOT/platforms/$_ANDROID_API/$_ANDROID_ARCH"
export SYSROOT="$ANDROID_SYSROOT"
export NDK_SYSROOT="$ANDROID_SYSROOT"
export ANDROID_NDK_SYSROOT="$ANDROID_SYSROOT"
export ANDROID_API="$_ANDROID_API"

# CROSS_COMPILE and ANDROID_DEV are DFW (Don't Fiddle With). Its used by OpenSSL build system.
# export CROSS_COMPILE="arm-linux-androideabi-"
export ANDROID_DEV="$ANDROID_NDK_ROOT/platforms/$_ANDROID_API/$_ANDROID_ARCH/usr"
export HOSTCC=gcc

VERBOSE=1
if [ ! -z "$VERBOSE" ] && [ "$VERBOSE" != "0" ]; then
  echo "ANDROID_NDK_ROOT: $ANDROID_NDK_ROOT"
  echo "_ANDROID_ARCH: $_ANDROID_ARCH"
  echo "_ANDROID_APP_ABI: $_ANDROID_APP_ABI"
  echo "_ANDROID_TOOLCHAIN_VERSION: $_ANDROID_TOOLCHAIN_VERSION"
  echo "_ANDROID_EABI: $_ANDROID_EABI"
  echo "ANDROID_API: $ANDROID_API"
  echo "ANDROID_SYSROOT: $ANDROID_SYSROOT"
  echo "ANDROID_TOOLCHAIN: $ANDROID_TOOLCHAIN"
  echo "FIPS_SIG: $FIPS_SIG"
  echo "CROSS_COMPILE: $CROSS_COMPILE"
  echo "ANDROID_DEV: $ANDROID_DEV"
fi
