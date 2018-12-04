#!/bin/bash
# by KangLin(kl222@126.com)

set -e

cd $1

PROJECT_DIR=`pwd`

cd ${PROJECT_DIR}
mkdir build
cd build

OPENSSL_BUILD_PREFIX=${PROJECT_DIR}/setup

echo "Configuration: $Configuration; Platform: $Platform"

if [ "$Configuration" = "shared" ]; then
    MODE=shared
else
    MODE="no-shared no-pic"
fi

case ${BUILD_TARGERT} in
    windows_msvc)
        pacman -S --noconfirm nasm
        export PATH=/c/Perl/site/bin:/c/Perl/bin:$PATH
        rm /usr/bin/link
        if [ "${Platform}" = "64" -o "${Platform}" = "x64" -o "${Platform}" = "X64" ]; then
            TARGET=VC-WIN64A-masm
            if [ $TOOLCHAIN_VERSION -le 11 ]; then
                echo "MSVC $TOOLCHAIN_VERSION don't support x64"
                cd ${PROJECT_DIR}
                exit 0
            fi
        else
            TARGET=VC-WIN32
        fi
        MAKE="nmake"
    ;;

esac

echo "PATH:$PATH"

perl ../Configure \
    --prefix=${OPENSSL_BUILD_PREFIX} \
    --openssldir=${OPENSSL_BUILD_PREFIX} \
    ${MODE} ${TARGET} ${CONFIG_PARA}

perl configdata.pm --dump

echo "${MAKE} build_all_generated"
${MAKE} build_all_generated


echo "${MAKE} test"
${MAKE} test V=1


echo "${MAKE} install"
${MAKE} install

cd ${PROJECT_DIR}
