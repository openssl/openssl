#!/bin/bash
# by KangLin(kl222@126.com)

set -e

cd $1

PROJECT_DIR=`pwd`

cd ${PROJECT_DIR}
mkdir build
cd build

OPENSSL_BUILD_PREFIX=${PROJECT_DIR}/setup

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
        if [ "${Platform}" = "x64" ]; then
            TARGET=VC-WIN64A-masm
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
echo "${MAKE}" # build_all_generated"
${MAKE} #build_all_generated
echo "${MAKE} test"
if [ "${BUILD_TARGERT}" != "android" ]; then
    ${MAKE} test V=1
fi
echo "${MAKE} install"
${MAKE} install

cd ${PROJECT_DIR}
