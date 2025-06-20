#!/bin/bash
TARGET_DIR=$1
mkdir -p $TARGET_DIR/usr/bin
mkdir -p $TARGET_DIR/usr/bin/openssl_stress
mkdir -p $TARGET_DIR/usr/lib
cp -rf build/bin/openssl  $TARGET_DIR/usr/bin/openssl
cp -rf build/lib/libssl.so $TARGET_DIR/usr/lib/
cp -rf build/lib/libssl.so.3 $TARGET_DIR/usr/lib/
cp -rf build/lib/libcrypto.so $TARGET_DIR/usr/lib/
cp -rf build/lib/libcrypto.so.3 $TARGET_DIR/usr/lib/
cp -rf _run_stress.sh $TARGET_DIR/usr/bin/openssl_stress
cp -rf run_stress.sh $TARGET_DIR/usr/bin/openssl_stress
