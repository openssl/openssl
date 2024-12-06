#!/bin/bash
TARGET_DIR=$1
mkdir -p $TARGET_DIR
cp -rf apps/openssl  $TARGET_DIR/usr/bin/openssl
cp -rf  libssl.so $TARGET_DIR/usr/lib/
cp -rf  libssl.so.3 $TARGET_DIR/usr/lib/
cp -rf  libcrypto.so $TARGET_DIR/usr/lib/
cp -rf  libcrypto.so.3 $TARGET_DIR/usr/lib/
