#!/bin/bash
TARGET_DIR=$1
mkdir -p $TARGET_DIR/usr/bin
cp -rf apps/openssl  $TARGET_DIR/usr/bin
