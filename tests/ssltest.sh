#!/bin/sh
set -e
export PATH=../apps:$PATH
$srcdir/testssl $srcdir/server.pem $srcdir/server.pem $srcdir/ca.pem
