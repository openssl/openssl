#!/bin/sh
set -e
./pq_test | cmp $srcdir/pq_expected.txt /dev/stdin
