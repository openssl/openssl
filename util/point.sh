#!/bin/sh

rm -f $2
ln -s $1 $2
echo "$2 => $1"

