#!/bin/bash

# This script outputs kex memory benchmarks using valgrind

DEFAULT_TMP_DIR=/tmp
TMP_DIR=$DEFAULT_TMP_DIR
ALGORITHMS=""
ROOT_DIR=`dirname $0`
TEST_KEX_CMD=$ROOT_DIR/test_kex

#check for installed programs
for prog in valgrind ms_print $TEST_KEX_CMD
do
  command -v $prog >/dev/null 2>&1 || { echo >&2 "Command $prog was not found.  Aborting."; exit 1; }
done


#parse arguments
for arg in "$@"
do
  case $arg in
    -tmp-dir=*|-t=*)
      TMP_DIR="${arg#*=}"
      shift
      ;;
    *)
      ALGORITHMS="$ALGORITHMS $arg"
      ;;
  esac
done


function print_help {
cat << EOF
Usage: $0 [OPTION]... ALGORITHM

  --tmp-dir=DIR       temporary directory [default: $DEFAULT_TMP_DIR]
    ALGORITHM         algorithm to test

Example usage: $0 ntru

EOF
  exit 0
}

if [[ ! -d $TMP_DIR ]]; then
  print_help
fi

TMP_FILE_NAME="oqs_mem_bench"
TMP_FILE_PATH=$TMP_DIR/$TMP_FILE_NAME

rm -f $TMP_FILE_PATH
valgrind --tool=massif --massif-out-file=$TMP_FILE_PATH $TEST_KEX_CMD -m $ALGORITHMS
ms_print $TMP_FILE_PATH
rm -f $TMP_FILE_PATH



