#!/bin/bash
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You can obtain a copy in the file LICENSE in the source distribution
# or at https://www.openssl.org/source/license.html
#
# Script to analyze logs produced by REPORT_RWLOCK_CONTENTION
# Usage: ./analyze-contention-log.sh <logfile>
###################################################################

#
# Setup a temp directory to massage our log file
#
TEMPDIR=$(mktemp -d /tmp/contention.XXXXXX)

LOGFILE=$1
trap "rm -rf $TEMPDIR" EXIT

if [ ! -f $LOGFILE ]
then
    echo "No log file found"
    exit 1
fi
LOGFILEBASE=$(basename $LOGFILE)

echo "Splitting files"

#
#start by splitting the log into separate stack traces
#
mkdir $TEMPDIR/individual_files
cp $LOGFILE $TEMPDIR/individual_files/$LOGFILEBASE
pushd $TEMPDIR/individual_files/ > /dev/null
awk '
    BEGIN {RS = ""; FS = "\n"}
    {file_num++; print > ("stacktrace" file_num ".txt")}' ./$LOGFILEBASE
popd > /dev/null
rm $TEMPDIR/individual_files/$LOGFILEBASE

#
# Make some associative arrays to track our stats
#
declare -A filenames
declare -A total_latency
declare -A latency_counts

echo "Gathering latencies"
FILECOUNT=$(ls $TEMPDIR/individual_files/stacktrace*.* | wc -l)
let currentidx=0

#
# Look at every stack trace, get and record its latency, and hash value
#
for i in $(ls $TEMPDIR/individual_files/stacktrace*.*)
do
    LATENCY=$(awk '{print $6}' $i)
    #drop the non-stacktrace line
    sed -i -e"s/lock blocked on.*//" $i
    #now compute its sha1sum
    SHA1SUM=$(sha1sum $i | awk '{print $1}')
    filenames["$SHA1SUM"]=$i
    let CUR_LATENCY=0
    let LATENCY_COUNT=0

    #
    # If we already have a latency total for this hash value
    # fetch it from the total_latency array, along with 
    # the number of times we've encountered this hash
    #
    if [[ -v total_latency["$SHA1SUM"] ]]
    then
        let CUR_LATENCY=${total_latency["$SHA1SUM"]}
        let LATENCY_COUNT=${latency_counts["$SHA1SUM"]}
    fi

    #
    # Add this files latency to the hashes total latency amount
    # and increment its associated count by 1
    #
    total_latency["$SHA1SUM"]=$(dc -e "$CUR_LATENCY $LATENCY + p")
    latency_counts["$SHA1SUM"]=$(dc -e "$LATENCY_COUNT 1 + p")
    echo -e -n "FILE $currentidx/$FILECOUNT \r"
    let currentidx=$currentidx+1
done

#
# Write out each latency in the hash array to a file named after its total latency
#
mkdir $TEMPDIR/sorted_latencies/
for i in ${!total_latency[@]}
do
    TOTAL=${total_latency[$i]}
    COUNT=${latency_counts[$i]}
    FNAME=${filenames[$i]}
    AVG=$(dc -e "6 k $TOTAL $COUNT / p")
    echo "Total latency $TOTAL usec, count $COUNT (avg $AVG usec)" >> $TEMPDIR/sorted_latencies/$TOTAL.txt
    cat $FNAME >> $TEMPDIR/sorted_latencies/$TOTAL.txt
done

#
# Now because we have our cumulative latencies recorded in files named
# after their total cumulative latency, we can easily do a numerical
# sort on them in reverse order to display them from greatest to least
#
echo "Top latencies"
for i in $(ls $TEMPDIR/sorted_latencies/ | sort -n -r)
do
    echo "============================================="
    cat $TEMPDIR/sorted_latencies/$i
    echo ""
done

