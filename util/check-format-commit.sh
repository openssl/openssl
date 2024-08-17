#!/bin/bash
# Copyright 2020-2024 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You can obtain a copy in the file LICENSE in the source distribution
# or at https://www.openssl.org/source/license.html
#
# This script is a wrapper around check-format.pl.  It accepts the same commit
# revision range as 'git diff' as arguments, and uses it to identify the files
# and ranges that were changed in that range, filtering check-format.pl output
# only to lines that fall into the change ranges of the changed files.
#

# Allowlist of files to scan
# Currently this is any .c or .h file (with an optional .in suffix
FILE_ALLOWLIST=("\.[ch]\(.in\)\?")

# Exit code for the script
EXIT_CODE=0

# Global vars

# TEMPDIR is used to hold any files this script creates
# And is cleaned on EXIT with a trap function
TEMPDIR=$(mktemp -d /tmp/checkformat.XXXXXX)

# TOPDIR always points to the root of the git tree we are working in
# used to locate the check-format.pl script
TOPDIR=$(git rev-parse --show-toplevel)


# cleanup handler function, returns us to the root of the git tree
# and erases our temp directory
cleanup() {
    rm -rf $TEMPDIR
    cd $TOPDIR
}

trap cleanup EXIT

# Get the canonical sha256 sum for the commits we are checking
# This lets us pass in symbolic ref names like master/etc and 
# resolve them to sha256 sums easily
COMMIT_RANGE="$@"
COMMIT_LAST=$(git rev-parse $COMMIT_RANGE)

# Fail gracefully if git rev-parse doesn't produce a valid
# commit
if [ $? -ne 0 ]
then
    echo "$1 is not a valid revision"
    exit 1
fi

# If the commit range was just one single revision, git rev-parse
# will output jut commit id of that one alone.  In that case, we
# must manipulate a little to get a desirable result, 'cause git
# diff has a slightly different interpretation of a single commit
# id, and takes that to mean all commits up to HEAD.
if [ $(echo "$COMMIT_LAST" | wc -l) -gt 1 ]; then
    COMMIT_LAST=$(echo "$COMMIT_LAST" | head -1)
else
    # $COMMIT_RANGE is just one commit, make it an actual range
    COMMIT_RANGE=$COMMIT_RANGE^..$COMMIT_RANGE
fi

# Create an iterable list of files to check formatting on,
# including the line ranges that are changed by the commits
# It produces output of this format:
# <file name> <change start line>, <change line count>
touch $TEMPDIR/ranges.txt
git diff -U0 $COMMIT_RANGE | awk '
    BEGIN {myfile=""} 
    /+{3}/ {
        gsub(/b\//,"",$2);
        myfile=$2
    }
    /@@/ {
        gsub(/+/,"",$3);
        printf myfile " " $3 "\n"
    }' >> $TEMPDIR/ranges.txt || true

# filter in anything that matches on a filter regex
for i in ${FILE_ALLOWLIST[@]}
do
    touch $TEMPDIR/ranges.filter
    # Note the space after the $i below.  This is done because we want
    # to match on file suffixes, but the input file is of the form
    # <commit> <file> <range start>, <range length>
    # So we can't just match on end of line.  The additional space
    # here lets us match on suffixes followed by the expected space
    # in the input file
    grep "$i " $TEMPDIR/ranges.txt >> $TEMPDIR/ranges.filter || true
done
cp $TEMPDIR/ranges.filter $TEMPDIR/ranges.txt
REMAINING_FILES=$(wc -l <$TEMPDIR/ranges.filter)
if [ $REMAINING_FILES -eq 0 ]
then
    echo "This commit has no files that require checking"
    exit 0
fi

# check out the files from the commit level.
# For each file name in ranges, we show that file at the commit
# level we are checking, and redirect it to the same path, relative
# to $TEMPDIR/check-format.  This give us the full file to run
# check-format.pl on with line numbers matching the ranges in the
# $TEMPDIR/ranges.txt file
for j in $(awk '{print $1}' $TEMPDIR/ranges.txt | sort -u)
do
    FDIR=$(dirname $j)
    mkdir -p $TEMPDIR/check-format/$FDIR
    git show $COMMIT_LAST:$j > $TEMPDIR/check-format/$j
done

# Now for each file in $TEMPDIR/ranges.txt, run check-format.pl
for j in $(awk '{print $1}' $TEMPDIR/ranges.txt | sort -u)
do
    range_start=()
    range_end=()

    # Get the ranges for this file. Create 2 arrays.  range_start contains
    # the start lines for valid ranges from the commit.  the range_end array
    # contains the corresponding end line (note, since diff output gives us
    # a line count for a change, the range_end[k] entry is actually
    # range_start[k]+line count
    for k in $(grep ^$j $TEMPDIR/ranges.txt | awk '{print $2}')
    do
        RANGE=$k
        RSTART=$(echo $RANGE | awk -F',' '{print $1}')
        RLEN=$(echo $RANGE | awk -F',' '{print $2}')
        # when the hunk is just one line, its length is implied
        if [ -z "$RLEN" ]; then RLEN=1; fi
        let REND=$RSTART+$RLEN
        range_start+=($RSTART)
        range_end+=($REND)
    done

    # Go to our checked out tree
    cd $TEMPDIR/check-format

    # Actually run check-format.pl on the file, capturing the output
    # in a temporary file.  Note the format of check-patch.pl output is
    # <file name>:<line number>:<error text>:<offending line contents>
    $TOPDIR/util/check-format.pl $j > $TEMPDIR/format-results.txt

    # Now we filter the check-format.pl output based on the changed lines
    # captured in the range_start/end arrays
    let maxidx=${#range_start[@]}-1
    for k in $(seq 0 1 $maxidx)
    do
        RSTART=${range_start[$k]}
        REND=${range_end[$k]}

        # field 2 of check-format.pl output is the offending line number
        # Check here if any line in that output falls between any of the 
        # start/end ranges defined in the range_start/range_end array.
        # If it does fall in that range, print the entire line to stdout
        # If anything is printed, have awk exit with a non-zero exit code
        awk -v rstart=$RSTART -v rend=$REND -F':' '
                BEGIN {rc=0}
                /:/ {
                    if (($2 >= rstart) && ($2 <= rend)) {
                        print $0;
                        rc=1
                    }
                }
                END {exit rc;}
            ' $TEMPDIR/format-results.txt

        # If awk exited with a non-zero code, this script will also exit
        # with a non-zero code
        if [ $? -ne 0 ]
        then
            EXIT_CODE=1
        fi
    done
done

# Exit with the recorded exit code above
exit $EXIT_CODE
