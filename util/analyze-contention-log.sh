#!/bin/sh

###################################################################
# Script to analyze logs produced by REPORT_RWLOCK_CONTENTION
############################### ###################################

#
# Setup a temp dir to massage our contention log
#
TEMPDIR=$(mktemp -d /tmp/contention.XXXXXX)

#
# Specify our input log file
#
LOGFILE=$1

#
# Make sure we clean up on exit
#
trap "rm -rf $TEMPDIR" EXIT

if [ ! -f $LOGFILE ]; then
    echo "No log file found"
    exit 1
fi
LOGFILEBASE=$(basename $LOGFILE)

echo "Splitting files"
#
# start by splitting the log into separate stack traces
# the produced log file splits stack traces on empty lines
# so we use the split command to break the big log up
# into lots of little logs, so we can work with each
# separately
mkdir $TEMPDIR/individual_files
cp $LOGFILE $TEMPDIR/individual_files/$LOGFILEBASE
pushd $TEMPDIR/individual_files/ > /dev/null
awk '
    BEGIN {RS = ""; FS = "\n"}
    {file_num++; print > ("stacktrace" file_num ".txt")}' ./$LOGFILEBASE
popd > /dev/null
rm $TEMPDIR/individual_files/$LOGFILEBASE

#
# Declare some associative arrays to track data for each file
# each array is indexed by the sha1sum of the file
#
# We track the file name, the total latency accumulated by
# that blocking event and the number of instances that we 
# encountered it
#
declare -A filenames
declare -A total_latency
declare -A latency_counts

echo "Gathering latencies"
FILECOUNT=$(ls $TEMPDIR/individual_files/stacktrace*.* | wc -l)
let currentidx=0

#
# Now look at every stack trace, get, and record its latency, and hash value
#
for i in $(ls $TEMPDIR/individual_files/stacktrace*.*); do
    echo -e -n "FILE $currentidx/$FILECOUNT \r"
    LATENCY=$(awk '{print $6}' $i)
    # drop the non-stacktrace line
    sed -i -e"s/lock blocked on.*//" $i
    # now compute its sha1sum
    SHA1SUM=$(sha1sum $i | awk '{print $1}')
    filenames["$SHA1SUM"]=$i

    #
    # Add this latency and count to the appropriate
    # array key (sha1sum)
    #
    let CUR_LATENCY=0
    let LATENCY_COUNT=0
    if [[ -v total_latency["$SHA1SUM"] ]]; then
        let CUR_LATENCY=${total_latency["$SHA1SUM"]}
        let LATENCY_COUNT=${latency_counts["$SHA1SUM"]}
    fi
    total_latency["$SHA1SUM"]=$(dc -e "$CUR_LATENCY $LATENCY + p")
    latency_counts["$SHA1SUM"]=$(dc -e "$LATENCY_COUNT 1 + p")
    let currentidx=$currentidx+1
done

#
# Now lets find the top 10 latencies in the log file
# Note, they won't be sorted here, because sorting
# is hard
#
echo ""
top_10_val=(0 0 0 0 0 0 0 0 0 0)
top_10_sha=("0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0")

#compute the average latency and sort it
let empty_count=0
for i in ${!total_latency[@]}; do
    if [ $empty_count -lt 10 ]; then
        top_10_val[$empty_count]=${total_latency["$i"]}
        top_10_sha[$empty_count]="$i"
        let empty_count=$empty_count+1
        continue;
    fi

    # if this sha value is already in the array, don't insert it again
    if printf '%s\n' "${top_10_sha[@]}" | grep -q -x "$i"; then
        continue
    fi
    for j in $(seq 0 1 9); do
        if [ ${top_10_val[$j]} -lt ${total_latency["$i"]} ]; then
            top_10_val[$j]=${total_latency["$i"]}
            top_10_sha[$j]="$i"
            break
        fi
    done
done

#
# Print out our top 10 latencies
#
echo "Top latencies"
for i in $(seq 0 1 9); do
    if [ "${top_10_sha[$i]}" == "0" ]; then
        continue
    fi
    SHA1SUM=${top_10_sha[$i]}
    AVG_LATENCY=${top_10_val[$i]}
    FNAME=${filenames["$SHA1SUM"]}
    echo "Total lock latency $AVG_LATENCY usec"
    cat $FNAME
    echo "=============="
done


