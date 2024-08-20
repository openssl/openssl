#!/bin/bash

set -euxo pipefail

CURLRC=~/testcase_curlrc

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

generate_outputs_http3() {
    for i in $REQUESTS
    do
        OUTFILE=$(basename $i)
        echo -e "--http3-only\n-o /downloads/$OUTFILE\n--url $i" >> $CURLRC
        echo "--next" >> $CURLRC
    done
    # Remove the last --next
    head -n -1 $CURLRC > $CURLRC.tmp
    mv $CURLRC.tmp $CURLRC 
}

dump_curlrc() {
    echo "Using curlrc:"
    cat $CURLRC
}

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    echo "Waiting for simulator"
    /wait-for-it.sh sim:57832 -s -t 30
    echo "TESTCASE is $TESTCASE"
    rm -f $CURLRC 

    case "$TESTCASE" in
    "http3"|"transfer")
    echo -e "--verbose\n--parallel" >> $CURLRC
    generate_outputs_http3
    dump_curlrc
        SSL_CERT_FILE=/certs/ca.pem curl --config $CURLRC 
        if [ $? -ne 0 ]
        then
            exit 1
        fi
        exit 0
        ;;
    "handshake")
       OUTFILE=$(basename $REQUESTS)
       echo -e "--verbose\n--http3\n-H \"Connection: close\"\n-o /downloads/$OUTFILE\n--url $REQUESTS" >> $CURLRC
       dump_curlrc
       SSL_CERT_FILE=/certs/ca.pem curl --config $CURLRC 
       if [ $? -ne 0 ]
       then
           exit 1
       fi
       exit 0
       ;; 
    "retry")
       OUTFILE=$(basename $REQUESTS)
       SSL_CERT_FILE=/certs/ca.pem curl --verbose --http3 -o /downloads/$OUTFILE $REQUESTS
       if [ $? -ne 0 ]
       then
           exit 1
       fi
       exit 0
       ;; 
    "chacha20")
       OUTFILE=$(basename $REQUESTS)
       SSL_CERT_FILE=/certs/ca.pem curl --verbose --tlsv1.3 --tls13-ciphers TLS_CHACHA20_POLY1305_SHA256 --http3 -o /downloads/$OUTFILE $REQUESTS
       if [ $? -ne 0 ]
       then
           exit 1
       fi
       exit 0
       ;; 
    *)
        echo "UNSUPPORTED TESTCASE $TESTCASE"
        exit 127
        ;;
    esac
elif [ "$ROLE" == "server" ]; then
    echo "UNSUPPORTED"
    exit 127
else
    echo "Unknown ROLE $ROLE"
    exit 127
fi

