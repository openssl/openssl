#!/bin/bash

###########
# Run speed test in OpenSSL 1.1.1 
#
###########

set -x

# Circumvent OSX SIP LIBPATH 'protection'
if [ "x$OQS_LIBPATH" != "x" ]; then
        export DYLD_LIBRARY_PATH=$OQS_LIBPATH
fi
echo "DLD = $DYLD_LIBRARY_PATH"

# Test all KEMs:
apps/openssl speed -seconds 1 oqskem
if [ $? -ne 0 ]; then
   exit -1
fi
# Test all SIGs 
if [ `uname` == "Darwin" ]; then
# On OSX, only test one alg that doesn't cause memory problems:
   apps/openssl speed -seconds 1 dilithium2
else
# Disabling cleanup on Linux because of picnic-induced memory glitch:
   OPENSSL_NO_CLEANUP=1 apps/openssl speed -seconds 1 oqssig
fi

