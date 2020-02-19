#!/bin/bash

###########
# Run CMS test in OpenSSL 1.1.1 (assume keys and certs have been generated before)
#
# Environment variables:
#  - SIGALG: signature algorithm to use
###########

set -x

# Circumvent OSX SIP LIBPATH 'protection'
if [ "x$OQS_LIBPATH" != "x" ]; then
        export DYLD_LIBRARY_PATH=$OQS_LIBPATH
fi
echo "DLD = $DYLD_LIBRARY_PATH"

# Abusing README.md as data to sign/verify
rm -f result
apps/openssl cms -in README.md -sign -signer ${SIGALG}_srv.crt -inkey ${SIGALG}_srv.key  -nodetach -outform pem -binary -out output-${SIGALG}.p7s
apps/openssl cms -verify -CAfile ${SIGALG}_CA.crt  -inform pem -in output-${SIGALG}.p7s -crlfeol -out result
rm output-${SIGALG}.p7s
# result of diff will become result of test (input must be equal verify result if all works)
diff result README.md
