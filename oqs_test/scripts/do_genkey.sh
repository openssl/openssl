#!/bin/bash

###########
# Run one client/server interaction in OpenSSL 1.1.1
#
# Environment variables:
#  - KEXALG: key exchange algorithm to use
#  - SIGALG: signature algorithm to use
#  - PORT: port to run server on
###########

set -x

pwd

# Circumvent OSX SIP LIBPATH 'protection'
if [ "x$OQS_LIBPATH" != "x" ]; then
	export DYLD_LIBRARY_PATH=$OQS_LIBPATH
fi
echo "DLD = $DYLD_LIBRARY_PATH"

if [ "x$SIGALG" == "xecdsa" ]; then
apps/openssl ecparam -out secp384r1.pem -name secp384r1

apps/openssl req -x509 -new -newkey ec:secp384r1.pem -keyout ${SIGALG}_CA.key -out ${SIGALG}_CA.crt -nodes -subj '/CN=oqstest_CA' -days 365 -config apps/openssl.cnf

apps/openssl req -new -newkey ec:secp384r1.pem -keyout ${SIGALG}_srv.key -out ${SIGALG}_srv.csr -nodes -subj '/CN=oqstest_server' -config apps/openssl.cnf

else
apps/openssl req -x509 -new -newkey ${SIGALG} -keyout ${SIGALG}_CA.key -out ${SIGALG}_CA.crt -nodes -subj '/CN=oqstest_CA' -days 365 -config apps/openssl.cnf

apps/openssl req -new -newkey ${SIGALG} -keyout ${SIGALG}_srv.key -out ${SIGALG}_srv.csr -nodes -subj '/CN=oqstest_server' -config apps/openssl.cnf
fi
apps/openssl x509 -req -in ${SIGALG}_srv.csr -out ${SIGALG}_srv.crt -CA ${SIGALG}_CA.crt -CAkey ${SIGALG}_CA.key -CAcreateserial -days 365
