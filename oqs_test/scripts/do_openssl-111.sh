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

# Circumvent OSX SIP LIBPATH 'protection'
if [ "x$OQS_LIBPATH" != "x" ]; then
	export DYLD_LIBRARY_PATH=$OQS_LIBPATH
fi
echo "DLD = $DYLD_LIBRARY_PATH"

apps/openssl s_server -curves "${KEXALG}" -cert ${SIGALG}_srv.crt -key ${SIGALG}_srv.key -CAfile ${SIGALG}_CA.crt -tls1_3 -www -accept ${PORT} > s_server_${PORT}.out 2>&1 &
SERVER_PID=$!
sleep 1

echo "GET /" > get_command.tmp

apps/openssl s_client -curves "${KEXALG}" -CAfile ${SIGALG}_CA.crt -connect "localhost:${PORT}" < get_command.tmp > s_client_${PORT}.out 2>&1
CLIENT_STATUS=$?

rm -f get_command.tmp

kill -9 ${SERVER_PID} > /dev/null 2> /dev/null

cat s_client_${PORT}.out | grep "Server Temp Key" | grep "${KEXALG}" > /dev/null
GREP_STATUS=$?

echo "Client output"
cat s_client_${PORT}.out
echo ""
rm -f s_client_${PORT}.out

echo "Server output"
cat s_server_${PORT}.out
echo ""
rm -f s_server_${PORT}.out

if [ ${CLIENT_STATUS} -ne 0 ] ; then
    exit ${CLIENT_STATUS}
fi

exit ${GREP_STATUS}
