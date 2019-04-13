#!/bin/bash

###########
# Run one client/server interaction in OpenSSL 1.1.1
#
# Environment variables:
#  - KEXALG: key exchange algorithm to use
#  - SIGALG: signature algorithm to use
#  - PORT: port to run server on
###########

set -exo pipefail

apps/openssl s_server -cert ${SIGALG}_srv.crt -key ${SIGALG}_srv.key -CAfile ${SIGALG}_CA.crt -tls1_3 -www -accept ${PORT} &
sleep 1
SERVER_PID=$!
echo "GET /" | apps/openssl s_client -curves "${KEXALG}" -CAfile ${SIGALG}_CA.crt -connect "localhost:${PORT}" > s_client_${PORT}.out 2>/dev/null
cat s_client_${PORT}.out | grep "Server Temp Key" | grep "${KEXALG}" > /dev/null
kill ${SERVER_PID}
