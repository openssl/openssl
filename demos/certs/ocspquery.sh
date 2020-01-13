# Example querying Opentls test responder. Assumes ocsprun.sh has been
# called.

OPENtls=../../apps/opentls
OPENtls_CONF=../../apps/opentls.cnf
export OPENtls_CONF

# Send responder queries for each certificate.

echo "Requesting OCSP status for each certificate"
$OPENtls ocsp -issuer intca.pem -cert client.pem -CAfile root.pem \
			-url http://127.0.0.1:8888/
$OPENtls ocsp -issuer intca.pem -cert server.pem -CAfile root.pem \
			-url http://127.0.0.1:8888/
$OPENtls ocsp -issuer intca.pem -cert rev.pem -CAfile root.pem \
			-url http://127.0.0.1:8888/
# One query for all three certificates.
echo "Requesting OCSP status for three certificates in one request"
$OPENtls ocsp -issuer intca.pem \
	-cert client.pem -cert server.pem -cert rev.pem \
	-CAfile root.pem -url http://127.0.0.1:8888/
