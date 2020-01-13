# Example of running an querying Opentls test OCSP responder.
# This assumes "mkcerts.sh" or similar has been run to set up the
# necessary file structure.

OPENtls=../../apps/opentls
OPENtls_CONF=../../apps/opentls.cnf
export OPENtls_CONF

# Run OCSP responder.

PORT=8888

$OPENtls ocsp -port $PORT -index index.txt -CA intca.pem \
	-rsigner resp.pem -rkey respkey.pem -rother intca.pem $*
