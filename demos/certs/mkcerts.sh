#!/bin/sh

OPENSSL=openssl

# Root CA: create certificate directly
CN="Test Root CA" $OPENSSL req -config ca.cnf -x509 -nodes \
	-keyout root.pem -out root.pem -newkey rsa:2048 -days 3650
# Server certificate: create request first
CN="Test Server Cert" $OPENSSL req -config ca.cnf -nodes \
	-keyout skey.pem -out req.pem -newkey rsa:1024
# Sign request: end entity extensions
$OPENSSL x509 -req -in req.pem -CA root.pem -days 3600 \
	-extfile ca.cnf -extensions usr_cert -CAcreateserial -out server.pem
# Intermediate CA: request first
CN="Test Intermediate CA" $OPENSSL req -config ca.cnf -nodes \
	-keyout intkey.pem -out intreq.pem -newkey rsa:2048
# Sign request: CA extensions
$OPENSSL x509 -req -in intreq.pem -CA root.pem -days 3600 \
	-extfile ca.cnf -extensions v3_ca -CAcreateserial -out intca.pem
# Client certificate: request first
CN="Test Client Cert" $OPENSSL req -config ca.cnf -nodes \
	-keyout ckey.pem -out creq.pem -newkey rsa:1024
# Sign using intermediate CA
$OPENSSL x509 -req -in creq.pem -CA intca.pem -CAkey intkey.pem -days 3600 \
	-extfile ca.cnf -extensions usr_cert -CAcreateserial -out client.pem
