#!/bin/bash

while true
do
	export OPENSSL_riscvcap=ZBA_ZBB_ZBC_ZBS_V_ZVBB_ZVBC_ZVKB_ZVKG_ZVKNED_ZVKNHA_ZVKNHB_ZVKSED_ZVKSH
	openssl speed -evp sm3
	openssl speed -evp sm4
	openssl speed -evp aes-128-cbc
	openssl speed -evp aes-192-cbc
	openssl speed -evp aes-256-cbc
	openssl speed -evp aes-128-gcm
	openssl speed -evp aes-192-gcm
	openssl speed -evp aes-256-gcm
	openssl speed -evp aes-128-xts
	openssl speed -evp aes-256-xts
	openssl speed -evp sha256
	openssl speed -evp sha512
done
