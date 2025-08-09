#!/bin/bash

LOG_FILE=openssl.log

echo run openssl
echo export OPENSSL_riscvcap=ZBA_ZBB_ZBC_ZBS_V_ZVBB_ZVBC_ZVKB_ZVKG_ZVKNED_ZVKNHA_ZVKNHB_ZVKSED_ZVKSH
export OPENSSL_riscvcap=ZBA_ZBB_ZBC_ZBS_V_ZVBB_ZVBC_ZVKB_ZVKG_ZVKNED_ZVKNHA_ZVKNHB_ZVKSED_ZVKSH
echo openssl speed
openssl speed 2>&1 | tee -a $LOG_FILE
echo export OPENSSL_riscvcap=
export OPENSSL_riscvcap=
echo openssl speed
openssl speed 2>&1 | tee -a $LOG_FILE

goldminer.sh --logfile=$LOG_FILE
