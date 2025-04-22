#!/bin/bash

cleanup() {
    killall -9 _run_stress.sh
    exit
}
trap cleanup SIGINT SIGKILL

LOG=/tmp/log_openssl_$(date +'%Y-%m-%d_%H-%M-%S').log
echo $LOG
touch $LOG

while true
do
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG &
    sleep $(( RANDOM % 5 + 1 ))
    ./_run_stress.sh 2>&1 | tee -a $LOG
    if grep "Segmentation fault" $LOG -rn; then
        echo error !!!!!!!!!!
        echo error !!!!!!!!!!
        echo error !!!!!!!!!!
        exit 1
    fi
done
