#!/bin/bash

cleanup() {
    killall -9 _run_stress.sh
    killall -9 check_run_stress_error.sh
    exit
}
trap cleanup SIGINT SIGKILL

LOG=/tmp/log_$(date +'%Y-%m-%d_%H-%M-%S').log
echo $LOG
touch $LOG

./check_run_stress_error.sh $LOG &

while true
do
    ./_run.sh | tee -a $LOG &
    ./_run.sh | tee -a $LOG &
    ./_run.sh | tee -a $LOG &
    ./_run.sh | tee -a $LOG &
    ./_run.sh | tee -a $LOG &
    ./_run.sh | tee -a $LOG &
    ./_run.sh | tee -a $LOG &
    ./_run.sh | tee -a $LOG
done
