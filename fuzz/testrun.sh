#! /bin/bash
while true
do
  for X in `ls ./corpora`
  do
    echo `date`: running $X
    for Y in `ls ./corpora/$X`
    do
      UBSAN_OPTIONS=${UBSAN_OPTIONS:-print_stacktrace=1} \
      ERROR_INJECT=${ERROR_INJECT:-} \
      ../util/shlib_wrap.sh ./$X-test ./corpora/$X/$Y &> $X-$Y-$$-test.out
      if [ $? != 0 ]
      then
        echo `date`: error detected
        echo `grep ERROR_INJECT= $X-$Y-$$-test.out` ../util/shlib_wrap.sh ./$X-test ./corpora/$X/$Y
        echo log file: $X-$Y-$$-test.out
        cat $X-$Y-$$-test.out
        exit
      fi
      rm $X-$Y-$$-test.out
      if [ -f stop.signal ]
      then
        rm stop.signal
        echo `date`: stopped
        exit
      fi
    done
  done
done
