#!/bin/sh
#
# A bit of an ugly shell script used to actually 'link' files.
# Used by 'make links'
#

PATH=$PATH:.:util:../util:../../util
export PATH

from=$1
shift

here=`pwd`
tmp=`dirname $from`
while [ "$tmp"x != "x" -a "$tmp"x != ".x" ]
do
	t=`basename $here`
	here=`dirname $here`
	to="/$t$to"
	tmp=`dirname $tmp`
done
to=..$to

#echo from=$from
#echo to  =$to
#exit 1

if [ "$*"x != "x" ]; then
	for i in $*
	do
		/bin/rm -f $from/$i
		point.sh $to/$i $from/$i
	done
fi
exit 0;
