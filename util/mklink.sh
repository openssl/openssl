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
prefix='..'

while [ `basename $tmp`x != ..x -a `basename $tmp`x != .x ]
do
	prefix=../$prefix
	tmp=`dirname $tmp`
done

to=''
while [ "$tmp"x != "x" -a "$tmp"x != ".x" ]
do
	t=`basename $here`
	here=`dirname $here`
	to="/$t$to"
	tmp=`dirname $tmp`
done
to=$prefix$to

if [ "$*"x != "x" ]; then
	for i in $*
	do
		rm -f $from/$i
		ln -s $to/$i $from/$i
		echo "$i => $from/$i"
	done
fi
exit 0;
