#!/bin/sh

cwd=`pwd`
cd /tmp

if [ -s /bin/ranlib ] ; then 
	RL=/bin/ranlib
else if [ -s /usr/bin/ranlib ] ; then
	RL=/usr/bin/ranlib
fi
fi

if [ "x$RL" != "x" ]
then
	case "$1" in
		/*)  
		$RL "$1"
		;;
		*)
		$RL "$cwd/$1"
		;;
	esac
fi
