#!/bin/sh

cwd=`pwd`
/bin/rm -fr tmp/*

cd crypto/des
make -f Makefile.uni tar
make -f Makefile.uni tar_lit
/bin/mv libdes.tgz $cwd/tmp
/bin/mv libdes-l.tgz $cwd/tmp
cd $cwd

for name in md5 sha cast bf idea rc4 rc2
do
	echo doing $name
	(cd crypto; tar cfh - $name)|(cd tmp; tar xf -)
	cd tmp/$name
	/bin/rm -f Makefile
	/bin/rm -f Makefile.ssl
	/bin/rm -f Makefile.ssl.orig
	/bin/rm -f *.old
	/bin/mv Makefile.uni Makefile

	if [ -d asm ]; then
		mkdir asm/perlasm
		cp $cwd/crypto/perlasm/*.pl asm/perlasm
	fi
	cd ..
	tar cf - $name|gzip >$name.tgz
#	/bin/rm -fr $name
	cd $cwd
done


