#!/bin/sh
#
# clean up the mess that NT makes of my source tree
#

if [ -f makefile.ssl -a ! -f Makefile.ssl ]; then
	/bin/mv makefile.ssl Makefile.ssl
fi
chmod +x Configure util/*
echo cleaning
/bin/rm -f `find . -name '*.$$$' -print` 2>/dev/null >/dev/null
echo 'removing those damn ^M'
perl -pi -e 's/\015//' `find . -type 'f' -print |grep -v '.obj$' |grep -v '.der$' |grep -v '.gz'`
make -f Makefile.ssl links
