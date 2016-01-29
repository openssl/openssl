#! /bin/sh

# $1 is expected to be $TRAVIS_OS_NAME

if [ "$1" == osx ]; then
    make -f Makefile.org \
	 DISTTARVARS="NAME=_srcdist TAR_COMMAND='\$\$(TAR) \$\$(TARFLAGS) -s \"|^|\$\$(NAME)/|\" -T \$\$(TARFILE).list -cvf -' TARFLAGS='-n' TARFILE=_srcdist.tar" SHELL='sh -vx' dist
else
    make -f Makefile.org DISTTARVARS='TARFILE=_srcdist.tar NAME=_srcdist' SHELL='sh -v' dist
fi
