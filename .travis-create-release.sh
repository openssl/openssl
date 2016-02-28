#! /bin/sh

# $1 is expected to be $TRAVIS_OS_NAME

./Configure dist
if [ "$1" == osx ]; then
    make NAME='_srcdist' TARFLAGS='-n' TARFILE='_srcdist.tar' \
	 TAR_COMMAND='$(TAR) $(TARFLAGS) -s "|^|$(NAME)/|" -T $(TARFILE).list -cvf -' \
	 SHELL='sh -vx' tar
else
    make TARFILE='_srcdist.tar' NAME='_srcdist' SHELL='sh -v' dist
fi
