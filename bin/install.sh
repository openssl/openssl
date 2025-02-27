#!/bin/sh
# Installs.

./Configure &&\
 make -s -j10 &&\
 sudo make install
