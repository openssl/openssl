#!/bin/bash
#
# Install clang-format on Linux
# 

if [ ! -x "$(which clang-format-3.9)" ]; then 
	sudo add-apt-repository 'deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.9 main'
	wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -
	sudo apt-get update -qq 
	sudo apt-get install -qq -y clang-format-3.9
fi;
