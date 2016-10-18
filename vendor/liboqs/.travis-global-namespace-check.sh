#!/bin/bash

if [[ $(nm -g liboqs.a | grep ' T ' | grep -E -v -i ' T [_]?OQS') ]]; 
then 
	tput setaf 1;
	echo "Code contains the following non-namespaced global symbols; see https://github.com/open-quantum-safe/liboqs/wiki/Coding-conventions for function naming conventions.";
	nm -g liboqs.a | grep ' T ' | grep -E -v -i ' T [_]?OQS'
	exit 1;
else 
	tput setaf 2;
	echo "Code adheres to the project standards.";
	exit 0;
fi;
