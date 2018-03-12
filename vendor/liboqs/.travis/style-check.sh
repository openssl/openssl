#!/bin/bash

# see what has been modified (ignoring submodules because they are likely patched)
modified=$(git status -s --ignore-submodules)

if [ "$modified" ]; then
	tput setaf 1;
	echo "There are modified files present in the directory prior to prettyprint check. This may indicate that some files should be added to .gitignore.";
	tput sgr 0;
	git status -s
	exit 1;
fi;

if [ ! -x "$(which clang-format-3.9)" ]; then
	# If clang-format is not version -3.9, just use clang-format
	CLANGFORMAT=clang-format make prettyprint
else
	CLANGFORMAT=clang-format-3.9 make prettyprint
fi;

modified=$(git status -s --ignore-submodules)

if [[ ${ENABLE_KEX_RLWE_NEWHOPE_AVX2} == 1 ]];then
  modified=$(echo $modified | grep -v "kex_rlwe_newhope/avx2" | grep -v "Makefile.am" | grep -v "avx2/kex*")
else
  modified=$(echo $modified | grep -v "Makefile.am")
fi

if [ "$modified" ]; then
	tput setaf 1;
	echo "Code does not adhere to the project standards. Run \"make prettyprint\".";
	tput sgr 0;
	git status -s
	exit 1;
else
	tput setaf 2;
	echo "Code adheres to the project standards (prettyprint).";
	tput sgr 0;
	exit 0;
fi;
