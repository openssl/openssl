#!/bin/bash

make prettyprint | grep -q Formatted
STATUS=(${PIPESTATUS[*]})

if [ ${STATUS[1]} == 0 ]; then 
	tput setaf 1;
	echo "Code does not adhere to the project standards. Run \"make prettyprint\".";
	tput sgr 0;
	exit 1;
elif [ ${STATUS[0]} != 0 ];  then
	tput setaf 1;
	echo "prettyprint failed.";
	tput sgr 0;
	exit 1;
else 
	tput setaf 2;
	echo "Code adheres to the project standards (prettyprint).";
	tput sgr 0;
	exit 0;
fi;
