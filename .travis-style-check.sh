#!/bin/bash

if [[ $(make prettyprint | grep Formatted) ]]; 
then 
	tput setaf 1;
	echo "Code does not adhere to the project standards. Run \"make prettyprint\".";
	exit 1;
else 
	tput setaf 2;
	echo "Code adheres to the project standards.";
	exit 0;
fi;
