#!/bin/bash

for dir in $1;
do
	patchfiles=`find ./patches/$dir -type f -name "*.patch"`
	for patchfile in $patchfiles;
	do
		git apply --check $patchfile >/dev/null 2>&1
		if [ $? -eq 0 ];then
			git -c core.whitespace=cr-at-eol apply $patchfile >/dev/null 2>&1
		fi
	done
done
