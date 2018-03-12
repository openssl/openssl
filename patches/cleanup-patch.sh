#!/bin/bash

for dir in $1;
do
	git clean -f src/$dir
	git checkout src/$dir
done
