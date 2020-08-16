#! /bin/sh

git restore --staged .
git restore .
git clean -f crypto doc include providers test
