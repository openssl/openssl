#!/bin/perl

# Simple perl script to wrap round "ar" program and exclude any
# object files in the environment variable EXCL_OBJ

map { s/^.*\/([^\/]*)$/$1/ ; $EXCL{$_} = 1} split(' ', $ENV{EXCL_OBJ});

#my @ks = keys %EXCL;
#print STDERR "Excluding: @ks \n";

my @ARGS = grep { !exists $EXCL{$_} } @ARGV;	

system @ARGS;

exit $? >> 8;
