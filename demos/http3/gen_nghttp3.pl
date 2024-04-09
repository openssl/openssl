#!/usr/bin/env perl

use File::Copy;
use File::Path;
use strict;
use warnings;

open STDOUT, '>&STDERR';

chdir "demos/http3";
rmtree("./nghttp3");
system("git clone https://github.com/ngtcp2/nghttp3.git");

chdir "nghttp3";
mkdir "build";
system("git submodule init");
system("git submodule update");
system("cmake -S . -B build");
system("cmake --build build");

my $libs="./build/lib/libnghttp*";

for my $file (glob $libs) {
    copy($file, "..");
}

chdir "../";

exit(0);
