#!/usr/local/bin/perl -w
#
# Run the test suite and generate a report
#

if (! -f "Configure") {
    print "Please run perl util/selftest.pl in the OpenSSL directory.\n";
    exit 1;
}

my $report="testlog";
my $os="??";
my $version="??";
my $platform0="??";
my $platform="??";
my $options="??";
my $last="??";
my $ok=0;
my $cc="cc";
my $sep="-----------------------------------------------------------------------------\n";

open(OUT,">$report") or die;

print OUT "OpenSSL self-test report:\n\n";

$uname=`uname -a`;

$c=`sh config -t`;
foreach $_ (split("\n",$c)) {
    $os=$1 if (/Operating system: (.*)$/);
    $platform0=$1 if (/Configuring for (.*)$/);
}

system "sh config" if (! -f "Makefile.ssl");

if (open(IN,"<Makefile.ssl")) {
    while (<IN>) {
	$version=$1 if (/^VERSION=(.*)$/);
	$platform=$1 if (/^PLATFORM=(.*)$/);
	$options=$1 if (/^OPTIONS=(.*)$/);
	$cc=$1 if (/^CC=(.*)$/);
    }
    close(IN);
} else {
    print OUT "Error running config: no Makefile.ssl!\n";
}

if (open(IN,"<CHANGES")) {
    while(<IN>) {
	if (/\*\) (.{0,55})/) {
	    $last=$1;
	    last;
	}
    }
    close(IN);
}

print OUT "OpenSSL version:  $version\n";
print OUT "Last change:      $last...\n";
print OUT "OS (uname):       $uname";
print OUT "OS (config):      $os\n";
print OUT "Target (default): $platform0\n";
print OUT "Target:           $platform\n";
print OUT "\n";

print "Checking compiler...\n";
if (open(TEST,">test.c")) {
    print TEST "#include <stdio.h>\nmain(){printf(\"Hello world\n\");}\n";
    close(TEST);
    system("$cc -o cctest test.c");
    if (! `./cctest` =~ /Hello world/) {
	print OUT "Compiler doesn't work.\n";
	goto err;
    }
} else {
    print OUT "Can't create test.c\n";
}
if (open(TEST,">test.c")) {
    print TEST "#include <openssl/opensslv.h>\nmain(){printf(OPENSSL_VERSION_TEXT);}\n";
    close(TEST);
    system("$cc -o cctest -Iinclude test.c");
    $cctest = `./cctest`;
    if ($cctest !~ /OpenSSL $version/) {
	if ($cctest =~ /OpenSSL/) {
	    print OUT "#include uses headers from different OpenSSL version!\n";
	} else {
	    print OUT "Can't compile test program!\n";
	}
	goto err;
    }
} else {
    print OUT "Can't create test.c\n";
}

print "Running make...\n";
if (system("make 2>&1 | tee make.log") > 255) {

    print OUT "make failed!\n";
    if (open(IN,"<make.log")) {
	print OUT $sep;
	while (<IN>) {
	    print OUT;
	}
	close(IN);
	print OUT $sep;
    } else {
	print OUT "make.log not found!\n";
    }
    goto err;
}

print "Running make test...\n";
if (system("make test 2>&1 | tee make.log") > 255)
 {
    print OUT "make test failed!\n";
} else {
    $ok=1;
}

if ($ok and open(IN,"<make.log")) {
    while (<IN>) {
	$ok=2 if /^platform: $platform/;
    }
    close(IN);
}

if ($ok != 2) {
    print OUT "Failure!\n";
    if (open(IN,"<make.log")) {
	print OUT $sep;
	while (<IN>) {
	    print OUT;
	}
	close(IN);
	print OUT $sep;
    } else {
	print OUT "make.log not found!\n";
    }
} else {
    print OUT "Test passed.\n";
}
err:
close(OUT);

print "\n";
open(IN,"<$report") or die;
while (<IN>) {
    last if /$sep/;
    print;
}
print "Test report in file $report\n";
