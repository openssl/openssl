#!/usr/bin/perl

# fipscheck.pl
# sample perl script to check integrity of critical FIPS files

my ($fipsdir) = @ARGV;

die "Directory $fipsdir not found or invalid" unless -d $fipsdir;

die "Standalone SHA1 check program ${fipsdir}/fips_standalone_sha1.exe not found" unless -f "${fipsdir}/fips_standalone_sha1.exe";

check_hash("fips_premain.c", $fipsdir);
check_hash("fipscanister.o", $fipsdir);

sub check_hash
	{
	my ($filename, $dir) = @_;
	my ($hashfile, $hashval);

	$filename = "$dir/$filename";

	die "File $filename does not exist" unless -f $filename;
	die "File ${filename}.sha1 does not exist" unless -f "${filename}.sha1";

	open(IN, "${filename}.sha1") || die "Cannot open file hash file ${filename}.sha1";
	$hashfile = <IN>;
	close IN;
	$hashval = `${dir}/fips_standalone_sha1.exe $filename`;
	chomp $hashfile;
	chomp $hashval;
	$hashfile =~ s/^.*=\s+//;
	$hashval =~ s/^.*=\s+//;
	die "Invalid hash syntax in file" if (length($hashfile) != 40);
	die "Invalid hash received for file" if (length($hashval) != 40);
	die "*** HASH VALUE MISMATCH FOR FILE $filename ***" if ($hashval ne $hashfile); 
	}


