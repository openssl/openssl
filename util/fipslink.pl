#!/usr/bin/perl

sub check_env
	{
	my @ret;
	foreach (@_)
		{
		die "Environment variable $_ not defined!\n" unless exists $ENV{$_};
		push @ret, $ENV{$_};
		}
	return @ret;
	}


my ($fips_cc,$fips_cc_args, $fips_link,$fips_target, $fips_libdir, $sha1_exe)
	 = check_env("FIPS_CC", "FIPS_CC_ARGS", "FIPS_LINK", "FIPS_TARGET",
	 	"FIPSLIB_D", "FIPS_SHA1_EXE");



if (exists $ENV{"PREMAIN_DSO_EXE"})
	{
	$fips_premain_dso = $ENV{"PREMAIN_DSO_EXE"};
	}
	else
	{
	$fips_premain_dso = "";
	}

check_hash($sha1_exe, "fips_premain.c");
check_hash($sha1_exe, "fipscanister.lib");


print "Integrity check OK\n";

print "$fips_cc $fips_cc_args $fips_libdir/fips_premain.c\n";
system "$fips_cc $fips_cc_args $fips_libdir/fips_premain.c";
die "First stage Compile failure" if $? != 0;

print "$fips_link @ARGV\n";
system "$fips_link @ARGV";
die "First stage Link failure" if $? != 0;


print "$fips_premain_dso $fips_target\n";
$fips_hash=`$fips_premain_dso $fips_target`;
chomp $fips_hash;
die "Get hash failure" if $? != 0;


print "$fips_cc -DHMAC_SHA1_SIG=\\\"$fips_hash\\\" $fips_cc_args $fips_libdir/fips_premain.c\n";
system "$fips_cc -DHMAC_SHA1_SIG=\\\"$fips_hash\\\" $fips_cc_args $fips_libdir/fips_premain.c";
die "Second stage Compile failure" if $? != 0;


print "$fips_link @ARGV\n";
system "$fips_link @ARGV";
die "Second stage Link failure" if $? != 0;

sub check_hash
	{
	my ($sha1_exe, $filename) = @_;
	my ($hashfile, $hashval);

	open(IN, "${fips_libdir}/${filename}.sha1") || die "Cannot open file hash file ${fips_libdir}/${filename}.sha1";
	$hashfile = <IN>;
	close IN;
	$hashval = `$sha1_exe ${fips_libdir}/$filename`;
	chomp $hashfile;
	chomp $hashval;
	$hashfile =~ s/^.*=\s+//;
	$hashval =~ s/^.*=\s+//;
	die "Invalid hash syntax in file" if (length($hashfile) != 40);
	die "Invalid hash received for file" if (length($hashval) != 40);
	die "***HASH VALUE MISMATCH FOR FILE $filename ***" if ($hashval ne $hashfile); 
	}


