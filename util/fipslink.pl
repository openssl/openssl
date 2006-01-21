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


my ($fips_cc,$fips_cc_args, $fips_link,$fips_target)
	 = check_env("FIPS_CC", "FIPS_CC_ARGS", "FIPS_LINK", "FIPS_TARGET");



if (exists $ENV{"FIPS_PREMAIN_DSO"})
	{
	$fips_premain_dso = $ENV{"FIPS_PREMAIN_DSO"};
	}
	else
	{
	$fips_premain_dso = "";
	}


print "$fips_cc $fips_cc_args\n";
system "$fips_cc $fips_cc_args";
die "First stage Compile failure" if $? != 0;

print "$fips_link @ARGV\n";
system "$fips_link @ARGV";
die "First stage Link failure" if $? != 0;


print "$fips_premain_dso $fips_target\n";
$fips_hash=`$fips_premain_dso $fips_target`;
chomp $fips_hash;
die "Get hash failure" if $? != 0;


print "$fips_cc -DHMAC_SHA1_SIG=\\\"$fips_hash\\\" $fips_cc_args\n";
system "$fips_cc -DHMAC_SHA1_SIG=\\\"$fips_hash\\\" $fips_cc_args";
die "Second stage Compile failure" if $? != 0;


print "$fips_link @ARGV\n";
system "$fips_link @ARGV";
die "Second stage Link failure" if $? != 0;

