# test/runex.pl
# Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
# project.
#
# ====================================================================
# Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer. 
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. All advertising materials mentioning features or use of this
#    software must display the following acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
#
# 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For written permission, please contact
#    licensing@OpenSSL.org.
#
# 5. Products derived from this software may not be called "OpenSSL"
#    nor may "OpenSSL" appear in their names without prior written
#    permission of the OpenSSL Project.
#
# 6. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
#
# THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
# EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
# ====================================================================

# Perl script to run tests against S/MIME examples in RFC4134
# Assumes all files are extracted in an directory called "examples"

my $badttest = 0;
my $verbose = 1;

my $cmscmd = "../util/shlib_wrap.sh ../apps/openssl cms";
my $convcmd = "../util/shlib_wrap.sh ../apps/openssl x509 -inform DER";
my $exdir = "examples";

my @test_list = (
["3.1.bin"	=> "dataout"],
["3.2.bin"	=> "encode, dataout"],
["4.1.bin"	=> "encode, verifyder, content, dss"],
["4.2.bin"	=> "encode, verifyder, cont, rsa"],
["4.3.bin"	=> "encode, verifyder, cont_extern, dss"],
["4.4.bin"	=> "encode, verifyder, cont, dss"],
["4.5.bin"	=> "verifyder, content, rsa"],
["4.6.bin"	=> "encode, verifyder, cont, dss"],
["4.7.bin"	=> "encode, verifyder, cont, dss"],
["4.8.eml"	=> "verifymime, dss"],
["4.9.eml"	=> "verifymime, dss"],
["4.10.bin"	=> "encode, verifyder, cont, dss"],
["4.11.bin"	=> "encode"],
["5.1.bin"	=> "encode"],
["5.2.bin"	=> "encode"],
["6.0.bin"	=> "encode, digest, cont"],
["7.1.bin"	=> "encode, encrypted, cont"],
["7.2.bin"	=> "encode, encrypted, cont"]
);

my $secretkey = "73:7c:79:1f:25:ea:d0:e0:46:29:25:43:52:f7:dc:62:91:e5:cb:26:91:7a:da:32";

	if (!-d $exdir)
		{
		print STDERR "FATAL ERROR: examples directory missing!!\n";
		exit 1;
		}

	system ("$convcmd -in $exdir/CarlDSSSelf.cer -out $exdir/CarlDSSSelf.pem");
	system ("$convcmd -in $exdir/CarlRSASelf.cer -out $exdir/CarlRSASelf.pem");

	$cafile = "$cmsdir/CarlRSASelf.pem" if $tlist =~ /rsa/;

foreach (@test_list) {
	my ($file, $tlist) = @$_;
	print "Example file $file:\n";
	if ($tlist =~ /encode/)
		{
		run_reencode_test($exdir, $file);
		}
	if ($tlist =~ /dataout/)
		{
		run_dataout_test($exdir, $file);
		}
	if ($tlist =~ /verify/)
		{
		run_verify_test($exdir, $tlist, $file);
		}
	if ($tlist =~ /digest/)
		{
		run_digest_test($exdir, $tlist, $file);
		}
	if ($tlist =~ /encrypted/)
		{
		run_encrypted_test($exdir, $tlist, $file, $secretkey);
		}

}

unlink "cms.out";
unlink "cms.err";
unlink "tmp.der";
unlink "tmp.txt";

if ($badtest) {
	print "\n$badtest TESTS FAILED!!\n";
} else {
	print "\n***All tests successful***\n";
}


sub run_reencode_test
	{
	my ($cmsdir, $tfile) = @_;
	unlink "tmp.der";

	system ("$cmscmd -cmsout -inform DER -outform DER" .
		" -in $cmsdir/$tfile -out tmp.der");

	if ($?)
		{
		print "\tReencode command FAILED!!\n";
		$badtest++;
		}
	elsif (!cmp_files("$cmsdir/$tfile", "tmp.der"))
		{
		print "\tReencode FAILED!!\n";
		$badtest++;
		}
	else
		{
		print "\tReencode passed\n" if $verbose;
		}
	}

sub run_dataout_test
	{
	my ($cmsdir, $tfile) = @_;
	unlink "tmp.txt";

	system ("$cmscmd -data_out -inform DER" .
		" -in $cmsdir/$tfile -out tmp.txt");

	if ($?)
		{
		print "\tDataout command FAILED!!\n";
		$badtest++;
		}
	elsif (!cmp_files("$cmsdir/ExContent.bin", "tmp.txt"))
		{
		print "\tDataout compare FAILED!!\n";
		$badtest++;
		}
	else
		{
		print "\tDataout passed\n" if $verbose;
		}
	}

sub run_verify_test
	{
	my ($cmsdir, $tlist, $tfile) = @_;
	unlink "tmp.txt";

	$form = "DER" if $tlist =~ /verifyder/;
	$form = "SMIME" if $tlist =~ /verifymime/;
	$cafile = "$cmsdir/CarlDSSSelf.pem" if $tlist =~ /dss/;
	$cafile = "$cmsdir/CarlRSASelf.pem" if $tlist =~ /rsa/;

	$cmd = "$cmscmd -verify -inform $form" .
		" -CAfile $cafile" .
		" -in $cmsdir/$tfile -out tmp.txt";

	$cmd .= " -content $cmsdir/ExContent.bin" if $tlist =~ /cont_extern/;	

	system ("$cmd 2>cms.err 1>cms.out");

	if ($?)
		{
		print "\tVerify command FAILED!!\n";
		$badtest++;
		}
	elsif ($tlist =~ /cont/ &&
		!cmp_files("$cmsdir/ExContent.bin", "tmp.txt"))
		{
		print "\tVerify content compare FAILED!!\n";
		$badtest++;
		}
	else
		{
		print "\tVerify passed\n" if $verbose;
		}
	}

sub run_digest_test
	{
	my ($cmsdir, $tlist, $tfile) = @_;
	unlink "tmp.txt";

	system ("$cmscmd -digest_verify -inform DER" .
		" -in $cmsdir/$tfile -out tmp.txt");

	if ($?)
		{
		print "\tDigest verify command FAILED!!\n";
		$badtest++;
		}
	elsif ($tlist =~ /cont/ &&
		!cmp_files("$cmsdir/ExContent.bin", "tmp.txt"))
		{
		print "\tDigest verify content compare FAILED!!\n";
		$badtest++;
		}
	else
		{
		print "\tDigest verify passed\n" if $verbose;
		}
	}

sub run_encrypted_test
	{
	my ($cmsdir, $tlist, $tfile, $key) = @_;
	unlink "tmp.txt";

	system ("$cmscmd -EncrypedData_decrypt -inform DER" .
		" -secretkey $key" .
		" -in $cmsdir/$tfile -out tmp.txt");

	if ($?)
		{
		print "\tEncrypted Data command FAILED!!\n";
		$badtest++;
		}
	elsif ($tlist =~ /cont/ &&
		!cmp_files("$cmsdir/ExContent.bin", "tmp.txt"))
		{
		print "\tEncrypted Data content compare FAILED!!\n";
		$badtest++;
		}
	else
		{
		print "\tEncryptedData verify passed\n" if $verbose;
		}
	}

sub cmp_files
	{
	my ($f1, $f2) = @_;
	my ($fp1, $fp2);

	my ($rd1, $rd2);

	if (!open($fp1, "<$f1") ) {
		print STDERR "Can't Open file $f1\n";
		return 0;
	}

	if (!open($fp2, "<$f2") ) {
		print STDERR "Can't Open file $f2\n";
		return 0;
	}

	binmode $fp1;
	binmode $fp2;

	my $ret = 0;

	for (;;)
		{
		$n1 = sysread $fp1, $rd1, 4096;
		$n2 = sysread $fp2, $rd2, 4096;
		last if ($n1 != $n2);
		last if ($rd1 ne $rd2);

		if ($n1 == 0)
			{
			$ret = 1;
			last;
			}

		}

	close $fp1;
	close $fp2;

	return $ret;

	}


