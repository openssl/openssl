#!/usr/local/bin/perl

open IN, "obj_mac.num";

# Read in OID nid values for a lookup table.

while (<IN>)
	{
	chomp;
	my ($name, $num) = /^(\S+)\s+(\S+)$/;
	$oid_tbl{$name} = $num;
	}
close IN;

open IN, "obj_xref.txt";

my $ln = 1;

while (<IN>)
	{
	chomp;
	s/#.*$//;
	next if (/^\S*$/);
	my ($xr, $p1, $p2) = /^(\S+)\s+(\S+)\s+(\S+)/;
	check_oid($xr);
	check_oid($p1);
	check_oid($p2);
	$xref_tbl{$xr} = [$p1, $p2, $ln];
	}

my @xrkeys = keys %xref_tbl;

my @srt1 = sort { $oid_tbl{$a} <=> $oid_tbl{$b}} @xrkeys;

for(my $i = 0; $i <= $#srt1; $i++)
	{
	$xref_tbl{$srt1[$i]}[2] = $i;
	}

my @srt2 = sort
	{
	my$ap1 = $oid_tbl{$xref_tbl{$a}[0]};
	my$bp1 = $oid_tbl{$xref_tbl{$b}[0]};
	return $ap1 - $bp1 if ($ap1 != $bp1);
	my$ap2 = $oid_tbl{$xref_tbl{$a}[1]};
	my$bp2 = $oid_tbl{$xref_tbl{$b}[1]};

	return $ap2 - $bp2;
	} @xrkeys;
	

print <<EOF;

typedef int nid_triple[3];

static const nid_triple sigoid_srt[] =
	{
EOF

foreach (@srt1)
	{
	my $xr = $_;
	my ($p1, $p2) = @{$xref_tbl{$_}};
	print "\t{NID_$xr, NID_$p1, NID_$p2},\n";
	}

print "\t};";
print <<EOF;


static const nid_triple * const sigoid_srt_xref[] =
	{
EOF

foreach (@srt2)
	{
	my $x = $xref_tbl{$_}[2];
	print "\t\&sigoid_srt\[$x\],\n";
	}

print "\t};\n\n";

sub check_oid
	{
	my ($chk) = @_;
	if (!exists $oid_tbl{$chk})
		{
		die "Not Found \"$chk\"\n";
		}
	}

