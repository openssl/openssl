#!/usr/local/bin/perl -w
#
# This is a utility that searches out "DECLARE_STACK_OF()"
# declarations in header files, and updates/creates/replaces
# the corresponding macro declarations that follow it. The
# reason is that with "DEBUG_SAFESTACK" defined, each type
# will generate 19 functions, all type-safe variants of the
# base "sk_***" functions for the general STACK type. Without
# DEBUG_SAFESTACK defined, we need to macro define all the
# "type'd sk_##type##_***" functions as mapping directly to
# the standard sk_*** equivalents. As it's not generally
# possible to have macros that generate macros, we need to
# control this from the "outside", here in this script.
#
# Geoff Thorpe, June, 2000 (with massive Perl-hacking
#                           help from Steve Robb)

my $type_thing;
my $recurse = 0;
my @files = @ARGV;

while (@ARGV) {
	my $arg = $ARGV[0];
	if($arg eq "-recurse") {
		$recurse = 1;
		shift @ARGV;
	} else {
		last;
	}
}

if($recurse) {
	@source = (<crypto/*.[ch]>, <crypto/*/*.[ch]>, <rsaref/*.[ch]>, <ssl/*.[ch]>);
} else {
	@source = @ARGV;
}

foreach $file (@source) {
	# After "Configure" has been run, we need to make sure we don't
	# overwrite symbollic links with new header files!
	next if -l $file;

	# Open the .c/.h file for reading
	open(IN, "< $file") || die "Can't open $file for reading: $!";

	while(<IN>) {
		if (/^DECLARE_STACK_OF\(([^)]+)\)/) {
			push @stacklst, $1;
		}
	}
	close(IN);
	write_defines("crypto/stack/safestack");
	unlink("crypto/stack/safestack.h");
	rename("crypto/stack/safestack.tmp","crypto/stack/safestack.h");
}

sub write_defines {

	my $stackfile = $_[0];
	my $inside_block = 0;
	open IN, "< $stackfile.h" || die "Can't open input file";
	open OUT, "> $stackfile.tmp" || die "Can't open output file";
	while(<IN>) {
		if (m|^/\* This block of defines is updated by a perl script, please do not touch! \*/|) {
			$inside_block = 1;
		}
		if (m|^/\* End of perl script block, you may now edit :-\) \*/|) {
			$inside_block = 0;
		} elsif ($inside_block == 0) {
			print OUT;
		}
		next if($inside_block != 1);
		print OUT <<EOF;
/* This block of defines is updated by a perl script, please do not touch! */
EOF
	foreach $type_thing (@stacklst) {
print OUT <<EOF;
	#define sk_${type_thing}_new(a) SKM_sk_new($type_thing, (a))
	#define sk_${type_thing}_new_null() SKM_sk_new_null($type_thing)
	#define sk_${type_thing}_free(a) SKM_sk_free($type_thing, (a))
	#define sk_${type_thing}_num(a) SKM_sk_num($type_thing, (a))
	#define sk_${type_thing}_value(a,b) SKM_sk_value($type_thing, (a), (b))
	#define sk_${type_thing}_set(a,b,c) SKM_sk_set($type_thing, (a), (b), (c))
	#define sk_${type_thing}_zero(a) SKM_sk_zero($type_thing, (a))
	#define sk_${type_thing}_push(a,b) SKM_sk_push($type_thing, (a),(b))
	#define sk_${type_thing}_unshift(a,b) SKM_sk_unshift($type_thing, (a),(b))
	#define sk_${type_thing}_find(a,b) SKM_sk_find($type_thing, (a), (b))
	#define sk_${type_thing}_delete(a,b) SKM_sk_delete($type_thing, (a),(b))
	#define sk_${type_thing}_delete_ptr(a,b) SKM_sk_delete_ptr($type_thing, (a),(b))
	#define sk_${type_thing}_insert(a,b,c) SKM_sk_insert($type_thing, (a),(b),(c))
	#define sk_${type_thing}_set_cmp_func(a,b) SKM_sk_set_cmp_func($type_thing, (a),(b))
	#define sk_${type_thing}_dup(a) SKM_sk_dup($type_thing, a)
	#define sk_${type_thing}_pop_free(a,b) SKM_sk_pop_free($type_thing, (a),(b))
	#define sk_${type_thing}_shift(a) SKM_sk_shift($type_thing, (a))
	#define sk_${type_thing}_pop(a) SKM_sk_pop($type_thing, (a))
	#define sk_${type_thing}_sort(a) SKM_sk_sort($type_thing, (a))

EOF
	}
print OUT <<EOF;
/* End of perl script block, you may now edit :-) */
EOF
	$inside_block = 2;
	}
	close OUT;
}
