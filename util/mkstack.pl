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
	open(OUT, "> $file.tmp") || die "Can't open $file.tmp for writing: $!";

	select(OUT);
	process_the_file();

	close(OUT);
	close(IN);

	unlink($file);
	rename("$file.tmp", $file);
}

sub process_the_file {

	my $inside_block = 0;
	my $output_defines = 0;

	while(<IN>) {
		if (/^DECLARE_STACK_OF\(([^)]+)\)/) {
			$type_thing = $1;
			$output_defines = 1;
		}
		if (m|^/\* This block of defines is updated by a perl script, please do not touch! \*/|) {
			$inside_block = 1;
		}
		if (m|^/\* End of perl script block, you may now edit :-\) \*/|) {
			$inside_block = 0;
		} elsif ($inside_block == 0) {
			print;
		}
		if($output_defines == 1) {
			print <<EOF;
/* This block of defines is updated by a perl script, please do not touch! */
#ifndef DEBUG_SAFESTACK
	#define sk_${type_thing}_new(a) sk_new((int (*) \\
		(const char * const *, const char * const *))(a))
	#define sk_${type_thing}_new_null() sk_new_null()
	#define sk_${type_thing}_free(a) sk_free(a)
	#define sk_${type_thing}_num(a) sk_num(a)
	#define sk_${type_thing}_value(a,b) ((${type_thing} *) \\
		sk_value((a),(b)))
	#define sk_${type_thing}_set(a,b,c) ((${type_thing} *) \\
		sk_set((a),(b),(char *)(c)))
	#define sk_${type_thing}_zero(a) sk_zero(a)
	#define sk_${type_thing}_push(a,b) sk_push((a),(char *)(b))
	#define sk_${type_thing}_unshift(a,b) sk_unshift((a),(b))
	#define sk_${type_thing}_find(a,b) sk_find((a), (char *)(b))
	#define sk_${type_thing}_delete(a,b) ((${type_thing} *) \\
		sk_delete((a),(b)))
	#define sk_${type_thing}_delete_ptr(a,b) ((${type_thing} *) \\
		sk_delete_ptr((a),(char *)(b)))
	#define sk_${type_thing}_insert(a,b,c) sk_insert((a),(char *)(b),(c))
	#define sk_${type_thing}_set_cmp_func(a,b) ((int (*) \\
		(const ${type_thing} * const *,const ${type_thing} * const *)) \\
		sk_set_cmp_func((a),(int (*) \\
		(const char * const *, const char * const *))(b)))
	#define sk_${type_thing}_dup(a) sk_dup(a)
	#define sk_${type_thing}_pop_free(a,b) sk_pop_free((a),(void (*)(void *))(b))
	#define sk_${type_thing}_shift(a) ((${type_thing} *)sk_shift(a))
	#define sk_${type_thing}_pop(a) ((${type_thing} *)sk_pop(a))
	#define sk_${type_thing}_sort(a) sk_sort(a)
#endif /* !DEBUG_SAFESTACK */
/* End of perl script block, you may now edit :-) */
EOF
			$output_defines = 0;
		}
	}
}
