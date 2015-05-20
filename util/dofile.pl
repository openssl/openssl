#! /usr/bin/perl
#
# Reads one or more template files and runs it through Text::Template
#
# It is assumed that this scripts is called with -Mconfigdata, a module
# that holds configuration data in %config

use strict;
use warnings;

# Because we know that Text::Template isn't a core Perl module, we use
# a fallback in case it's not installed on the system
use File::Basename;
use File::Spec::Functions;
use lib catdir(dirname(__FILE__));
use with_fallback qw(Text::Template);

# We actually expect to get the following hash tables from configdata:
#
#    %config
#    %target
#    %withargs
#
# We just do a minimal test to see that we got what we expected.
# $config{target} must exist as an absolute minimum.
die "You must run this script with -Mconfigdata\n" if !exists($config{target});

# Helper functions for the templates #################################

# It might be practical to quotify some strings and have them protected
# from possible harm.  These functions primarly quote things that might
# be interpreted wrongly by a perl eval.

# quotify1 STRING
# This adds quotes (") around the given string, and escapes any $, @, \,
# " and ' by prepending a \ to them.
sub quotify1 {
    my $s = shift @_;
    $s =~ s/([\$\@\\"'])/\\$1/g;
    '"'.$s.'"';
}

# quotify_l LIST
# For each defined element in LIST (i.e. elements that aren't undef), have
# it quotified with 'quotofy1'
sub quotify_l {
    map {
        if (!defined($_)) {
            ();
        } else {
            quotify1($_);
        }
    } @_;
}

# Error reporter #####################################################

# The error reporter uses %lines to figure out exactly which file the
# error happened and at what line.  Not that the line number may be
# the start of a perl snippet rather than the exact line where it
# happened.  Nothing we can do about that here.

my %lines = ();
sub broken {
    my %args = @_;
    my $filename = "<STDIN>";
    my $deducelines = 0;
    foreach (sort keys %lines) {
        $filename = $lines{$_};
        last if ($_ > $args{lineno});
        $deducelines += $_;
    }
    print STDERR $args{error}," in $filename, fragment starting at line ",$args{lineno}-$deducelines;
    undef;
}

# Template reading ###################################################

# Read in all the templates into $text, while keeping track of each
# file and its size in lines, to try to help report errors with the
# correct file name and line number.

my $prev_linecount = 0;
my $text =
    @ARGV
    ? join("", map { my $x = Text::Template::_load_text($_);
                     my $linecount = $x =~ tr/\n//;
                     $prev_linecount = ($linecount += $prev_linecount);
                     $lines{$linecount} = $_;
                     $x } @ARGV)
    : join("", <STDIN>);

# Engage! ############################################################

# Load the full template (combination of files) into Text::Template
# and fill it up with our data.  Output goes directly to STDOUT

my $template = Text::Template->new(TYPE => 'STRING', SOURCE => $text );
$template->fill_in(OUTPUT => \*STDOUT,
                   HASH => { config => \%config,
                             target => \%target,
                             withargs => \%withargs,
                             quotify1 => \&quotify1,
                             quotify_l => \&quotify_l },
                   DELIMITERS => [ "{-", "-}" ],
                   BROKEN => \&broken);
