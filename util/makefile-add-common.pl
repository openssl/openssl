#!/usr/bin/perl -w
use strict;
use warnings;

sub dofile
{
    my ($file) = @_;
    my $file_out = $file.".tmp";
    my $content;

    open(IN,"<$file") || die "unable to open $file:$!\n";
    print STDERR "doing $file\n";

    open(OUT,">$file_out") || die "unable to open $file_out:$!\n";
    local $/ = undef;

    $content = <IN>;
    close(IN);

    if ($content =~ m,\n# DO NOT DELETE THIS LINE,) {
        if ($content !~ m,\n[ \t]*include \$\(TOP\)/Makefile\.common[ \t]*\n,) {
            $content =~ s,\n?\n# DO NOT DELETE THIS LINE,\n\ninclude \$(TOP)/Makefile.common\n\n# DO NOT DELETE THIS LINE,
        }
    }

    print OUT $content;
    close(OUT);

    if (!exists($ENV{'MAKEFILE_UTIL_NO_REPLACE'})) {
        rename("$file_out",$file) || die "unable to rename $file_out to $file:$!\n";
    }

    return 1;
}

if (@ARGV < 1) {
    die "Usage: perl makefile-add-common.pl FILENAME";
}

dofile($ARGV[0]);
1;
