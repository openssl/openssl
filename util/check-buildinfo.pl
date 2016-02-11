#! /usr/bin/perl

my %MINFO_source = ();

open my $minfo, "MINFO" or die "Couldn't open MINFO: $!\n";
my $reldir = "";
my $searchterm = "";
my $goal = "";
while (<$minfo>) {
    s|\R$||;

    if (/^RELATIVE_DIRECTORY=(.*)$/) {
        $reldir=$1;
        next;
    }

    if (/^LIBSRC=(.*)$/) {
        my @src = sort split(/\s+/, $1);
        if ($reldir =~ m|^crypto(/.*)?$|) {
            $MINFO_source{"libcrypto|$reldir"} = [ @src ];
        } elsif ($reldir eq "ssl") {
            $MINFO_source{"libssl|$reldir"} = [ @src ];
        } elsif ($reldir ne "engines") {
            warn "LIBSRC found in MINFO for $reldir";
        }
        next;
    }

    if (/^(?:TEST)?LIBNAMES=(.*)$/) {
        my @names = sort split(/\s+/, $1);
        if ($reldir eq "engines") {
            push @{$MINFO_source{"engines|$reldir"}}, @names;
        } else {
            warn "(TEST)?LIBNAMES found in MINFO for $reldir";
        }
        next;
    }
    
    } elsif ($reldir eq "apps") {
        $searchterm = "EXE_SRC";
        $goal = "apps|openssl";
    } elsif ($reldir eq "engines") {
        $searchterm = "
