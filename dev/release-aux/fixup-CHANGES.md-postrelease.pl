#! /usr/bin/env perl -pi

BEGIN {
    our $count = 1;              # Only the first one
    our $RELEASE = $ENV{RELEASE};
    our $RELEASE_DATE = $ENV{RELEASE_DATE};

    $RELEASE =~ s/-dev//;
}

if (/^### Changes between (\S+) and (\S+) \[xx XXX xxxx\]/
    && $count-- > 0) {
    my $v1 = $1;
    my $v2 = $2;

    # If this is a pre-release, we do nothing
    if ($RELEASE !~ /^\d+\.\d+\.\d+-(?:alpha|beta)/) {
        $_ = <<_____
### Changes between $v2 and $RELEASE [xx XXX xxxx] ###

 * 

### Changes between $v1 and $v2 [$RELEASE_DATE] ###
_____
    }
}
