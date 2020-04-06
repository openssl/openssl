#! /usr/bin/env perl -p

BEGIN {
    our $count = 1;              # Only the first one
    our $RELEASE = $ENV{RELEASE};
    our $RELEASE_DATE = $ENV{RELEASE_DATE};
}

if (/^### Changes between (\S+) and (\S+) \[xx XXX xxxx\]/
    && $count-- > 0) {
    $_ = "### Changes between $1 and $2 [$RELEASE_DATE]$'";
}
