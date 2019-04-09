package platform::Windows::MSVC;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::Windows;
@ISA = qw(platform::Windows);

# Assume someone set @INC right before loading this module
use configdata;

sub pdbext              { '.pdb' }

sub staticlibpdb {
    return platform::BASE::__concat($_[0]->staticname($_[1]), $_[0]->pdbext());
}

sub sharedlibpdb {
    return platform::BASE::__concat($_[0]->sharedname($_[1]), $_[0]->pdbext());
}

sub dsopdb {
    return platform::BASE::__concat($_[0]->dsoname($_[1]), $_[0]->pdbext());
}

sub binpdb {
    return platform::BASE::__concat($_[0]->binname($_[1]), $_[0]->pdbext());
}

1;
