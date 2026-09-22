package platform::Windows::Unix;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::Windows;
@ISA = qw(platform::Windows);

# Assume someone set @INC right before loading this module
use configdata;

sub makedepcmd          { $disabled{makedepend} ? undef : $config{makedepcmd} }

sub asmext              { '.s' }
sub resext              { '.res.obj' }

# As with Mingw, there is not any "simpler" shared library name
sub sharedlib_simple {
    return undef;
}

1;
