package platform::CMake;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::BASE;
@ISA = qw(platform::BASE);

# Assume someone set @INC right before loading this module
use configdata;

sub binext              { '.exe' }
sub objext              { '.obj' }
sub libext              { '.a' }
sub dsoext              { '.dll' }
sub defext              { '.def' }
sub asmext              { '.asm' }

# Other extra that aren't defined in platform::BASE
sub resext              { '.res' }
sub shlibext            { '.dll' }
sub shlibextimport      { $target{shared_import_extension} || '.dll.a' }
sub shlibextsimple      { undef }
sub shlibvariant        { $target{shlib_variant} || '' }
sub makedepcmd          { $disabled{makedepend} ? undef : $config{makedepcmd} }

# CMake will handle object files for us.
sub issrc               { return $_[1] =~ m/\.(S|s|asm|c|cc|cpp|rc|def)$/; }

# To mark forward compatibility, we include the OpenSSL major release version
# number in the installed shared library names.
(my $sover_filename = $config{shlib_version}) =~ s|\.|_|g;
sub shlib_version_as_filename {
    return $sover_filename
}
sub sharedname {
    return platform::BASE::__concat(platform::BASE->sharedname($_[1]),
                                    "_",
                                    $_[0]->shlib_version_as_filename());
}

# With Mingw and other DLL producers, there isn't any "simpler" shared
# library name.  However, there is a static import library.
sub sharedlib_simple {
    return undef;
}

sub sharedlib_import {
    return platform::BASE::__concat(platform::BASE->sharedname($_[1]),
                                    $_[0]->shlibextimport());
}

1;
