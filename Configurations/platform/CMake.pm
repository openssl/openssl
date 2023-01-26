package platform::CMake;

use strict;
use warnings;
use Carp;

use vars qw(@ISA);

require platform::BASE;
@ISA = qw(platform::BASE);

# Assume someone set @INC right before loading this module
use configdata;

sub binext              { $target{exe_extension} || '' }
sub objext              { $target{obj_extension} || '.obj' }
sub libext              { $target{lib_extension} || '.a' }
sub dsoext              { $target{dso_extension} || platform->shlibextsimple()
                              || '.so' }
sub defext              { $target{def_extension} || '.def' }
sub asmext              { $^O eq 'msys' or
                          $^O eq 'MSWin32' or
                          $config{target} =~ m|^mingw| ? '.asm' : '.s' }

# Other extra that aren't defined in platform::BASE
sub resext              { '.res' }
# Because these are also used in scripts and not just Makefile, we must
# convert $(SHLIB_VERSION_NUMBER) to the actual number.
sub shlibext_unix       { (my $x = $target{shared_extension}
                               || '.so.$(SHLIB_VERSION_NUMBER)')
                              =~ s|\.\$\(SHLIB_VERSION_NUMBER\)
                                  |.$config{shlib_version}|x;
                          $x; }
sub shlibext            { '.dll' }
sub shlibextimport      { $target{shared_import_extension} || '.dll.a' }
# Other extra that aren't defined in platform::BASE
sub shlibextsimple      { (my $x = $target{shared_extension} || '.so')
                              =~ s|\.\$\(SHLIB_VERSION_NUMBER\)||;
                          $x; }
sub shlibvariant        { $target{shlib_variant} || "" }
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
    return undef;
}

1;
