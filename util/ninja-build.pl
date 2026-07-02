#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Basename qw(basename dirname);
use File::Copy qw(copy);
use File::Find;
use File::Path qw(make_path remove_tree);
use File::Spec::Functions qw(:DEFAULT rel2abs file_name_is_absolute canonpath);
use Text::ParseWords qw(shellwords);

use lib '.';
use configdata;

my $srcdir = rel2abs($config{sourcedir});
my $blddir = rel2abs($config{builddir});
unshift @INC, catdir($srcdir, 'Configurations');
require platform;

my $action = shift @ARGV // usage();
my $builder_platform = $target{build_scheme}->[1] // '';
my $native_windows = $builder_platform eq 'windows';
my $destdir = $ENV{DESTDIR} // '';
my $buildfile = $config{build_file} || 'build.ninja';

my %dirs = install_dirs();
my %actions = (
    clean                  => \&clean,
    distclean              => \&distclean,
    depend                 => \&depend,
    install_ssldirs        => \&install_ssldirs,
    install_dev            => \&install_dev,
    uninstall_dev          => \&uninstall_dev,
    install_modules        => \&install_modules,
    uninstall_modules      => \&uninstall_modules,
    install_runtime_libs   => \&install_runtime_libs,
    uninstall_runtime_libs => \&uninstall_runtime_libs,
    install_programs       => \&install_programs,
    uninstall_programs     => \&uninstall_programs,
    install_fips           => \&install_fips,
    uninstall_fips         => \&uninstall_fips,
    install_man_docs       => \&install_man_docs,
    uninstall_man_docs     => \&uninstall_man_docs,
    install_html_docs      => \&install_html_docs,
    uninstall_html_docs    => \&uninstall_html_docs,
    install_image_docs     => \&install_image_docs,
    uninstall_image_docs   => \&uninstall_image_docs,
    uninstall_docs         => \&uninstall_docs,
);

usage() unless exists $actions{$action};
$actions{$action}->();

sub usage {
    die "Usage: perl util/ninja-build.pl <action>\n";
}

sub split_path {
    return grep { $_ ne '' } split m|[\\/]+|, shift;
}

sub srcpath {
    my $path = shift;
    return $path if file_name_is_absolute($path);
    return catfile($srcdir, split_path($path));
}

sub bldpath {
    my $path = shift;
    return $path if file_name_is_absolute($path);
    return catfile($blddir, split_path($path));
}

sub dest_path {
    my $path = canonpath(shift);
    return $path if $destdir eq '';

    if ($native_windows) {
        $path =~ s|^[A-Za-z]:||;
        $path =~ s|^[\\/]+||;
        return catfile($destdir, split_path($path));
    }

    return $destdir . $path;
}

sub install_dirs {
    my %d;

    if ($native_windows) {
        my $install_flavour = $target{build_scheme}->[$#{$target{build_scheme}}];
        my $win_installenv = $install_flavour eq 'VC-WOW'
            ? 'ProgramFiles(x86)' : 'ProgramW6432';
        my $win_commonenv = $install_flavour eq 'VC-WOW'
            ? 'CommonProgramFiles(x86)' : 'CommonProgramW6432';
        my $win_installroot = defined $ENV{$win_installenv}
            ? $ENV{$win_installenv} : $ENV{ProgramFiles};
        my $win_commonroot = defined $ENV{$win_commonenv}
            ? $ENV{$win_commonenv} : $ENV{CommonProgramFiles};

        $d{installtop} = canonpath($config{prefix}
                                   || catdir($win_installroot, 'OpenSSL'));
        $d{openssldir} = $config{openssldir}
            ? (file_name_is_absolute($config{openssldir})
               ? canonpath($config{openssldir})
               : catdir($d{installtop}, $config{openssldir}))
            : canonpath(catdir($win_commonroot, 'SSL'));
        my $libdir = $config{libdir} || 'lib';
        $d{libdir_rel} = file_name_is_absolute($libdir) ? '' : $libdir;
        $d{libdir} = file_name_is_absolute($libdir)
            ? canonpath($libdir) : catdir($d{installtop}, $libdir);
        $d{bindir_rel} = 'bin';
        $d{bindir} = catdir($d{installtop}, 'bin');
        $d{modulesdir} = catdir($d{libdir}, 'ossl-modules');
        $d{cmakeconfigdir} = catdir($d{libdir}, 'cmake', 'OpenSSL');
        $d{htmldir} = catdir($d{installtop}, 'html');
    } else {
        $d{installtop} = $config{prefix} || '/usr/local';
        $d{openssldir} = $config{openssldir}
            ? (file_name_is_absolute($config{openssldir})
               ? $config{openssldir}
               : catdir($d{installtop}, $config{openssldir}))
            : catdir($d{installtop}, 'ssl');
        my $libdir = $config{libdir} || 'lib' . ($target{multilib} // '');
        $d{libdir_rel} = file_name_is_absolute($libdir) ? '' : $libdir;
        $d{libdir} = file_name_is_absolute($libdir)
            ? $libdir : catdir($d{installtop}, $libdir);
        my $bindir = $config{bindir} || 'bin' . ($target{multibin} // '');
        $d{bindir_rel} = file_name_is_absolute($bindir) ? '' : $bindir;
        $d{bindir} = file_name_is_absolute($bindir)
            ? $bindir : catdir($d{installtop}, $bindir);
        $d{modulesdir} = catdir($d{libdir}, 'ossl-modules');
        $d{pkgconfigdir} = catdir($d{libdir}, 'pkgconfig');
        $d{cmakeconfigdir} = catdir($d{libdir}, 'cmake', 'OpenSSL');
        $d{mandir} = catdir($d{installtop}, 'share', 'man');
        $d{docdir} = catdir($d{installtop}, 'share', 'doc', 'openssl');
        $d{htmldir} = catdir($d{docdir}, 'html');
    }

    return %d;
}

sub check_installtop {
    die "INSTALLTOP should not be empty\n" if !defined $dirs{installtop}
        || $dirs{installtop} eq '';
}

sub run {
    system(@_) == 0 or die "Command failed: @_\n";
}

sub capture_to_file {
    my ($outfile, @cmd) = @_;
    my $tmp = "$outfile.tmp";
    make_path(dirname($outfile));

    open my $in, '-|', @cmd or die "Cannot run @cmd: $!\n";
    open my $out, '>', $tmp or die "Cannot open $tmp for writing: $!\n";
    while (my $line = <$in>) {
        print $out $line or die "Cannot write to $tmp: $!\n";
    }
    close $in or die "Command failed: @cmd\n";
    close $out or die "Cannot close $tmp: $!\n";
    rename $tmp, $outfile or die "Cannot rename $tmp to $outfile: $!\n";
}

sub rm_f {
    for my $path (@_) {
        next unless defined $path && $path ne '';
        unlink $path if -e $path || -l $path;
    }
}

sub rm_rf {
    for my $path (@_) {
        next unless defined $path && $path ne '';
        remove_tree($path, { safe => 1 }) if -e $path;
    }
}

sub maybe_rmdir {
    for my $path (@_) {
        next unless defined $path && $path ne '';
        rmdir $path if -d $path;
    }
}

sub copy_file {
    my ($src, $dst, $mode, $atomic) = @_;
    die "No such file: $src\n" unless -f $src;
    make_path(dirname($dst));

    my $tmp = $atomic ? "$dst.new" : $dst;
    unlink $tmp if -e $tmp || -l $tmp;
    copy($src, $tmp) or die "Cannot copy $src to $tmp: $!\n";
    chmod $mode, $tmp if defined $mode;
    if ($atomic) {
        unlink $dst if -e $dst || -l $dst;
        rename $tmp, $dst or die "Cannot rename $tmp to $dst: $!\n";
    }
    print "install $src -> $dst\n";
}

sub copy_to_dir {
    my ($src, $dir, $mode, $atomic) = @_;
    copy_file($src, catfile($dir, basename($src)), $mode, $atomic);
}

sub optional_copy_to_dir {
    my ($src, $dir, $mode, $atomic) = @_;
    copy_to_dir($src, $dir, $mode, $atomic) if defined $src && -f $src;
}

sub list_dir_files {
    my ($dir, $re) = @_;
    return () unless -d $dir;
    opendir my $dh, $dir or die "Cannot open directory $dir: $!\n";
    my @files = map { catfile($dir, $_) }
                grep { /$re/ && -f catfile($dir, $_) } readdir $dh;
    closedir $dh;
    return sort @files;
}

sub attr {
    my ($kind, $name, $attr) = @_;
    return $unified_info{attributes}->{$kind}->{$name}->{$attr};
}

sub generated_files {
    my %generatables =
        map { $_ => 1 }
        ((map { @{$unified_info{sources}->{$_}} }
              keys %{$unified_info{sources}}),
         ($disabled{shared}
          ? ()
          : map { @{$unified_info{shared_sources}->{$_}} }
                keys %{$unified_info{shared_sources}}),
         (map { $_ eq '' ? () : @{$unified_info{depends}->{$_}} }
              keys %{$unified_info{depends}}));

    return sort((grep { defined $unified_info{generate}->{$_} }
                 sort keys %generatables),
                (grep { defined $unified_info{sources}->{$_} }
                 @{$unified_info{scripts}}));
}

sub build_modules {
    return map { platform->dso($_) }
           grep {
               my $x = $_;
               !grep { grep { $_ eq $x } @$_ } values %{$unified_info{depends}};
           } @{$unified_info{modules}};
}

sub fips_modules {
    return grep { !attr('modules', $_, 'noinst')
                  && attr('modules', $_, 'fips') }
           @{$unified_info{modules}};
}

sub install_modules_list {
    return map { platform->dso($_) }
           grep { !attr('modules', $_, 'noinst')
                  && !attr('modules', $_, 'fips') }
           @{$unified_info{modules}};
}

sub install_programs_list {
    return map { platform->bin($_) }
           grep { !attr('programs', $_, 'noinst') }
           @{$unified_info{programs}};
}

sub install_libs_list {
    return map {
               $native_windows
                   ? (platform->sharedlib_import($_) // platform->staticlib($_))
                   : (platform->staticlib($_) // ())
           }
           grep { !attr('libraries', $_, 'noinst') }
           @{$unified_info{libraries}};
}

sub install_shlibs {
    return map { platform->sharedlib($_) // () }
           grep { !attr('libraries', $_, 'noinst') }
           @{$unified_info{libraries}};
}

sub shlib_info {
    my ($install_only) = @_;
    my @libs = $install_only
        ? grep { !attr('libraries', $_, 'noinst') } @{$unified_info{libraries}}
        : @{$unified_info{libraries}};
    return map {
        my $full = platform->sharedlib($_);
        $full ? [ $full,
                  platform->sharedlib_simple($_) // '',
                  platform->sharedlib_import($_) // '' ] : ();
    } @libs;
}

sub exporter_files {
    my ($type) = @_;
    return grep {
        ($unified_info{attributes}->{generate}->{$_}->{exporter} // '') eq $type
    } sort keys %{$unified_info{generate}};
}

sub lib_ex_libs {
    return join(' ', $target{ex_libs} || (),
                     @{$config{ex_libs}},
                     @{$config{LDLIBS}});
}

sub input_path {
    my $path = shift;
    return $path if file_name_is_absolute($path) || -f $path;
    my $src = srcpath($path);
    return $src if -f $src;
    return bldpath($path);
}

sub ensure_installdata {
    my $outfile = bldpath('installdata.pm');
    return if -f $outfile;

    my @args = (
        'COMMENT=This file provides configuration information for OpenSSL',
        'PREFIX=' . $dirs{installtop},
        'BINDIR=' . $dirs{bindir_rel},
        'LIBDIR=' . $dirs{libdir_rel},
        'libdir=' . $dirs{libdir},
        'INCLUDEDIR=include',
        'APPLINKDIR=include/openssl',
        'MODULESDIR=' . $dirs{modulesdir},
        'PKGCONFIGDIR=' . ($dirs{pkgconfigdir} // ''),
        'CMAKECONFIGDIR=' . $dirs{cmakeconfigdir},
        'LDLIBS=' . lib_ex_libs(),
        'VERSION=' . $config{full_version},
    );
    capture_to_file($outfile, $config{PERL}, srcpath(catfile('util', 'mkinstallvars.pl')),
                    @args);
}

sub ensure_generated {
    my $file = shift;
    my $outfile = bldpath($file);
    return if -f $outfile;

    ensure_installdata() if ($unified_info{attributes}->{generate}->{$file}->{exporter} // '');

    my $generator = $unified_info{generate}->{$file}
        or die "No generator known for $file\n";
    my ($template, @args) = @$generator;

    my @cmd = ($config{PERL}, '-I.', '-Mconfigdata');
    push @cmd, '-Minstalldata' if -f bldpath('installdata.pm');
    push @cmd, srcpath(catfile('util', 'dofile.pl')),
               "-o$buildfile", input_path($template), @args;

    capture_to_file($outfile, @cmd);
    chmod 0444, $outfile;
}

sub bin_scripts {
    my ($misc) = @_;
    return map {
               my $linkname = attr('scripts', $_, 'linkname');
               !$native_windows && $linkname ? "$_:$linkname" : $_;
           }
           grep { !attr('scripts', $_, 'noinst')
                  && (!!attr('scripts', $_, 'misc') == !!$misc) }
           @{$unified_info{scripts}};
}

sub windowsdll {
    return $config{target} =~ /^(?:Cygwin|mingw)/;
}

sub sharedaix {
    return !$disabled{shared} && ($target{shared_target} // '') =~ /^aix(?!-solib$)/;
}

sub sharedaix_solib {
    return !$disabled{shared} && ($target{shared_target} // '') =~ /^aix-solib$/;
}

sub clean {
    for my $info (shlib_info(0)) {
        my ($full, $simple, $import) = @$info;
        rm_f(bldpath($full), bldpath($simple), bldpath($import));
        if (windowsdll()) {
            rm_f(map { bldpath(catfile($_, basename($full))) } qw(apps test fuzz));
        }
    }

    rm_f(map { bldpath($_) }
         (map { platform->staticlib($_) // () } @{$unified_info{libraries}}),
         (map { platform->bin($_) } @{$unified_info{programs}}),
         build_modules(),
         (map { platform->dso($_) } fips_modules()),
         @{$unified_info{scripts}},
         @{$unified_info{depends}->{''} // []},
         (map { platform->convertext($_) } generated_files()),
         (map { @{$unified_info{htmldocs}->{$_}} } qw(man1 man3 man5 man7)),
         (map { @{$unified_info{mandocs}->{$_}} } qw(man1 man3 man5 man7)));

    rm_f(glob('*' . platform->defext())) if !$native_windows;
    rm_f(bldpath('core'), bldpath('tags'), bldpath('TAGS'),
         bldpath('doc-nits'), bldpath('md-nits'));
    rm_rf(bldpath('test-runs'));
    rm_f(glob(catfile('providers', 'fips*.new')));

    if ($native_windows) {
        find({ wanted => sub {
                   return if -d $_;
                   rm_f($File::Find::name)
                       if /\.(?:d|obj|pdb|ilk|manifest|rsp)\z/i;
               }, no_chdir => 1 }, '.');
        rm_f(glob(catfile('apps', '*.' . $_))) for qw(lib rc res exp);
        rm_f(glob(catfile('test', '*.exp')));
    } else {
        my $dep_ext = $target{dep_extension} || platform->depext();
        my $obj_ext = $target{obj_extension} || platform->objext();
        find({ wanted => sub {
                   return if $_ =~ /^\./;
                   return if -d $_;
                   rm_f($File::Find::name)
                       if /\Q$dep_ext\E\z/ || /\Q$obj_ext\E\z/ || /\.rsp\z/;
               }, no_chdir => 1 }, '.');
        find({ wanted => sub {
                   return if $File::Find::name =~ m|^\./pkcs11-provider/|;
                   return if $_ =~ /^\./;
                   rm_f($File::Find::name) if -l $File::Find::name;
               }, no_chdir => 1 }, '.');
    }
}

sub distclean {
    rm_f(bldpath(catfile('include', 'openssl', 'configuration.h')),
         bldpath('configdata.pm'),
         bldpath($buildfile));
}

sub depend {
    if ($disabled{makedepend}) {
        print "Dependency tracking is disabled for this configuration\n";
    } else {
        print "Ninja records compiler dependencies while building\n";
    }
}

sub install_ssldirs {
    check_installtop();
    my $ossl = dest_path($dirs{openssldir});
    make_path(catdir($ossl, 'certs'), catdir($ossl, 'private'), catdir($ossl, 'misc'));

    for my $cnf (qw(openssl.cnf ct_log_list.cnf)) {
        my $src = srcpath(catfile('apps', $cnf));
        copy_file($src, catfile($ossl, "$cnf.dist"), 0644, 1);
        copy_file($src, catfile($ossl, $cnf), 0644, 0)
            unless -e catfile($ossl, $cnf);
    }

    for my $spec (bin_scripts(1)) {
        my ($script, $linkname) = split /:/, $spec, 2;
        my $src = bldpath($script);
        my $dst = catfile($ossl, 'misc', basename($script));
        copy_file($src, $dst, 0755, 1);
        if (defined $linkname && $linkname ne '') {
            my $link = catfile($ossl, 'misc', basename($linkname));
            rm_f($link);
            if (windowsdll() || $native_windows) {
                copy_file($dst, $link, 0755, 0);
            } else {
                symlink basename($script), $link
                    or die "Cannot symlink $link to " . basename($script) . ": $!\n";
                print "link $link -> " . basename($script) . "\n";
            }
        }
    }
}

sub install_runtime_libs {
    check_installtop();
    return if $disabled{shared};
    my $dir = dest_path(windowsdll() || $native_windows
                        ? $dirs{bindir} : $dirs{libdir});
    make_path($dir);
    print "*** Installing runtime libraries\n";
    copy_to_dir(bldpath($_), $dir, 0755, 1) for install_shlibs();

    if ($native_windows && platform->can('sharedlibpdb')) {
        optional_copy_to_dir(bldpath(platform->sharedlibpdb($_)), $dir, 0644, 0)
            for grep { !attr('libraries', $_, 'noinst') } @{$unified_info{libraries}};
    }
}

sub install_dev {
    check_installtop();
    print "*** Installing development files\n";
    my $includedir = dest_path(catdir($dirs{installtop}, 'include', 'openssl'));
    my $libdir = dest_path($dirs{libdir});
    make_path($includedir, $libdir);

    if (!$disabled{uplink}) {
        copy_to_dir(srcpath(catfile('ms', 'applink.c')), $includedir, 0644, 0);
    }

    for my $h (list_dir_files(srcpath(catdir('include', 'openssl')), qr/\.h\z/)) {
        next if $native_windows && basename($h) =~ /__DECC_/;
        copy_to_dir($h, $includedir, 0644, 0);
    }
    copy_to_dir($_, $includedir, 0644, 0)
        for list_dir_files(bldpath(catdir('include', 'openssl')), qr/\.h\z/);

    for my $lib (install_libs_list()) {
        my $src = bldpath($lib);
        my $dst = catfile($libdir, basename($lib));
        copy_file($src, $dst, 0644, 1);
        run(shellwords(($config{CROSS_COMPILE} // '') . $config{RANLIB}), $dst)
            if !$native_windows && $config{RANLIB};
    }

    if (!$disabled{shared} && !$native_windows) {
        for my $info (shlib_info(1)) {
            my ($full, $simple, $import) = @$info;
            if (!windowsdll() && !sharedaix() && !sharedaix_solib() && $simple ne '') {
                my $link = catfile($libdir, basename($simple));
                rm_f($link);
                symlink basename($full), $link
                    or die "Cannot symlink $link to " . basename($full) . ": $!\n";
                print "link $link -> " . basename($full) . "\n";
            } elsif ((windowsdll() || sharedaix_solib()) && $import ne '') {
                copy_to_dir(bldpath($import), $libdir, 0644, 1);
            }
        }
    }

    if (!$native_windows) {
        my $pcdir = dest_path($dirs{pkgconfigdir});
        make_path($pcdir);
        for my $e (exporter_files('pkg-config')) {
            ensure_generated($e);
            copy_to_dir(bldpath($e), $pcdir, 0644, 0);
        }
    }

    my $cmakedir = dest_path($dirs{cmakeconfigdir});
    make_path($cmakedir);
    for my $e (exporter_files('cmake')) {
        ensure_generated($e);
        copy_to_dir(bldpath($e), $cmakedir, 0644, 0);
    }
}

sub uninstall_dev {
    print "*** Uninstalling development files\n";
    my $includedir = dest_path(catdir($dirs{installtop}, 'include', 'openssl'));
    my $libdir = dest_path($dirs{libdir});

    rm_f(catfile($includedir, 'applink.c')) if !$disabled{uplink};
    rm_f(catfile($includedir, basename($_)))
        for list_dir_files(srcpath(catdir('include', 'openssl')), qr/\.h\z/),
            list_dir_files(bldpath(catdir('include', 'openssl')), qr/\.h\z/);
    maybe_rmdir($includedir, dirname($includedir));

    rm_f(catfile($libdir, basename($_))) for install_libs_list();
    if (!$disabled{shared} && !$native_windows) {
        for my $info (shlib_info(1)) {
            rm_f(catfile($libdir, basename($_))) for grep { $_ ne '' } @$info;
        }
    }

    if (!$native_windows) {
        my $pcdir = dest_path($dirs{pkgconfigdir});
        rm_f(catfile($pcdir, basename($_))) for exporter_files('pkg-config');
        maybe_rmdir($pcdir);
    }
    my $cmakedir = dest_path($dirs{cmakeconfigdir});
    rm_f(catfile($cmakedir, basename($_))) for exporter_files('cmake');
    maybe_rmdir($cmakedir, dirname($cmakedir), $libdir);
}

sub install_modules {
    check_installtop();
    my $dir = dest_path($dirs{modulesdir});
    make_path($dir);
    print "*** Installing modules\n";
    copy_to_dir(bldpath($_), $dir, 0755, 1) for install_modules_list();

    if ($native_windows && platform->can('dsopdb')) {
        optional_copy_to_dir(bldpath(platform->dsopdb($_)), $dir, 0644, 0)
            for grep { !attr('modules', $_, 'noinst') && !attr('modules', $_, 'fips') }
                @{$unified_info{modules}};
    }
}

sub uninstall_modules {
    print "*** Uninstalling modules\n";
    my $dir = dest_path($dirs{modulesdir});
    rm_f(catfile($dir, basename($_))) for install_modules_list();
    maybe_rmdir($dir);
}

sub install_programs {
    check_installtop();
    my $dir = dest_path($dirs{bindir});
    make_path($dir);
    print "*** Installing runtime programs\n";
    copy_to_dir(bldpath($_), $dir, 0755, 1) for install_programs_list();

    if ($native_windows && platform->can('binpdb')) {
        optional_copy_to_dir(bldpath(platform->binpdb($_)), $dir, 0644, 0)
            for grep { !attr('programs', $_, 'noinst') } @{$unified_info{programs}};
    }

    for my $spec (bin_scripts(0)) {
        my ($script, $linkname) = split /:/, $spec, 2;
        copy_to_dir(bldpath($script), $dir, 0755, 1);
        if (defined $linkname && $linkname ne '') {
            my $link = catfile($dir, basename($linkname));
            rm_f($link);
            symlink basename($script), $link
                or die "Cannot symlink $link to " . basename($script) . ": $!\n";
        }
    }
}

sub uninstall_programs {
    print "*** Uninstalling runtime programs\n";
    my $dir = dest_path($dirs{bindir});
    rm_f(catfile($dir, basename($_))) for install_programs_list();
    for my $spec (bin_scripts(0)) {
        my ($script, $linkname) = split /:/, $spec, 2;
        rm_f(catfile($dir, basename($script)));
        rm_f(catfile($dir, basename($linkname))) if defined $linkname;
    }
    maybe_rmdir($dir);
}

sub uninstall_runtime_libs {
    print "*** Uninstalling runtime libraries\n";
    my $dir = dest_path(windowsdll() || $native_windows
                        ? $dirs{bindir} : $dirs{libdir});
    rm_f(catfile($dir, basename($_))) for install_shlibs();
    if ($native_windows && platform->can('sharedlibpdb')) {
        rm_f(catfile($dir, basename(platform->sharedlibpdb($_))))
            for grep { !attr('libraries', $_, 'noinst') } @{$unified_info{libraries}};
    }
}

sub install_fips {
    if ($disabled{fips}) {
        print "The 'install_fips' target requires the 'enable-fips' option\n";
        return;
    }

    check_installtop();
    my @mods = fips_modules();
    die "More than one FIPS module\n" if @mods > 1;
    return if @mods == 0;

    my $module = platform->dso($mods[0]);
    my $moduledir = dest_path($dirs{modulesdir});
    my $ossl = dest_path($dirs{openssldir});
    make_path($moduledir, $ossl);

    print "*** Installing FIPS module\n";
    copy_file(bldpath($module), catfile($moduledir, basename($module)), 0755, 1);
    print "*** Installing FIPS module configuration\n";
    copy_to_dir(bldpath(catfile('providers', 'fipsmodule.cnf')), $ossl, 0644, 0);
}

sub uninstall_fips {
    if ($disabled{fips}) {
        print "The 'uninstall_fips' target requires the 'enable-fips' option\n";
        return;
    }

    my @mods = fips_modules();
    die "More than one FIPS module\n" if @mods > 1;
    my $module = @mods ? platform->dso($mods[0]) : undef;
    print "*** Uninstalling FIPS module configuration\n";
    rm_f(catfile(dest_path($dirs{openssldir}), 'fipsmodule.cnf'));
    print "*** Uninstalling FIPS module\n";
    rm_f(catfile(dest_path($dirs{modulesdir}), basename($module))) if defined $module;
}

sub install_man_docs {
    return if $native_windows || $disabled{docs};
    check_installtop();
    my $mandir = dest_path($dirs{mandir});
    make_path(map { catdir($mandir, $_) } qw(man1 man3 man5 man7));
    print "*** Installing manpages\n";

    for my $section (qw(1 3 5 7)) {
        my $key = "man$section";
        my $dir = catdir($mandir, $key);
        for my $doc (@{$unified_info{mandocs}->{$key}}) {
            my $fn = basename($doc) . 'ossl';
            copy_file(bldpath($doc), catfile($dir, $fn), 0644, 0);
            run($config{PERL}, srcpath(catfile('util', 'write-man-symlinks')),
                'install', srcpath(catdir('doc', $key)), bldpath(catdir('doc', $key)),
                $fn, $dir);
        }
    }
}

sub uninstall_man_docs {
    return if $native_windows || $disabled{docs};
    print "*** Uninstalling manpages\n";
    my $mandir = dest_path($dirs{mandir});
    for my $section (qw(1 3 5 7)) {
        my $key = "man$section";
        my $dir = catdir($mandir, $key);
        for my $doc (@{$unified_info{mandocs}->{$key}}) {
            my $fn = basename($doc) . 'ossl';
            rm_f(catfile($dir, $fn));
            run($config{PERL}, srcpath(catfile('util', 'write-man-symlinks')),
                'uninstall', srcpath(catdir('doc', $key)), bldpath(catdir('doc', $key)),
                $fn, $dir);
        }
    }
}

sub install_html_docs {
    return if $disabled{docs};
    check_installtop();
    my $htmldir = dest_path($dirs{htmldir});
    make_path(map { catdir($htmldir, $_) } qw(man1 man3 man5 man7));
    print "*** Installing HTML manpages\n";
    for my $section (qw(1 3 5 7)) {
        my $key = "man$section";
        my $dir = catdir($htmldir, $key);
        copy_to_dir(bldpath($_), $dir, 0644, 0)
            for @{$unified_info{htmldocs}->{$key}};
    }
}

sub uninstall_html_docs {
    return if $disabled{docs};
    print "*** Uninstalling HTML manpages\n";
    my $htmldir = dest_path($dirs{htmldir});
    for my $section (qw(1 3 5 7)) {
        my $key = "man$section";
        my $dir = catdir($htmldir, $key);
        rm_f(catfile($dir, basename($_))) for @{$unified_info{htmldocs}->{$key}};
    }
}

sub install_image_docs {
    return if $disabled{docs};
    check_installtop();
    my $dir = dest_path(catdir($dirs{htmldir}, 'man7', 'img'));
    make_path($dir);
    print "*** Installing HTML images\n";
    copy_to_dir(srcpath($_), $dir, 0644, 0)
        for @{$unified_info{imagedocs}->{man7}};
}

sub uninstall_image_docs {
    return if $disabled{docs};
    my $dir = dest_path(catdir($dirs{htmldir}, 'man7', 'img'));
    rm_f(catfile($dir, basename($_))) for @{$unified_info{imagedocs}->{man7}};
}

sub uninstall_docs {
    return if $disabled{docs};
    rm_rf(dest_path($dirs{docdir})) if !$native_windows;
}
