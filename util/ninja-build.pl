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
use File::Compare qw(compare);
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
    check_format_cmd       => \&check_format_cmd,
    check_format           => \&check_format,
    doc_nits               => \&doc_nits,
    errors                 => \&errors,
    fips_checksums         => \&fips_checksums,
    generate_apps          => \&generate_apps,
    generate_crypto_asn1   => \&generate_crypto_asn1,
    generate_crypto_bn     => \&generate_crypto_bn,
    generate_crypto_conf   => \&generate_crypto_conf,
    generate_crypto_objects => \&generate_crypto_objects,
    generate_doc_buildinfo => \&generate_doc_buildinfo,
    generate_fips_sources  => \&generate_fips_sources,
    generate_fuzz_oids     => \&generate_fuzz_oids,
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
    lint                   => \&lint,
    md_nits                => \&md_nits,
    ordinals               => \&ordinals,
    renumber               => \&renumber,
    tags                   => \&tags,
    tar                    => \&tar,
    test_ordinals          => \&test_ordinals,
    update                 => \&update,
    update_fips_checksums  => \&update_fips_checksums,
    diff_fips_checksums    => \&diff_fips_checksums,
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

sub unix_developer_action {
    die "This action is only available for Unix-like targets\n"
        if $native_windows;
}

sub shell_quote {
    my $value = shift // '';
    $value =~ s/'/'"'"'/g;
    return "'$value'";
}

sub run_shell {
    run('/bin/sh', '-c', shift);
}

sub command_words {
    my ($env_name, $default) = @_;
    my @words = shellwords($ENV{$env_name} // $default);
    die "$env_name must name a command\n" unless @words;
    return @words;
}

sub command_exists {
    my $command = shift;
    return -x $command if $command =~ m|/|;
    return scalar grep { -x catfile($_, $command) }
                  grep { $_ ne '' } split /:/, ($ENV{PATH} // '');
}

sub generate_apps {
    unix_developer_action();
    run_shell('cd ' . shell_quote($srcdir)
              . ' && ' . shell_quote($config{PERL})
              . ' VMS/VMSify-conf.pl < apps/openssl.cnf > apps/openssl-vms.cnf');
}

sub generate_crypto_bn {
    unix_developer_action();
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    capture_to_file(srcpath(catfile('crypto', 'bn', 'bn_prime.h')),
                    $config{PERL},
                    srcpath(catfile('crypto', 'bn', 'bn_prime.pl')));
}

sub generate_crypto_objects {
    unix_developer_action();
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    my $objects_dir = srcpath(catdir('crypto', 'objects'));
    my $objects = catfile($objects_dir, 'objects.pl');
    my $objects_txt = catfile($objects_dir, 'objects.txt');
    my $obj_mac_num = catfile($objects_dir, 'obj_mac.num');
    my $obj_mac_new = catfile($objects_dir, 'obj_mac.new');
    my $obj_mac_h = srcpath(catfile('include', 'openssl', 'obj_mac.h'));

    capture_to_file($obj_mac_new, $config{PERL}, $objects, '-n',
                    $objects_txt, $obj_mac_num);
    rename $obj_mac_new, $obj_mac_num
        or die "Cannot rename $obj_mac_new to $obj_mac_num: $!\n";
    capture_to_file($obj_mac_h, $config{PERL}, $objects,
                    $objects_txt, $obj_mac_num);
    capture_to_file(catfile($objects_dir, 'obj_dat.h'), $config{PERL},
                    catfile($objects_dir, 'obj_dat.pl'), $obj_mac_h);
    capture_to_file(catfile($objects_dir, 'obj_xref.h'), $config{PERL},
                    catfile($objects_dir, 'objxref.pl'), $obj_mac_num,
                    catfile($objects_dir, 'obj_xref.txt'));

    open my $compat, '<', catfile($objects_dir, 'obj_compat.h')
        or die "Cannot open obj_compat.h: $!\n";
    scalar <$compat> for 1..8;
    open my $mac, '>>', $obj_mac_h or die "Cannot append to $obj_mac_h: $!\n";
    while (my $line = <$compat>) {
        print $mac $line or die "Cannot append to $obj_mac_h: $!\n";
    }
    close $compat or die "Cannot close obj_compat.h: $!\n";
    close $mac or die "Cannot close $obj_mac_h: $!\n";
}

sub generate_crypto_conf {
    unix_developer_action();
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    capture_to_file(srcpath(catfile('crypto', 'conf', 'conf_def.h')),
                    $config{PERL},
                    srcpath(catfile('crypto', 'conf', 'keysets.pl')));
}

sub generate_crypto_asn1 {
    unix_developer_action();
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    capture_to_file(srcpath(catfile('crypto', 'asn1', 'charmap.h')),
                    $config{PERL},
                    srcpath(catfile('crypto', 'asn1', 'charmap.pl')));
}

sub generate_fuzz_oids {
    unix_developer_action();
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    capture_to_file(srcpath(catfile('fuzz', 'oids.txt')), $config{PERL},
                    srcpath(catfile('fuzz', 'mkfuzzoids.pl')),
                    srcpath(catfile('crypto', 'objects', 'obj_dat.h')));
}

sub generate_doc_buildinfo {
    unix_developer_action();
    my $buildinfo = srcpath(catfile('doc', 'build.info'));
    my $new = "$buildinfo.new";
    capture_to_file($new, $config{PERL}, "-I$blddir", '-Mconfigdata',
                    srcpath(catfile('util', 'dofile.pl')), '-o', $buildfile,
                    srcpath(catfile('doc', 'build.info.in')));
    if (-e $buildinfo && compare($new, $buildinfo) == 0) {
        unlink $new or die "Cannot remove $new: $!\n";
    } else {
        rename $new, $buildinfo
            or die "Cannot rename $new to $buildinfo: $!\n";
    }
}

sub update {
    unix_developer_action();
    generate_apps();
    generate_crypto_bn();
    generate_crypto_objects();
    generate_crypto_conf();
    generate_crypto_asn1();
    generate_fuzz_oids();
    errors();
    ordinals();
    generate_doc_buildinfo();
}

sub doc_nits {
    unix_developer_action();
    chdir $blddir or die "Cannot change directory to $blddir: $!\n";
    run($config{PERL}, srcpath(catfile('util', 'find-doc-nits')),
        qw(-c -n -l -e -i -a));
}

sub md_nits {
    unix_developer_action();
    my @mdl = command_words('MDL', 'mdl');
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    run(@mdl, '-s', srcpath(catfile('util', 'markdownlint.rb')), '.');
}

sub ordinal_headers {
    my @sslheaders_tmpl = qw(
        include/openssl/ssl.h include/openssl/ssl2.h include/openssl/ssl3.h
        include/openssl/sslerr.h include/openssl/tls1.h
        include/openssl/dtls1.h include/openssl/srtp.h
        include/openssl/quic.h include/openssl/sslerr_legacy.h
        include/openssl/ech.h
    );
    my @cryptoheaders_tmpl = qw(
        include/internal/dso.h include/internal/o_dir.h include/internal/err.h
        include/internal/evp.h include/internal/pem.h include/internal/asn1.h
        include/internal/sslconf.h
    );
    my @cryptoskipheaders = (
        @sslheaders_tmpl,
        qw(include/openssl/conf_api.h include/openssl/ebcdic.h
           include/openssl/engine.h include/openssl/opensslconf.h
           include/openssl/symhacks.h)
    );
    my (%cryptoheaders, %sslheaders);

    for my $dir (qw(include/openssl include/internal)) {
        my @patterns = map { catfile($srcdir, split_path($dir), $_) }
                           qw(*.h *.h.in);
        for my $file (map { glob($_) } @patterns) {
            my $base = basename($file);
            my $base_in = basename($file, '.in');
            my $header_dir = catdir($srcdir, split_path($dir));
            if ($base ne $base_in) {
                $base = $base_in;
                $header_dir = catdir($blddir, split_path($dir));
            }
            my $new_file = catfile($header_dir, $base);
            my $name = "$dir/$base";
            $cryptoheaders{$new_file} = 1
                if (($dir eq 'include/openssl'
                     || grep { $_ eq $name } @cryptoheaders_tmpl)
                    && !grep { $_ eq $name } @cryptoskipheaders);
            $sslheaders{$new_file} = 1
                if grep { $_ eq $name } @sslheaders_tmpl;
        }
    }

    return ([ sort keys %cryptoheaders ], [ sort keys %sslheaders ]);
}

sub source_files {
    my (%seen, @sources);
    for my $product (sort keys %{$unified_info{sources}}) {
        for my $source (@{$unified_info{sources}->{$product}}) {
            my @flat = ref($source) eq 'ARRAY' ? @$source : ($source);
            push @sources, grep { /\.(?:c|cc|cpp)\z/ && !$seen{$_}++ } @flat;
        }
    }
    return @sources;
}

sub lint {
    unix_developer_action();
    my ($cryptoheaders, $sslheaders) = ordinal_headers();
    print join(' ', 'splint', '-DLINT', '-posixlib', '-preproc',
               '-D__gnuc_va_list=void', '-I.', '-Iinclude', '-Iapps/include',
               @$cryptoheaders, @$sslheaders, source_files()), "\n";
}

sub check_format_cmd {
    unix_developer_action();
    my @command = command_words('CLANG_FORMAT_DIFF', 'clang-format-diff');
    return if command_exists($command[0]);
    print STDERR "Unable to find $command[0]\n";
    print STDERR "Please set the CLANG_FORMAT_DIFF environment variable ",
                 "to your clang-format-diff command\n";
    exit 1;
}

sub check_format {
    unix_developer_action();
    my @command = command_words('CLANG_FORMAT_DIFF', 'clang-format-diff');
    run_shell('cd ' . shell_quote($srcdir)
              . ' && git diff -U0 --no-prefix --no-color | '
              . join(' ', map { shell_quote($_) } @command));
}

sub errors {
    unix_developer_action();
    my @rebuild = shellwords($ENV{ERROR_REBUILD} // '');
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    run($config{PERL}, catfile('util', 'ck_errf.pl'), qw(-strict -internal));
    run($config{PERL}, "-I$blddir", catfile('util', 'mkerr.pl'),
        @rebuild, '-internal');
}

sub update_ordinals {
    my $do_renumber = shift;
    unix_developer_action();
    my ($cryptoheaders, $sslheaders) = ordinal_headers();
    my @common = ('--version', $config{version}, '--no-warnings');
    my @renumber = $do_renumber ? ('--renumber') : ();
    run($config{PERL}, srcpath(catfile('util', 'mknum.pl')), @common,
        '--ordinals', srcpath(catfile('util', 'libcrypto.num')),
        '--symhacks', srcpath(catfile('include', 'openssl', 'symhacks.h')),
        @renumber, @$cryptoheaders);
    run($config{PERL}, srcpath(catfile('util', 'mknum.pl')), @common,
        '--ordinals', srcpath(catfile('util', 'libssl.num')),
        '--symhacks', srcpath(catfile('include', 'openssl', 'symhacks.h')),
        @renumber, @$sslheaders);
}

sub ordinals {
    update_ordinals(0);
}

sub renumber {
    update_ordinals(1);
}

sub test_ordinals {
    unix_developer_action();
    local $ENV{SRCTOP} = $srcdir;
    local $ENV{BLDTOP} = $blddir;
    local $ENV{PERL} = $config{PERL};
    local $ENV{FIPSKEY} = $config{FIPSKEY};
    local $ENV{EXE_EXT} = platform->binext();
    run($config{PERL}, srcpath(catfile('test', 'run_tests.pl')),
        'test_ordinals');
}

sub tags {
    unix_developer_action();
    rm_f(bldpath('TAGS'), bldpath('tags'));
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    system(srcpath(catfile('util', 'ctags.sh')));

    chdir $blddir or die "Cannot change directory to $blddir: $!\n";
    my @files;
    find({ wanted => sub {
               return if -d $_;
               push @files, $File::Find::name if /\.(?:c|h|pm|inc)\z/;
           }, no_chdir => 1 }, '.');
    system('etags', @files);
}

sub generate_fips_sources {
    unix_developer_action();
    local $ENV{NINJA_SRCDIR} = $srcdir;
    local $ENV{NINJA_CONFIG_SRCDIR} = $config{sourcedir};
    local $ENV{NINJA_PERL} = $config{PERL};
    local $ENV{NINJA_CMD} = $ENV{NINJA} // 'ninja';
    chdir $blddir or die "Cannot change directory to $blddir: $!\n";
    run_shell(<<'SH');
set -e
rm -rf sources-tmp
mkdir sources-tmp
cd sources-tmp
BUILDFILE=build.ninja "$NINJA_PERL" "$NINJA_SRCDIR/Configure" --banner=Configured enable-fips -O0
"$NINJA_PERL" ./configdata.pm --query 'get_sources("providers/fips")' > sources1
"$NINJA_CMD" -d keepdepfile -j4 build_generated providers/fips.so
find . -name '*.d' -type f -exec cat {} + > dep1
"$NINJA_CMD" distclean
BUILDFILE=build.ninja "$NINJA_PERL" "$NINJA_SRCDIR/Configure" \
    --banner=Configured enable-fips no-asm -O0
"$NINJA_PERL" ./configdata.pm --query 'get_sources("providers/fips")' > sources2
"$NINJA_CMD" -d keepdepfile -j4 build_generated providers/fips.so
find . -name '*.d' -type f -exec cat {} + > dep2
cat sources1 sources2 \
    | grep -v ' : \\$' | grep -v util/providers.num \
    | sed -e 's/^ *//' -e 's/ *\\$//' \
    | sort | uniq > sources
cat dep1 dep2 \
    | "$NINJA_PERL" -p -e 's/\\\n//' \
    | sed -e 's/^.*: *//' -e 's/  */ /g' \
    | fgrep -f sources \
    | tr ' ' '\n' \
    | sort | uniq > deps.raw
xargs "$NINJA_PERL" ./configdata.pm --query 'get_sources(@ARGV)' < deps.raw \
    | "$NINJA_PERL" -p -e 's/\\\n//' \
    | sed -e 's/\./\\\./g' -e 's/ : */:/' -e 's/^/s:/' -e 's/$/:/' \
    > deps.sed
sed -f deps.sed deps.raw > deps
(
    cat sources deps \
        | "$NINJA_PERL" -p \
            -e 's:^ *\Q../\E::;' \
            -e 's:^\Q$ENV{NINJA_CONFIG_SRCDIR}/\E:: if $ENV{NINJA_CONFIG_SRCDIR} ne ".";' \
            -e 'my $x; do { $x = $_; s:(^|/)((?!\Q../\E)[^/]*/)\Q..\E($|/):$1: } while ($x ne $_);'
    cd "$NINJA_SRCDIR"
    for x in crypto/bn/asm/*.pl crypto/bn/asm/*.S \
             crypto/aes/asm/*.pl crypto/aes/asm/*.S \
             crypto/ec/asm/*.pl \
             crypto/ml_dsa/asm/*.pl \
             crypto/ml_kem/asm/*.pl \
             crypto/modes/asm/*.pl \
             crypto/sha/asm/*.pl \
             crypto/slh_dsa/asm/*.pl \
             crypto/*cpuid.pl crypto/*cpuid.S \
             crypto/*cap.c; do
        test -e "$x" && echo "$x"
    done
) | grep -v sm2p256 | sort | uniq > ../providers/fips.module.sources.new
cd ..
rm -rf sources-tmp
SH
}

sub fips_checksums {
    unix_developer_action();
    die "ERROR: unifdef not in your PATH, FIPS checksums not calculated\n"
        unless command_exists('unifdef');
    local $ENV{NINJA_SRCDIR} = $srcdir;
    local $ENV{NINJA_BLDDIR} = $blddir;
    run_shell(<<'SH');
set -e
cd "$NINJA_SRCDIR"
xargs ./util/fips-checksums.sh \
    < "$NINJA_BLDDIR/providers/fips.module.sources.new" \
    > "$NINJA_BLDDIR/providers/fips-sources.checksums.new"
cd "$NINJA_BLDDIR"
sha256sum providers/fips-sources.checksums.new \
    | sed -e 's|\.new||' > providers/fips.checksum.new
SH
}

sub update_fips_checksums {
    unix_developer_action();
    for my $file (qw(fips.module.sources fips-sources.checksums fips.checksum)) {
        run('cp', '-p', bldpath(catfile('providers', "$file.new")),
            srcpath(catfile('providers', $file)));
    }
}

sub diff_fips_checksums {
    unix_developer_action();
    for my $file (qw(fips.module.sources fips-sources.checksums fips.checksum)) {
        run('diff', '-u', srcpath(catfile('providers', $file)),
            bldpath(catfile('providers', "$file.new")));
    }
}

sub tar {
    unix_developer_action();
    my $name = $ENV{NAME} // 'openssl-' . $config{full_version};
    my $tarfile = $ENV{TARFILE} // catfile('..', "$name.tar");
    chdir $srcdir or die "Cannot change directory to $srcdir: $!\n";
    run(srcpath(catfile('util', 'mktar.sh')), "--name=$name",
        "--tarfile=$tarfile");
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
