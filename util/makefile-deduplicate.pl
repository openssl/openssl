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

    if ($content =~ m,\ninclude [^\n]+/Makefile\.common[ \t]*\n,) {

        my ( $re);

        $re = qr,\nlib:\t\$\(LIBOBJ\)\n\t\$\(ARX\) \$\(LIB\) \$\(LIBOBJ\)\n\t\$\(RANLIB\) \$\(LIB\) \|\| echo Never mind\.\n\t\@touch lib\n,;
        $content =~ s,$re,\nlib: lib_arx_common\n,;

        $re = qr,\nlib:\t\$\(LIBOBJ\)\n\t\$\(AR\) \$\(LIB\) \$\(LIBOBJ\)\n\t\$\(RANLIB\) \$\(LIB\) \|\| echo Never mind\.\n\t\@touch lib\n,;
        $content =~ s,$re,\nlib: lib_ar_common\n,;

        $re = qr,\nfiles:\n\t\$\(PERL\) \$\(TOP\)/util/files\.pl Makefile \>\> \$\(TOP\)/MINFO\n,;
        $content =~ s,$re,\nfiles: files_common\n,;

        $re = qr,\nlinks:\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \.\./\.\./include/openssl \$\(EXHEADER\)\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \.\./\.\./test \$\(TEST\)\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \.\./\.\./apps \$\(APPS\)\n,;
        $content =~ s,$re,\nlinks: links_up2_common\n,;

        $re = qr,\nlinks:\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \.\./include/openssl \$\(EXHEADER\)\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \.\./test \$\(TEST\)\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \.\./apps \$\(APPS\)\n,;
        $content =~ s,$re,\nlinks: links_up1_common\n,;

        $re = qr,\nlinks:\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \$\(TOP\)/include/openssl \$\(EXHEADER\)\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \$\(TOP\)/test \$\(TEST\)\n\t\@\$\(PERL\) \$\(TOP\)/util/mklink\.pl \$\(TOP\)/apps \$\(APPS\)\n,;
        $content =~ s,$re,\nlinks: links_top_common\n,;

        $re = qr,\ninstall:\n\t\@\[ \-n "\$\(INSTALLTOP\)" \] \# should be set by top Makefile\.\.\.\n\t\@headerlist\="\$\(EXHEADER\)"\; for i in \$\$headerlist[ \t]*\;[ \t]*\\\n\t[ \t]*do[ \t]*\\\n\t[ \t]*\(cp \$\$i \$\(INSTALL_PREFIX\)\$\(INSTALLTOP\)/include/openssl/\$\$i\; \\\n\t[ \t]*chmod 644 \$\(INSTALL_PREFIX\)\$\(INSTALLTOP\)/include/openssl/\$\$i \)\; \\\n\tdone[ \t]*\;[ \t]*\n,;
        $content =~ s,$re,\ninstall: install_common\n,;

        $re = qr,\ninstall:\n\t\@headerlist\="\$\(EXHEADER\)"\; for i in \$\$headerlist[ \t]*\;[ \t]*\\\n\t[ \t]*do[ \t]*\\\n\t[ \t]*\(cp \$\$i \$\(INSTALL_PREFIX\)\$\(INSTALLTOP\)/include/openssl/\$\$i\; \\\n\t[ \t]*chmod 644 \$\(INSTALL_PREFIX\)\$\(INSTALLTOP\)/include/openssl/\$\$i \)\; \\\n\t[ \t]*done[ \t]*\n,;
        $content =~ s,$re,\ninstall: install_fips_common\n,;

        $re = qr,\ntags:\n\tctags \$\(SRC\)\n,;
        $content =~ s,$re,\ntags: tags_common\n,;

        $re = qr,\nlint:\n\tlint \-DLINT \$\(INCLUDES\) \$\(SRC\)\>fluff\n,;
        $content =~ s,$re,\nlint: lint_common\n,;

        $re = qr,\ndepend:\n\t\@\[ \-n "\$\(MAKEDEPEND\)" \] \# should be set by upper Makefile\.\.\.\n\t\$\(MAKEDEPEND\) \-\- \$\(CFLAG\) \$\(INCLUDES\) \$\(DEPFLAG\) \-\- \$\(PROGS\) \$\(LIBSRC\)\n,;
        $content =~ s,$re,\ndepend: depend_common\n,;

        $re = qr,\ndclean:\n\t\$\(PERL\) \-pe 'if \(/\^\# DO NOT DELETE THIS LINE/\) \{print\; exit\(0\)\;\}' \$\(MAKEFILE\) \>Makefile\.new\n\tmv \-f Makefile\.new \$\(MAKEFILE\)\n,;
        $content =~ s,$re,\ndclean: dclean_common\n,;

        $re = qr,\nclean:\n\trm \-f \*\.o \*\.obj lib tags core \.pure \.nfs\* \*\.old \*\.bak fluff\n,;
        $content =~ s,$re,\nclean: clean_common\n,;

        $re = qr,\nclean:\n\trm \-f \*\.s \*\.o \*\.obj lib tags core \.pure \.nfs\* \*\.old \*\.bak fluff\n,;
        $content =~ s,$re,\nclean: clean_common clean_s_common\n,;

        $re = qr,\nclean:\n\trm \-f \*\.o \*/\*\.o \*\.obj lib tags core \.pure \.nfs\* \*\.old \*\.bak fluff\n,;
        $content =~ s,$re,\nclean: clean_common clean_sub_o_common\n,;

    }


    print OUT $content;
    close(OUT);

    if (!exists($ENV{'MAKEFILE_UTIL_NO_REPLACE'})) {
        rename("$file_out",$file) || die "unable to rename $file_out to $file:$!\n";
    }

    return 1;
}

if (@ARGV < 1) {
    die "Usage: perl makefile-deduplicate.pl FILENAME";
}

dofile($ARGV[0]);
1;
