package OpenSSL::Test;

use strict;
use warnings;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
$VERSION = "0.5";
@ISA = qw(Exporter);
@EXPORT = qw(setup indir app test run);
@EXPORT_OK = qw(top_dir top_file pipe with cmdstr quotify));


use File::Copy;
use File::Spec::Functions qw/file_name_is_absolute curdir canonpath splitdir
                             catdir catfile splitpath catpath devnull abs2rel
                             rel2abs/;
use File::Path 2.00 qw/remove_tree mkpath/;
use Test::More 0.96;


my $test_name = undef;

my %directories = ();		# Directories we want to keep track of
				# TOP, APPS, TEST and RESULTS are the
				# ones we're interested in, corresponding
				# to the environment variables TOP (mandatory),
				# BIN_D, TEST_D and RESULT_D.

sub quotify;

sub __top_file {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $f = pop;
    return catfile($directories{TOP},@_,$f);
}

sub __test_file {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $f = pop;
    return catfile($directories{TEST},@_,$f);
}

sub __apps_file {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $f = pop;
    return catfile($directories{APPS},@_,$f);
}

sub __results_file {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $f = pop;
    return catfile($directories{RESULTS},@_,$f);
}

sub __test_log {
    return __results_file("$test_name.log");
}

sub top_dir {
    return __top_file(@_, "");	# This caters for operating systems that have
				# a very distinct syntax for directories.
}
sub top_file {
    return __top_file(@_);
}

sub __cwd {
    my $dir = shift;
    my %opts = @_;
    my $abscurdir = rel2abs(curdir());
    my $absdir = rel2abs($dir);
    my $reverse = abs2rel($abscurdir, $absdir);

    # PARANOIA: if we're not moving anywhere, we do nothing more
    if ($abscurdir eq $absdir) {
	return $reverse;
    }

    # Do not support a move to a different volume for now.  Maybe later.
    BAIL_OUT("FAILURE: \"$dir\" moves to a different volume, not supported")
	if $reverse eq $abscurdir;

    # If someone happened to give a directory that leads back to the current,
    # it's extremely silly to do anything more, so just simulate that we did
    # move.
    # In this case, we won't even clean it out, for safety's sake.
    return "." if $reverse eq "";

    $dir = canonpath($dir);
    if ($opts{create}) {
	mkpath($dir);
    }

    # Should we just bail out here as well?  I'm unsure.
    return undef unless chdir($dir);

    if ($opts{cleanup}) {
	remove_tree(".", { safe => 0, keep_root => 1 });
    }

    # For each of these directory variables, figure out where they are relative
    # to the directory we want to move to if they aren't absolute (if they are,
    # they don't change!)
    my @dirtags = ("TOP", "TEST", "APPS", "RESULTS");
    foreach (@dirtags) {
	if (!file_name_is_absolute($directories{$_})) {
	    my $newpath = abs2rel(rel2abs($directories{$_}), rel2abs($dir));
	    $directories{$_} = $newpath;
	}
    }

    if (0) {
	print STDERR "DEBUG: __cwd(), directories and files:\n";
	print STDERR "  \$directories{TEST}    = \"$directories{TEST}\"\n";
	print STDERR "  \$directories{RESULTS} = \"$directories{RESULTS}\"\n";
	print STDERR "  \$directories{APPS}    = \"$directories{APPS}\"\n";
	print STDERR "  \$directories{TOP}     = \"$directories{TOP}\"\n";
	print STDERR "  \$test_log             = \"",__test_log(),"\"\n";
	print STDERR "\n";
	print STDERR "  current directory is \"",curdir(),"\"\n";
	print STDERR "  the way back is \"$reverse\"\n";
    }

    return $reverse;
}

sub setup {
    $test_name = shift;

    BAIL_OUT("setup() must receive a name") unless $test_name;
    BAIL_OUT("setup() needs \$TOP to be defined") unless $ENV{TOP};

    $directories{TOP}     = $ENV{TOP},
    $directories{APPS}    = $ENV{BIN_D}    || catdir($directories{TOP},"apps");
    $directories{TEST}    = $ENV{TEST_D}   || catdir($directories{TOP},"test");
    $directories{RESULTS} = $ENV{RESULT_D} || $directories{TEST};

    BAIL_OUT("setup() expects the file Configure in the \$TOP directory")
	unless -f top_file("Configure");

    __cwd($directories{RESULTS});

    # Loop in case we're on a platform with more than one file generation
    1 while unlink(__test_log());
}

sub indir {
    my $subdir = shift;
    my $codeblock = shift;
    my %opts = @_;

    my $reverse = __cwd($subdir,%opts);
    BAIL_OUT("FAILURE: indir, \"$subdir\" wasn't possible to move into")
	unless $reverse;

    $codeblock->();

    __cwd($reverse);

    if ($opts{cleanup}) {
	remove_tree($subdir, { safe => 0 });
    }
}

my %hooks = (
    exit_checker => sub { return shift == 0 ? 1 : 0 }
    );

sub with {
    my $opts = shift;
    my %opts = %{$opts};
    my $codeblock = shift;

    my %saved_hooks = ();

    foreach (keys %opts) {
	$saved_hooks{$_} = $hooks{$_}	if exists($hooks{$_});
	$hooks{$_} = $opts{$_};
    }

    $codeblock->();

    foreach (keys %saved_hooks) {
	$hooks{$_} = $saved_hooks{$_};
    }
}

sub __fixup_cmd {
    my $prog = shift;

    my $prefix = __top_file("util", "shlib_wrap.sh")." ";
    my $ext = $ENV{"EXE_EXT"} || "";

    if ( $^O eq "VMS" ) {	# VMS
	$prefix = "mcr ";
	$ext = ".exe";
    } elsif ($^O eq "MSWin32") { # Windows
	$prefix = "";
	$ext = ".exe";
    }

    # We test both with and without extension.  The reason
    # is that we might, for example, be passed a Perl script
    # ending with .pl...
    my $file = "$prog$ext";
    if ( -x $file ) {
	return $prefix.$file;
    } elsif ( -f $prog ) {
	return $prog;
    }

    print STDERR "$prog not found\n";
    return undef;
}

sub __build_cmd {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $num = shift;
    my $path_builder = shift;
    my $cmd = __fixup_cmd($path_builder->(shift @{$_[0]}));
    my @args = @{$_[0]}; shift;
    my %opts = @_;

    return () if !$cmd;

    my $arg_str = "";
    my $null = devnull();


    $arg_str = " ".join(" ", quotify @args) if @args;

    my $fileornull = sub { $_[0] ? $_[0] : $null; };
    my $stdin = "";
    my $stdout = "";
    my $stderr = "";
    my $saved_stderr = undef;
    $stdin = " < ".$fileornull->($opts{stdin})  if exists($opts{stdin});
    $stdout= " > ".$fileornull->($opts{stdout}) if exists($opts{stdout});
    $stderr=" 2> ".$fileornull->($opts{stderr}) if exists($opts{stderr});

    $saved_stderr = $opts{stderr}		if defined($opts{stderr});

    my $errlog = $num ? "$test_name.$num.tmp_err" : "$test_name.tmp_err";
    my $display_cmd = "$cmd$arg_str$stdin$stdout$stderr";
    $cmd .= "$arg_str$stdin$stdout 2> $errlog";

    return ($cmd, $display_cmd, $errlog => $saved_stderr);
}

sub app {
    my $cmd = shift;
    my %opts = @_;
    return sub { my $num = shift;
		 return __build_cmd($num, \&__apps_file, $cmd, %opts); }
}

sub test {
    my $cmd = shift;
    my %opts = @_;
    return sub { my $num = shift;
		 return __build_cmd($num, \&__test_file, $cmd, %opts); }
}

sub cmdstr {
    my ($cmd, $display_cmd, %errlogs) = shift->(0);

    return $display_cmd;
}

sub run {
    my ($cmd, $display_cmd, %errlogs) = shift->(0);
    my %opts = @_;

    return () if !$cmd;

    my $prefix = "";
    if ( $^O eq "VMS" ) {	# VMS
	$prefix = "pipe ";
    } elsif ($^O eq "MSWin32") { # MSYS
	$prefix = "cmd /c ";
    }

    my @r = ();
    my $r = 0;
    my $e = 0;
    if ($opts{capture}) {
	@r = `$prefix$cmd`;
	$e = $? >> 8;
    } else {
	system("$prefix$cmd");
	$e = $? >> 8;
	$r = $hooks{exit_checker}->($e);
    }

    # At this point, $? stops being interesting, and unfortunately,
    # there are Test::More versions that get picky if we leave it
    # non-zero.
    $? = 0;

    open ERR, ">>", __test_log();
    { local $| = 1; print ERR "$display_cmd => $e\n"; }
    foreach (keys %errlogs) {
	copy($_,\*ERR);
	copy($_,$errlogs{$_}) if defined($errlogs{$_});
	unlink($_);
    }
    close ERR;

    if ($opts{capture}) {
	return @r;
    } else {
	return $r;
    }
}

sub pipe {
    my @cmds = @_;
    return
	sub {
	    my @cs  = ();
	    my @dcs = ();
	    my @els = ();
	    my $counter = 0;
	    foreach (@cmds) {
		my ($c, $dc, @el) = $_->(++$counter);

		return () if !$c;

		push @cs, $c;
		push @dcs, $dc;
		push @els, @el;
	    }
	    return (
		join(" | ", @cs),
		join(" | ", @dcs),
		@els
		);
    };
}

# Utility functions, some of which are exported on request

sub quotify {
    # Unix setup (default if nothing else is mentioned)
    my $arg_formatter =
	sub { $_ = shift; /\s|[\{\}\\\$\[\]\*\?\|\&:;<>]/ ? "'$_'" : $_ };

    if ( $^O eq "VMS") {	# VMS setup
	$arg_formatter = sub {
	    $_ = shift;
	    if (/\s|["[:upper:]]/) {
		s/"/""/g;
		'"'.$_.'"';
	    } else {
		$_;
	    }
	};
    } elsif ( $^O eq "MSWin32") { # MSWin setup
	$arg_formatter = sub {
	    $_ = shift;
	    if (/\s|["\|\&\*\;<>]/) {
		s/(["\\])/\\$1/g;
		'"'.$_.'"';
	    } else {
		$_;
	    }
	};
    }

    return map { $arg_formatter->($_) } @_;
}

1;
