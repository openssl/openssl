package OpenSSL::Test;

use strict;
use warnings;

use Test::More 0.96;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
$VERSION = "0.7";
@ISA = qw(Exporter);
@EXPORT = (@Test::More::EXPORT, qw(setup indir app test run));
@EXPORT_OK = (@Test::More::EXPORT_OK, qw(top_dir top_file pipe with cmdstr
                                         quotify));

=head1 NAME

OpenSSL::Test - a private extension of Test::More

=head1 SYNOPSIS

  use OpenSSL::Test;

  setup("my_test_name");

  ok(run(app(["openssl", "version"])), "check for openssl presence");

  indir "subdir" => sub {
    ok(run(test(["sometest", "arg1"], stdout => "foo.txt")),
       "run sometest with output to foo.txt");
  };

=head1 DESCRIPTION

This module is a private extension of L<Test::More> for testing OpenSSL.
In addition to the Test::More functions, it also provides functions that
easily find the diverse programs within a OpenSSL build tree, as well as
some other useful functions.

This module I<depends> on the environment variable C<$TOP>.  Without it,
it refuses to work.  See L</ENVIRONMENT> below.

=cut

use File::Copy;
use File::Spec::Functions qw/file_name_is_absolute curdir canonpath splitdir
                             catdir catfile splitpath catpath devnull abs2rel
                             rel2abs/;
use File::Path 2.00 qw/remove_tree mkpath/;


# The name of the test.  This is set by setup() and is used in the other
# functions to verify that setup() has been used.
my $test_name = undef;

# Directories we want to keep track of TOP, APPS, TEST and RESULTS are the
# ones we're interested in, corresponding to the environment variables TOP
# (mandatory), BIN_D, TEST_D and RESULT_D.
my %directories = ();

# A bool saying if we shall stop all testing if the current recipe has failing
# tests or not.  This is set by setup() if the environment variable STOPTEST
# is defined with a non-empty value.
my $end_with_bailout = 0;

# A set of hooks that is affected by with() and may be used in diverse places.
# All hooks are expected to be CODE references.
my %hooks = (

    # exit_checker is used by run() directly after completion of a command.
    # it receives the exit code from that command and is expected to return
    # 1 (for success) or 0 (for failure).  This is the value that will be
    # returned by run().
    # NOTE: When run() gets the option 'capture => 1', this hook is ignored.
    exit_checker => sub { return shift == 0 ? 1 : 0 },

    );

# Declare some utility functions that are defined at the end
sub top_file;
sub top_dir;
sub quotify;

# Declare some private functions that are defined at the end
sub __env;
sub __cwd;
sub __apps_file;
sub __results_file;
sub __test_log;
sub __cwd;
sub __fixup_cmd;
sub __build_cmd;

=head2 Main functions

The following functions are exported by default when using C<OpenSSL::Test>.

=cut

=over 4

=item B<setup "NAME">

C<setup> is used for initial setup, and it is mandatory that it's used.
If it's not used in a OpenSSL test recipe, the rest of the recipe will
most likely refuse to run.

C<setup> checks for environment variables (see L</ENVIRONMENT> below),
check that C<$TOP/Configure> exists, C<chdir> into the results directory
(defined by the C<$RESULT_D> environment variable if defined, otherwise
C<$TEST_D> if defined, otherwise C<$TOP/test>).

=back

=cut

sub setup {
    $test_name = shift;

    BAIL_OUT("setup() must receive a name") unless $test_name;
    BAIL_OUT("setup() needs \$TOP to be defined") unless $ENV{TOP};

    __env();

    BAIL_OUT("setup() expects the file Configure in the \$TOP directory")
	unless -f top_file("Configure");

    __cwd($directories{RESULTS});

    # Loop in case we're on a platform with more than one file generation
    1 while unlink(__test_log());
}

=over 4

=item B<indir "SUBDIR" =E<gt> sub BLOCK, OPTS>

C<indir> is used to run a part of the recipe in a different directory than
the one C<setup> moved into, usually a subdirectory, given by SUBDIR.
The part of the recipe that's run there is given by the codeblock BLOCK.

C<indir> takes some additional options OPTS that affect the subdirectory:

=over 4

=item B<create =E<gt> 0|1>

When set to 1 (or any value that perl preceives as true), the subdirectory
will be created if it doesn't already exist.  This happens before BLOCK
is executed.

=item B<cleanup =E<gt> 0|1>

When set to 1 (or any value that perl preceives as true), the subdirectory
will be cleaned out and removed.  This happens both before and after BLOCK
is executed.

=back

An example:

  indir "foo" => sub {
      ok(run(app(["openssl", "version"]), stdout => "foo.txt"));
      if (ok(open(RESULT, "foo.txt"), "reading foo.txt")) {
          my $line = <RESULT>;
          close RESULT;
          is($line, qr/^OpenSSL 1\./,
             "check that we're using OpenSSL 1.x.x");
      }
  }, create => 1, cleanup => 1;

=back

=cut

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

=over 4

=item B<app ARRAYREF, OPTS>

=item B<test ARRAYREF, OPTS>

Both of these functions take a reference to a list that is a command and
its arguments, and some additional options (described further on).

C<app> expects to find the given command (the first item in the given list
reference) as an executable in C<$BIN_D> (if defined, otherwise C<$TOP/apps>).

C<test> expects to find the given command (the first item in the given list
reference) as an executable in C<$TEST_D> (if defined, otherwise C<$TOP/test>).

Both return a CODEREF to be used by C<run>, C<pipe> or C<cmdstr>.

The options that both C<app> and C<test> can take are in the form of hash
values:

=over 4

=item B<stdin =E<gt> PATH>

=item B<stdout =E<gt> PATH>

=item B<stderr =E<gt> PATH>

In all three cases, the corresponding standard input, output or error is
redirected from (for stdin) or to (for the others) a file given by the
string PATH, I<or>, if the value is C<undef>, C</dev/null> or similar.

=back

=back

=cut

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

=over 4

=item B<run CODEREF, OPTS>

This CODEREF is expected to be the value return by C<app> or C<test>,
anything else will most likely cause an error unless you know what you're
doing.

C<run> executes the command returned by CODEREF and return either the
resulting output (if the option C<capture> is set true) or a boolean indicating
if the command succeeded or not.

The options that C<run> can take are in the form of hash values:

=over 4

=item B<capture =E<gt> 0|1>

If true, the command will be executed with a perl backtick, and C<run> will
return the resulting output as an array of lines.  If false or not given,
the command will be executed with C<system()>, and C<run> will return 1 if
the command was successful or 0 if it wasn't.

=back

For further discussion on what is considered a successful command or not, see
the function C<with> further down.

=back

=cut

sub run {
    my ($cmd, $display_cmd, %errlogs) = shift->(0);
    my %opts = @_;

    return () if !$cmd;

    my $prefix = "";
    if ( $^O eq "VMS" ) {	# VMS
	$prefix = "pipe ";
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

END {
    my $tb = Test::More->builder;
    my $failure = scalar(grep { $_ == 0; } $tb->summary);
    if ($failure && $end_with_bailout) {
	BAIL_OUT("Stoptest!");
    }
}

=head2 Utility functions

The following functions are exported on request when using C<OpenSSL::Test>.

  # To only get the top_file function.
  use OpenSSL::Test qw/top_file/;

  # To only get the top_file function in addition to the default ones.
  use OpenSSL::Test qw/:DEFAULT top_file/;

=cut

# Utility functions, exported on request

=over 4

=item B<top_dir LIST>

LIST is a list of directories that make up a path from the top of the OpenSSL
source directory (as indicated by the environment variable C<$TOP>).
C<top_dir> returns the resulting directory as a string, adapted to the local
operating system.

=back

=cut

sub top_dir {
    return __top_dir(@_);	# This caters for operating systems that have
				# a very distinct syntax for directories.
}

=over 4

=item B<top_file LIST, FILENAME>

LIST is a list of directories that make up a path from the top of the OpenSSL
source directory (as indicated by the environment variable C<$TOP>) and
FILENAME is the name of a file located in that directory path.
C<top_file> returns the resulting file path as a string, adapted to the local
operating system.

=back

=cut

sub top_file {
    return __top_file(@_);
}

=over 4

=item B<pipe LIST>

LIST is a list of CODEREFs returned by C<app> or C<test>, from which C<pipe>
creates a new command composed of all the given commands put together in a
pipe.  C<pipe> returns a new CODEREF in the same manner as C<app> or C<test>,
to be passed to C<run> for execution.

=back

=cut

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

=over 4

=item B<with HASHREF, CODEREF>

C<with> will temporarly install hooks given by the HASHREF and then execute
the given CODEREF.  Hooks are usually expected to have a coderef as value.

The currently available hoosk are:

=over 4

=item B<exit_checker =E<gt> CODEREF>

This hook is executed after C<run> has performed its given command.  The
CODEREF receives the exit code as only argument and is expected to return
1 (if the exit code indicated success) or 0 (if the exit code indicated
failure).

=back

=back

=cut

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

=over 4

=item B<cmdstr CODEREF>

C<cmdstr> takes a CODEREF from C<app> or C<test> and simply returns the
command as a string.

=back

=cut

sub cmdstr {
    my ($cmd, $display_cmd, %errlogs) = shift->(0);

    return $display_cmd;
}

=over 4

=item B<quotify LIST>

LIST is a list of strings that are going to be used as arguments for a
command, and makes sure to inject quotes and escapes as necessary depending
on the content of each string.

This can also be used to put quotes around the executable of a command.
I<This must never ever be done on VMS.>

=back

=cut

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

######################################################################
# private functions.  These are never exported.

=head1 ENVIRONMENT

OpenSSL::Test depends on some environment variables.

=over 4

=item B<TOP>

This environment variable is mandatory.  C<setup> will check that it's
defined and that it's a directory that contains the file C<Configure>.
If this isn't so, C<setup> will C<BAIL_OUT>.

=item B<BIN_D>

If defined, its value should be the directory where the openssl application
is located.  Defaults to C<$TOP/apps> (adapted to the operating system).

=item B<TEST_D>

If defined, its value should be the directory where the test applications
are located.  Defaults to C<$TOP/test> (adapted to the operating system).

=item B<RESULT_D>

If defined, its value should be the directory where the log files are
located.  Defaults to C<$TEST_D>.

=item B<STOPTEST>

If defined, it puts testing in a different mode, where a recipe with
failures will result in a C<BAIL_OUT> at the end of its run.

=back

=cut

sub __env {
    $directories{TOP}     = $ENV{TOP},
    $directories{APPS}    = $ENV{BIN_D}    || catdir($directories{TOP},"apps");
    $directories{TEST}    = $ENV{TEST_D}   || catdir($directories{TOP},"test");
    $directories{RESULTS} = $ENV{RESULT_D} || $directories{TEST};

    $end_with_bailout	  = $ENV{STOPTEST} ? 1 : 0;
};

sub __top_file {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    my $f = pop;
    return catfile($directories{TOP},@_,$f);
}

sub __top_dir {
    BAIL_OUT("Must run setup() first") if (! $test_name);

    return catdir($directories{TOP},@_);
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

sub __fixup_cmd {
    my $prog = shift;

    my $prefix = __top_file("util", "shlib_wrap.sh")." ";
    my $ext = $ENV{"EXE_EXT"} || "";

    if (defined($ENV{EXE_SHELL})) {
	$prefix = "$ENV{EXE_SHELL} ";
    } elsif ($^O eq "VMS" ) {	# VMS
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
    # Make a copy to not destroy the caller's array
    my @cmdarray = ( @{$_[0]} ); shift;
    my $cmd = __fixup_cmd($path_builder->(shift @cmdarray));
    my @args = @cmdarray;
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

    my $errlog =
        __results_file($num ? "$test_name.$num.tmp_err" : "$test_name.tmp_err");
    my $display_cmd = "$cmd$arg_str$stdin$stdout$stderr";
    $cmd .= "$arg_str$stdin$stdout 2> $errlog";

    return ($cmd, $display_cmd, $errlog => $saved_stderr);
}

=head1 SEE ALSO

L<Test::More>, L<Test::Harness>

=head1 AUTHORS

Richard Levitte E<lt>levitte@openssl.orgE<gt> with assitance and
inspiration from Andy Polyakov E<lt>appro@openssl.org<gt>.

=cut

1;
