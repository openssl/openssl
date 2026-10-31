#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IPC::Open3;
use POSIX ':sys_wait_h';
use OpenSSL::Test qw/:DEFAULT result_file srctop_file bldtop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_app_s_client_no_interactive";
setup($test_name);

plan skip_all => "$test_name needs sock enabled"
    if disabled("sock");
plan skip_all => "$test_name needs some TLS protocols to be enabled"
    if alldisabled(available_protocols("tls"));
plan skip_all => "$test_name needs ec, ecx or dh for TLS key exchange"
    if disabled("ec") && disabled("ecx") && disabled("dh");

# This guards the Windows stdin polling path, and only that path.  Neither app
# can select() on stdin there, so both poll has_stdin_waiting() on a timer
# instead, and that is where they used to wedge.  Everywhere else stdin takes
# part in select() and s_client -no-interactive waits on it by design, so the
# same run would block for reasons that have nothing to do with this.
#
# The build decides that, not whichever Perl drives the suite: a Cygwin Perl
# may well be running a MinGW application, while a Cygwin application takes
# the POSIX path.  So key on the target rather than on $^O.
plan skip_all => "$test_name only applies to the Windows stdin polling path"
    unless config('target') =~ /^(?:VC-|mingw)/;

plan tests => 5;

my $shlib_wrap   = bldtop_file("util", "wrap.pl");
my $apps_openssl = bldtop_file("apps", "openssl");
my $server_pem   = srctop_file("test", "certs", "servercert.pem");
my $server_key   = srctop_file("test", "certs", "serverkey.pem");

# util/wrap.pl is a Perl script, which Windows cannot exec from a hashbang, so
# name the interpreter.  Note that the pid open3() returns is the wrapper's:
# wrap.pl runs the application with system(), and under MSWin32 that goes by
# way of the command interpreter as well.  stdin is inherited down the chain,
# so the pipe below still reaches the application, and the wrapper exits with
# the application's exit code, so waiting on it reports faithfully.
# Signalling it, however, would leave the application behind -- see
# release_and_reap().
my @wrap = ($^X, $shlib_wrap, $apps_openssl);

# Both peers write to files rather than to pipes.  Nothing here drains a pipe
# while they are running and Windows Perl cannot select() on one, so a chatty
# peer would fill the buffer and wedge the very exit this test waits for.
sub result_handle
{
    my $name = shift;
    my $path = result_file($name);

    open my $fh, ">", $path or BAIL_OUT("failed to open $path: $!");
    return ($fh, $path);
}

sub slurp
{
    my $path = shift;
    my $text = "";

    if (open my $fh, "<", $path) {
        local $/;
        $text = <$fh>;
        close $fh;
    }
    return defined $text ? $text : "";
}

# do_server() prints a single "ACCEPT <address>:<port>" line, flushed, once it
# has bound the socket.  -accept 0 asks the OS for a free port, so this is the
# only way to learn which one.
sub wait_for_port
{
    my ($path, $limit) = @_;

    for (my $waited = 0; $waited < $limit; $waited += 0.1) {
        foreach my $line (split /\n/, slurp($path)) {
            return $1 if $line =~ /^ACCEPT \S*?:(\d+)/;
        }
        select(undef, undef, undef, 0.1);
    }
    return undef;
}

# Perl's emulated alarm() on Windows does not interrupt a blocking waitpid(),
# so poll for the exit instead.  Returns the wait status, or undef if the
# process was still running when the deadline passed.
sub wait_for_exit
{
    my ($pid, $limit) = @_;

    for (my $waited = 0; $waited < $limit; $waited += 0.1) {
        my $reaped = waitpid($pid, WNOHANG);

        return $? if $reaped == $pid;
        last if $reaped < 0;
        select(undef, undef, undef, 0.1);
    }
    return undef;
}

# Did it go?  After a kill, waitpid() may report ECHILD rather than a status,
# because the runtime can have reaped the process already.  Either answer
# means the process is gone, which is all this has to establish.
sub reaped
{
    my ($pid, $limit) = @_;

    for (my $waited = 0; $waited < $limit; $waited += 0.1) {
        my $gone = waitpid($pid, WNOHANG);

        return 1 if $gone == $pid || $gone < 0;
        select(undef, undef, undef, 0.1);
    }
    return 0;
}

# The pid open3() returns belongs to util/wrap.pl, so kill() reaches the
# wrapper and not the application.  An application left behind that way keeps
# inherited copies of the harness's own handles, which wedges the whole test
# run rather than just this recipe, so a Windows pid is needed to take the
# tree down.  MSWin32 Perl already has one; under an MSYS2 or Cygwin Perl the
# procfs entry gives it.
sub win_pid
{
    my $pid = shift;

    return $pid if $^O eq 'MSWin32';
    open my $fh, "<", "/proc/$pid/winpid" or return undef;
    my $win = <$fh>;

    close $fh;
    chomp $win if defined $win;
    return $win;
}

# Clean up after a peer that overran its deadline.  Closing the stdin pipe is
# the graceful way out and is enough for a working build, but an affected one
# does not act on EOF either: s_server keeps asking has_stdin_waiting(), which
# still answers yes, and reads a pipe that now returns nothing.  That is the
# bug, so there has to be a fallback.  Only ever call this once the run has
# been measured -- closing the writer early is exactly what hides the
# condition this recipe is here to catch.
sub release_and_reap
{
    my ($name, $pid, $writer, $limit) = @_;

    close $writer;
    return if defined wait_for_exit($pid, $limit);

    my $win = win_pid($pid);

    if (defined $win) {
        # Name taskkill by its absolute path: the Windows directories are not
        # on PATH under every MSYS2 shell.  The list form of open keeps the
        # backslashes away from a shell, and reading the output keeps it out
        # of this recipe's own TAP stream.
        my $root = $ENV{SYSTEMROOT} || $ENV{SystemRoot} || 'C:\\Windows';
        my $taskkill = "$root\\System32\\taskkill.exe";

        my $killed = 0;

        # An MSYS2 Perl rewrites arguments that look like POSIX paths when it
        # spawns a native program, which turns /F into F:/ before taskkill
        # ever sees it.  This asks the runtime to leave them alone, and does
        # nothing under an MSWin32 Perl, which never rewrote them.
        local $ENV{MSYS2_ARG_CONV_EXCL} = '*';

        diag("$name ignored EOF on stdin; terminating its process tree");
        if (open my $fh, "-|", $taskkill, "/F", "/T", "/PID", $win) {
            local $/;
            my $ignored = <$fh>;

            close $fh;
            $killed = ($? == 0);
        } else {
            diag("could not run $taskkill: $!");
        }
        diag("$name could not be terminated; an openssl process may remain")
            unless $killed;
    } else {
        diag("$name ignored EOF on stdin and its Windows pid is unknown");
        kill 'KILL', $pid;
    }

    # taskkill reporting success is what establishes the tree is down; this is
    # only to collect the child if the runtime still has it.  Never wait here
    # without a bound: a peer that cannot be put down should fail this recipe,
    # not stall the whole test run.
    reaped($pid, 5);
}

# $s_server_i is the server's stdin: a pipe whose writer this recipe holds open
# and never writes to.  That is what a test harness, or any script that pipes
# into the app without sending anything, presents.  Such a pipe never becomes
# readable, and the accept loop used to reach a blocking read of it before it
# had accepted anything at all.  The writer must stay open for the whole run:
# closing it makes the pipe readable at EOF and hides the problem.
my ($s_server_out, $s_server_out_file) = result_handle("s_server-stdout.txt");
my ($s_server_err) = result_handle("s_server-stderr.txt");
my @s_server_cmd = ("s_server", "-accept", "0", "-naccept", "1",
                    "-cert", $server_pem, "-key", $server_key);
my $s_server_pid = open3(my $s_server_i,
                         ">&" . fileno($s_server_out),
                         ">&" . fileno($s_server_err),
                         @wrap, @s_server_cmd);

my $port = wait_for_port($s_server_out_file, 30);
ok(defined $port, "s_server port check");

SKIP: {
    skip "could not start s_server", 4 unless defined $port;

    # The client gets the same kind of idle, open stdin pipe.  It is run with
    # -no-interactive, which never reads stdin, so it has to finish on its own
    # once the peer is done with it, whatever stdin is doing.
    my ($s_client_out, $s_client_out_file)
        = result_handle("s_client-stdout.txt");
    my ($s_client_err, $s_client_err_file)
        = result_handle("s_client-stderr.txt");
    my @s_client_cmd = ("s_client", "-no-interactive",
                        "-connect", "localhost:$port");
    my $s_client_pid = open3(my $s_client_i,
                             ">&" . fileno($s_client_out),
                             ">&" . fileno($s_client_err),
                             @wrap, @s_client_cmd);

    my $s_client_status = wait_for_exit($s_client_pid, 30);

    release_and_reap("s_client", $s_client_pid, $s_client_i, 15)
        unless defined $s_client_status;
    close $s_client_out;
    close $s_client_err;

    # This recipe cannot be run by most contributors, so leave something in
    # the log to work from when it does fail.
    diag("s_client stderr:\n" . slurp($s_client_err_file))
        unless defined $s_client_status;

    ok(defined $s_client_status,
       "s_client -no-interactive exits with an idle stdin pipe");
    is($s_client_status, 0, "s_client -no-interactive exit status");

    # Exiting is not on its own enough.  Before this fix the server blocked on
    # stdin ahead of its first accept(), so the handshake never started, and
    # the client still exited 0 as soon as a second of socket silence had
    # passed.  print_stuff() reports "Cipher is (NONE)" in that state, so this
    # is what separates the fix from a client that merely gave up on time.
    like(slurp($s_client_out_file),
         qr/^(?:New|Reused), [^,\n]+, Cipher is (?!\(NONE\))\S/m,
         "s_client -no-interactive completed the handshake");

    # -naccept 1 makes s_server leave once it has served one connection, so
    # its own exit is what says the accept loop was never stuck on stdin.
    # Its stdin writer has to still be open for that to mean anything.
    my $s_server_status = wait_for_exit($s_server_pid, 30);

    ok(defined $s_server_status,
       "s_server served the connection with an idle stdin pipe");
    $s_server_pid = 0 if defined $s_server_status;
}

release_and_reap("s_server", $s_server_pid, $s_server_i, 15) if $s_server_pid;
close $s_server_out;
close $s_server_err;
