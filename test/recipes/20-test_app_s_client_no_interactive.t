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
use IO::Select;
use IO::Socket::INET;
use POSIX ':sys_wait_h';
use Time::HiRes qw(time);
use OpenSSL::Test qw/:DEFAULT cmdstr result_file srctop_file/;
use OpenSSL::Test::Utils;

my $test_name = "test_app_s_client_no_interactive";
setup($test_name);

plan skip_all => "$test_name needs sock enabled"
    if disabled("sock");
plan skip_all => "$test_name needs some TLS protocols to be enabled"
    if alldisabled(available_protocols("tls"));
plan skip_all => "$test_name needs ec, ecx or dh for TLS key exchange"
    if disabled("ec") && disabled("ecx") && disabled("dh");
plan skip_all => "$test_name needs IPv4"
    unless have_IPv4();

plan tests => 18;

# Tests 1-10 guard the Windows stdin polling path, and only that path.
# Neither app can select() on stdin there, so both poll has_stdin_waiting()
# on a timer instead, and that is where they used to wedge.  Everywhere else
# stdin takes part in select() and s_client -no-interactive waits on it by
# design, so the same run would block for reasons that have nothing to do
# with this.
#
# The build decides that, not whichever Perl drives the suite: a Cygwin Perl
# may well be running a MinGW application, while a Cygwin application takes
# the POSIX path.  So key on the target rather than on $^O.
my $windows_stdin = config('target') =~ /^(?:VC-|mingw)/;

my $server_pem   = srctop_file("test", "certs", "servercert.pem");
my $server_key   = srctop_file("test", "certs", "serverkey.pem");
my $root_pem     = srctop_file("test", "certs", "rootcert.pem");

# What says the client finished its handshake.  With -brief, s_client prints
# this to stderr at the moment the handshake completes, and at no other time.
# Its session summary is no use for this: it is also printed when the client
# exits mid-handshake, and once a TLS 1.3 ServerHello has arrived that
# already names the negotiated cipher.
my $established = qr/^CONNECTION ESTABLISHED\r?$/m;

# The command line for a child, built the way the harness builds one for
# run(): that honours BIN_D, TEST_D and EXE_SHELL, and goes by way of
# util/wrap.pl, naming the Perl interpreter where the platform cannot exec a
# script from its hashbang.  open3() gets it as a single command line, which
# a POSIX Perl hands to /bin/sh; "exec" there makes the shell give way to the
# command, so that the pid open3() returns is the command's own.
#
# Under MSWin32 the pid is the wrapper's, though: wrap.pl runs the
# application with system(), which goes by way of the command interpreter as
# well.  stdin is inherited down the chain, so the pipes below still reach the
# application, and the wrapper exits with the application's exit code, so
# waiting on it reports faithfully.  Signalling it, however, would leave the
# application behind -- see release_and_reap().
sub command_line
{
    my $cmd = cmdstr(shift);

    return $^O eq 'MSWin32' || $^O eq 'VMS' ? $cmd : "exec $cmd";
}

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

    if (defined $path && open my $fh, "<", $path) {
        local $/;
        $text = <$fh>;
        close $fh;
    }
    return defined $text ? $text : "";
}

# do_server() prints a single "ACCEPT <address>:<port>" line, flushed, once it
# has bound the socket, and quic_alpn_server does the same.  Port 0 asks the
# OS for a free port, so this is the only way to learn which one.
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

# Under MSWin32 the pid open3() returns belongs to util/wrap.pl, so kill()
# reaches the wrapper and not the application.  An application left behind
# that way keeps inherited copies of the harness's own handles, which wedges
# the whole test run rather than just this recipe, so a Windows pid is needed
# to take the tree down.  MSWin32 Perl already has one; under an MSYS2 or
# Cygwin Perl the procfs entry gives it.
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

        diag("$name is still running; terminating its process tree");
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
        diag("$name is still running; killing it");
        kill 'KILL', $pid;
    }

    # taskkill reporting success is what establishes the tree is down; this is
    # only to collect the child if the runtime still has it.  Never wait here
    # without a bound: a peer that cannot be put down should fail this recipe,
    # not stall the whole test run.
    reaped($pid, 5);
}

# Start a server with an idle stdin pipe and its output in result files.
sub start_server
{
    my ($tag, $cmd) = @_;
    my ($out, $out_file) = result_handle("$tag-stdout.txt");
    my ($err) = result_handle("$tag-stderr.txt");
    my $pid = open3(my $stdin, ">&" . fileno($out), ">&" . fileno($err),
                    command_line($cmd));

    return ($pid, $stdin, $out, $err, $out_file);
}

sub start_s_server
{
    my $tag = shift;

    return start_server($tag,
                        app(["openssl", "s_server", "-accept", "127.0.0.1:0",
                             "-naccept", "1",
                             "-cert", $server_pem, "-key", $server_key]));
}

sub write_all
{
    my ($sock, $buf) = @_;

    for (my $off = 0; $off < length($buf); ) {
        my $w = syswrite($sock, $buf, length($buf) - $off, $off);

        return unless defined $w;
        $off += $w;
    }
}

# Relay between the client and the server, but stall the handshake halfway:
# pass on the server's first TLS record (its ServerHello), then hold back the
# rest of its flight for $stall seconds.  The client then knows its cipher
# without having finished, which is the state an early exit is easiest to
# mistake for success in.  Runs until the client ($pid) exits or $limit
# seconds pass.  Returns its wait status (undef if still running) and whether
# the held flight was released while the client was still there to get it.
# This polls in-process: select() works on sockets on Windows, pipes aside.
sub relay_with_stall
{
    my ($pid, $client, $server, $stall, $limit) = @_;
    my $sel = IO::Select->new($client, $server);
    my $deadline = time() + $limit;
    my ($held, $release_at, $released) = ("", undef, 0);

    while (time() < $deadline) {
        my $reaped = waitpid($pid, WNOHANG);

        return ($?, $released) if $reaped == $pid;
        last if $reaped < 0;
        if (defined $release_at && !$released && time() >= $release_at) {
            write_all($client, $held);
            $released = 1;
        }
        if ($sel->count() == 0) {
            select(undef, undef, undef, 0.1);
            next;
        }
        foreach my $s ($sel->can_read(0.1)) {
            my $from_server = $s == $server;
            my $to = $from_server ? $client : $server;
            my $n = sysread($s, my $buf, 16384);

            unless ($n) {
                # EOF: stop reading this side, and pass the close on unless
                # data for the other side is still being held back.
                $sel->remove($s);
                shutdown($to, 1) if $released || !$from_server;
                next;
            }
            if (!$from_server || $released) {
                write_all($to, $buf);
                next;
            }
            $held .= $buf;
            next if defined $release_at || length($held) < 5;
            my $first = 5 + unpack("n", substr($held, 3, 2));
            next if length($held) < $first;
            write_all($client, substr($held, 0, $first, ""));
            $release_at = time() + $stall;
        }
    }
    return (undef, $released);
}

SKIP: {
    skip "the Windows stdin polling path is only built for Windows targets", 10
        unless $windows_stdin;

    # $s_server_i is the server's stdin: a pipe whose writer this recipe holds
    # open and never writes to.  That is what a test harness, or any script
    # that pipes into the app without sending anything, presents.  Such a pipe
    # never becomes readable, and the accept loop used to reach a blocking read
    # of it before it had accepted anything at all.  The writer must stay open
    # for the whole run: closing it makes the pipe readable at EOF and hides
    # the problem.
    my ($s_server_pid, $s_server_i, $s_server_out, $s_server_err,
        $s_server_out_file) = start_s_server("s_server");

    my $port = wait_for_port($s_server_out_file, 30);
    ok(defined $port, "s_server port check");

    SKIP: {
        skip "could not start s_server", 4 unless defined $port;

        # The client gets the same kind of idle, open stdin pipe.  It is run
        # with -no-interactive, which never reads stdin, so it has to finish on
        # its own once the peer is done with it, whatever stdin is doing.
        my ($s_client_out, $s_client_out_file)
            = result_handle("s_client-stdout.txt");
        my ($s_client_err, $s_client_err_file)
            = result_handle("s_client-stderr.txt");
        my $s_client_pid
            = open3(my $s_client_i,
                    ">&" . fileno($s_client_out), ">&" . fileno($s_client_err),
                    command_line(app(["openssl", "s_client", "-no-interactive",
                                      "-brief",
                                      "-connect", "127.0.0.1:$port"])));

        my $s_client_status = wait_for_exit($s_client_pid, 30);

        release_and_reap("s_client", $s_client_pid, $s_client_i, 15)
            unless defined $s_client_status;
        close $s_client_out;
        close $s_client_err;

        # This recipe cannot be run by most contributors, so leave something
        # in the log to work from when it does fail.
        diag("s_client stderr:\n" . slurp($s_client_err_file))
            unless defined $s_client_status;

        ok(defined $s_client_status,
           "s_client -no-interactive exits with an idle stdin pipe");
        is($s_client_status, 0, "s_client -no-interactive exit status");

        # Exiting is not on its own enough.  Before this fix the server blocked
        # on stdin ahead of its first accept(), so the handshake never started,
        # and the client still exited 0 as soon as a second of socket silence
        # had passed.  This is what separates the fix from a client that merely
        # gave up on time.
        like(slurp($s_client_err_file), $established,
             "s_client -no-interactive completed the handshake");

        # -naccept 1 makes s_server leave once it has served one connection, so
        # its own exit is what says the accept loop was never stuck on stdin.
        # Its stdin writer has to still be open for that to mean anything.
        my $s_server_status = wait_for_exit($s_server_pid, 30);

        ok(defined $s_server_status,
           "s_server served the connection with an idle stdin pipe");
        $s_server_pid = 0 if defined $s_server_status;
    }

    release_and_reap("s_server", $s_server_pid, $s_server_i, 15)
        if $s_server_pid;
    close $s_server_out;
    close $s_server_err;

    # Now a server that is slow to finish the handshake.  With -nbio, s_client
    # drives its handshake from the same 1-second poll that watches stdin, and
    # a timeout there used to reach the -no-interactive exit mid-handshake: the
    # client exited 0 without ever finishing.  (Without -nbio the handshake
    # blocks inside SSL_write() instead and the poll never sees it.)  The
    # client connects to a relay in this recipe rather than to s_server, so
    # that the relay can stall the server's flight for longer than one poll.
    my $stall = 2.5;
    my ($s_server2_pid, $s_server2_i, $s_server2_out, $s_server2_err,
        $s_server2_out_file) = start_s_server("s_server-stalled");
    my $port2 = wait_for_port($s_server2_out_file, 30);
    ok(defined $port2, "s_server port check for the stalled handshake");

    SKIP: {
        skip "could not start s_server", 4 unless defined $port2;
        my $listener = IO::Socket::INET->new(LocalHost => "127.0.0.1",
                                             LocalPort => 0, Listen => 1)
            or BAIL_OUT("cannot listen for the client: $@");

        my ($s_client_out) = result_handle("s_client-stalled-stdout.txt");
        my ($s_client_err, $s_client_err_file)
            = result_handle("s_client-stalled-stderr.txt");
        my $s_client_pid
            = open3(my $s_client_i,
                    ">&" . fileno($s_client_out), ">&" . fileno($s_client_err),
                    command_line(app(["openssl", "s_client", "-no-interactive",
                                      "-brief", "-nbio", "-connect",
                                      "127.0.0.1:" . $listener->sockport()])));

        my ($client, $server, $s_client_status, $released);

        $client = $listener->accept()
            if IO::Select->new($listener)->can_read(30);
        $server = IO::Socket::INET->new(PeerHost => "127.0.0.1",
                                        PeerPort => $port2)
            if $client;
        diag("the relay could not connect the client to s_server")
            unless $client && $server;
        ($s_client_status, $released)
            = relay_with_stall($s_client_pid, $client, $server, $stall, 30)
            if $client && $server;

        release_and_reap("s_client", $s_client_pid, $s_client_i, 15)
            unless defined $s_client_status;
        close $_ foreach grep { defined } ($client, $server, $listener);
        close $s_client_out;
        close $s_client_err;

        diag("s_client stderr:\n" . slurp($s_client_err_file))
            unless $released && defined $s_client_status;

        # The client must still be there when the rest of the server's flight
        # arrives: leaving before then is the early exit.
        ok($released, "s_client -no-interactive waits for a stalled handshake");
        ok(defined $s_client_status,
           "s_client -no-interactive exits after a stalled handshake");
        is($s_client_status, 0,
           "s_client -no-interactive exit status after a stalled handshake");
        like(slurp($s_client_err_file), $established,
             "s_client -no-interactive completed the stalled handshake");
    }

    # Closing the relay's sockets ends s_server's only connection, so a working
    # build is already on its way out.
    $s_server2_pid = 0 if defined wait_for_exit($s_server2_pid, 10);
    release_and_reap("s_server", $s_server2_pid, $s_server2_i, 15)
        if $s_server2_pid;
    close $s_server2_out;
    close $s_server2_err;
}

# One QUIC case: start quic_alpn_server for a single connection, run
# s_client -quic -no-interactive -brief -nbio against it with @args (and an
# idle stdin pipe, as above), and wait for the server to finish.  Returns the
# server's port (undef if it did not start), the client's wait status (undef
# if it was still running after 30 seconds), and the file holding the client's
# stderr.
sub quic_case
{
    my ($tag, @args) = @_;
    my ($server_pid, $server_i, $server_out, $server_err, $server_out_file)
        = start_server("$tag-server",
                       test(["quic_alpn_server", $server_pem, $server_key,
                             "1"]));
    my $port = wait_for_port($server_out_file, 30);
    my ($status, $err_file);

    if (defined $port) {
        my ($out) = result_handle("$tag-stdout.txt");
        my $err;

        ($err, $err_file) = result_handle("$tag-stderr.txt");
        my $pid = open3(my $stdin, ">&" . fileno($out), ">&" . fileno($err),
                        command_line(app(["openssl", "s_client", "-quic",
                                          "-no-interactive", "-brief", "-nbio",
                                          "-connect", "127.0.0.1:$port",
                                          @args])));

        $status = wait_for_exit($pid, 30);
        if (defined $status) {
            close $stdin;
        } else {
            release_and_reap("s_client", $pid, $stdin, 15);
        }
        close $out;
        close $err;
        if (defined $status) {
            note("s_client stderr:\n" . slurp($err_file));
        } else {
            diag("s_client stderr:\n" . slurp($err_file));
        }
    }

    # The server leaves once it has dealt with its one connection.
    release_and_reap("quic_alpn_server", $server_pid, $server_i, 15)
        unless defined wait_for_exit($server_pid, 10);
    close $server_out;
    close $server_err;
    return ($port, $status, $err_file);
}

# Whether a handshake failed is not specific to Windows, and neither is this.
# With -nbio, a QUIC client completes its handshake, or fails it, inside
# SSL_handle_events(), with no SSL_read() or SSL_write() waiting to report
# the result.  s_client -no-interactive used to exit 0 at once, before any
# handshake; and once it learned to wait for the handshake, it waited for
# ever when the handshake failed, and when it succeeded it left before
# reporting it.  s_server cannot speak QUIC, so quic_alpn_server stands in.
# It takes the ALPN protocol "ossltest".  The failed handshake is one that the
# client fails itself, by insisting on a host name that the server's
# certificate does not have.
SKIP: {
    skip "QUIC is disabled", 8 if disabled("quic");

    my ($port, $status, $err_file)
        = quic_case("s_client-quic", "-alpn", "ossltest");

    ok(defined $port, "QUIC server port check");
    ok(defined $status,
       "s_client -no-interactive -nbio exits after a QUIC handshake");
    is($status, 0,
       "s_client -no-interactive -nbio exit status after a QUIC handshake");
    like(slurp($err_file), $established,
         "s_client -no-interactive -nbio completed the QUIC handshake");

    ($port, $status, $err_file)
        = quic_case("s_client-quic-hostname", "-alpn", "ossltest",
                    "-CAfile", $root_pem, "-verify_return_error",
                    "-verify_hostname", "mismatch.invalid");

    ok(defined $port, "QUIC server port check for the host name mismatch");
    like(slurp($err_file), qr/hostname mismatch/,
         "s_client found the host name mismatch");
    ok(defined $status,
       "s_client -no-interactive -nbio exits once it fails the QUIC handshake itself");
    ok(defined $status && $status != 0,
       "s_client -no-interactive -nbio exit status once it fails the QUIC handshake itself");
}
