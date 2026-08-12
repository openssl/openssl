#! /usr/bin/env perl
# -*- mode: Perl -*-
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Spec::Functions qw(catfile splitdir);
use IPC::Cmd;
use OpenSSL::Test qw(:DEFAULT bldtop_dir srctop_dir);

use constant MAX_REPORTED => 10;    # Longer lists are truncated

BEGIN {
    setup("test_generated_ignored");
}

use lib bldtop_dir('.');
use configdata;

# Every file the build generates must be absent from the index and covered
# by .gitignore.  The generated files that are deliberately committed --
# doc/build.info, util/libcrypto.num and the like -- come from explicit
# "make update" targets rather than GENERATE directives, so they are not
# among the targets checked here.

plan skip_all => "This test requires git"
    unless IPC::Cmd::can_run('git');
# Release tarballs are unpacked archives with no repository.  .git is a
# directory in an ordinary clone and a file in a linked worktree.
plan skip_all => "This test requires a git checkout"
    unless -e catfile(srctop_dir(), '.git');

# The targets are native paths relative to the build tree; git speaks only
# in forward slashes.  splitdir() knows the local separator, so splitting
# and rejoining converts them without naming it.
my @targets = sort map { join('/', splitdir($_)) }
                   keys %{ $unified_info{generate} };

plan skip_all => "This build configuration generates no files"
    unless @targets;

plan tests => 2;

note "Checking ", scalar @targets, " generated files";

my %tracked = map { $_ => 1 } git_run('ls-files');
my %why = ignore_faults(@targets);
my @committed = grep { $tracked{$_} } @targets;
my @unignored = grep { exists $why{$_} } @targets;

ok(!@committed, "no generated file is tracked in git")
    or report_tracked(@committed);
ok(!@unignored, "every generated file is in .gitignore")
    or report_unignored(\%why, @unignored);

# Of the given paths, return those .gitignore does not ignore, mapped to an
# explanation, or to the empty string where none is needed.
#
# git draws ignore rules from three places: the .gitignore files in the
# tree, .git/info/exclude, and the file named by core.excludesFile.  Only
# the first is committed.  A generated file the other two cover is one that
# every other clone is free to commit, so it must fail here.  Telling them
# apart needs the rule that matched, which "git check-ignore -v" reports as
#
#     <source>:<line>:<pattern>\t<pathname>
sub ignore_faults {
    my (@paths) = @_;
    my %rule_for;

    foreach my $line (git_batched(['check-ignore', '--no-index', '-v'],
                                  \@paths)) {
        # A pattern may contain anything but a tab, so the pathname is
        # split off from the end.
        my ($fields, $path) = $line =~ m|^(.*)\t([^\t]*)$|
            or next;
        my ($source, $line_no, $pattern) = $fields =~ m|^(.+?):(\d+):(.*)$|
            or next;

        $rule_for{$path} = { source => $source, line => $line_no,
                             pattern => $pattern };
    }

    # An absolute path is core.excludesFile and anything under .git is
    # .git/info/exclude.  Neither can be tracked, and git rejects them as
    # pathspecs, so they are dropped before asking.
    my @sources = grep { !m|^([A-Za-z]:)?[\\/]| && !m|^\.git/| }
                  do { my %seen;
                       grep { !$seen{$_}++ } map { $_->{source} }
                       values %rule_for };
    my %tracked_source = map { $_ => 1 } git_batched(['ls-files'], \@sources);
    my %why;

    foreach my $path (@paths) {
        my $rule = $rule_for{$path};

        # A path is ignored only if some rule matched it, that rule was not
        # a negative one, and the file holding the rule is committed.
        next if defined $rule
                && $rule->{pattern} !~ m|^!|
                && $tracked_source{ $rule->{source} };

        # Verbose mode reports negative rules too, and those are matches
        # that leave the path *not* ignored.  They are also the one case
        # where the placement of the new entry matters, since an entry
        # above the negative rule has no effect.
        $why{$path} = defined $rule && $rule->{pattern} =~ m|^!|
            ? "because $rule->{source} line $rule->{line}"
              . " ($rule->{pattern}) cancels an earlier match - add it to"
              . " .gitignore after line $rule->{line}"
            : '';
    }
    return %why;
}

# Run a git subcommand in the source tree and return its standard output as
# a list of lines.  Both subcommands used here report their answer entirely
# on stdout and set their exit status only to say whether the answer was
# empty, so it is not consulted.  core.quotePath is off so that paths come
# back as they were passed in.
sub git_run {
    my (@args) = @_;

    open(my $pipe, '-|', 'git', '-c', 'core.quotePath=false',
                         '-C', srctop_dir(), @args)
        or die "Failed to run git @args: $!";
    my @lines = map { s|\R$||; $_ } <$pipe>;
    close $pipe;
    return @lines;
}

# As git_run(), but with a list of paths to act on.  They go in batches:
# the full list runs to a couple of thousand entries, enough to exceed the
# command line length limit on some platforms.
sub git_batched {
    my ($subcmd, $paths) = @_;
    my $batch = 100;
    my @lines;

    for (my $first = 0; $first <= $#$paths; $first += $batch) {
        my $last = $first + $batch - 1;

        $last = $#$paths if $last > $#$paths;
        push @lines, git_run(@$subcmd, '--', @{$paths}[$first .. $last]);
    }
    return @lines;
}

sub report_tracked {
    my (@paths) = @_;

    diag scalar @paths, " generated file(s) are committed to the repository",
         " and need to be removed:";
    diag "    git rm --cached ", $_ foreach shown(@paths);
    diag "    ... and ", @paths - MAX_REPORTED, " more" if @paths > MAX_REPORTED;
}

# Paths are shown with a leading "/", the anchored form .gitignore uses for
# generated files.
sub report_unignored {
    my ($why, @paths) = @_;

    diag scalar @paths, " generated file(s) are not ignored by .gitignore",
         " and need to be added:";
    foreach my $path (shown(@paths)) {
        diag "    /$path";
        diag "        ", $why->{$path} if $why->{$path} ne '';
    }
    diag "    ... and ", @paths - MAX_REPORTED, " more" if @paths > MAX_REPORTED;
}

sub shown {
    my (@paths) = @_;

    return @paths > MAX_REPORTED ? @paths[0 .. MAX_REPORTED - 1] : @paths;
}
