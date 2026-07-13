#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# check-doc-comments.pl - check that new or changed function declarations in
# header files carry the documentation comments required by DOCUMENTATION.md
# and STYLE.md.  It only verifies that the required documentation is present;
# it does not judge whether the content is correct.
#
# Those two documents are authoritative.  The rules below come from STYLE.md
# "Applicability" and "Doxygen comments" (including "Public functions: link the
# manual page") and DOCUMENTATION.md "Public symbols in the libraries" and
# "Internal functions, structures, globals and macros".
#
# Runs as a pre-commit hook (.pre-commit-config.yaml) and in CI via
# .github/workflows/style-checks.yml on a pull request's changed files.  Only
# function prototypes on added or modified lines are checked; unchanged code is
# left alone.
#
# Rules:
#   * public headers (include/openssl/...): the prototype must be immediately
#     preceded by a /** ... */ doxygen block containing "@see NAME(3)" for the
#     function's own name, and that manual page must exist in the doc/ tree.
#   * other (internal) headers: the prototype must be immediately preceded by a
#     /** ... */ block with a @param for each named parameter and a @returns
#     when the return type is not void.  When the parameter list cannot be
#     parsed with confidence the @param check is skipped; the block is still
#     required.
#
# Not checked: static functions, non-function declarations (macros, typedefs,
# function-pointer typedefs), and declarations carrying a "doc-exempt" marker.
# The marker invokes the trivial-item exception from DOCUMENTATION.md; place
# /* doc-exempt: <reason> */ immediately before the declaration.
#
# The diff range is $DOC_COMMENTS_RANGE if set (CI sets it to the PR base sha),
# else the staged changes if any exist, else the merge-base with the upstream
# default branch.

use strict;
use warnings;

my @files = grep { /\.h(?:\.in)?$/ && -f $_ } @ARGV;
exit 0 unless @files;

my $range     = diff_range();
print STDERR "check-doc-comments: diffing changed lines against '$range'\n";
my %doc_name  = harvest_pod_names();          # NAME => { section => 1 }
my $nerrors   = 0;

for my $file (@files) {
    # Skip a generated header when its .h.in source exists; the source is
    # what contributors edit and what carries the declarations.
    next if $file =~ /\.h$/ && -f "$file.in";
    my %changed = changed_lines($range, $file);
    next unless %changed;
    check_file($file, \%changed);
}

print STDERR "note: a trivial function may be exempted with a "
    . "\"/* doc-exempt: <reason> */\" comment immediately before its "
    . "declaration\n"
    if $nerrors;

exit($nerrors ? 1 : 0);

# ---------------------------------------------------------------------------

sub nit {
    my ($file, $line, $msg) = @_;
    print STDERR "$file:$line: $msg\n";
    $nerrors++;
}

sub is_public { return $_[0] =~ m{(?:^|/)include/openssl/}; }

sub diff_range {
    return "$ENV{PRE_COMMIT_FROM_REF}...$ENV{PRE_COMMIT_TO_REF}"
        if $ENV{PRE_COMMIT_FROM_REF} && $ENV{PRE_COMMIT_TO_REF};
    return $ENV{DOC_COMMENTS_RANGE} if $ENV{DOC_COMMENTS_RANGE};
    my $staged = `git diff --cached --name-only 2>/dev/null`;
    return '--cached' if length $staged;
    for my $base (qw(upstream/master origin/master master)) {
        chomp(my $mb = `git merge-base $base HEAD 2>/dev/null`);
        return $mb if $mb ne '';
    }
    return 'HEAD~1';
}

# Set of new-side line numbers added/changed for $file in $range.
sub changed_lines {
    my ($range, $file) = @_;
    my @cmd = $range eq '--cached'
        ? ('git', 'diff', '--cached', '-U0', '--', $file)
        : ('git', 'diff', '-U0', $range, '--', $file);
    my %ch;
    open my $fh, '-|', @cmd or return %ch;
    while (<$fh>) {
        next unless /^\@\@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? \@\@/;
        my ($start, $count) = ($1, defined $2 ? $2 : 1);
        next unless $count > 0;
        $ch{$_} = 1 for $start .. $start + $count - 1;
    }
    close $fh;
    return %ch;
}

# Build NAME => { section => 1 } from doc/man*/*.pod on disk (the working
# tree), so a page added in the same change resolves.
sub harvest_pod_names {
    my %names;
    for my $pod (glob 'doc/man*/*.pod') {
        my ($sec) = $pod =~ m{doc/man(\d)/} or next;
        open my $fh, '<', $pod or next;
        my ($in_name, $buf) = (0, '');
        while (<$fh>) {
            if (/^=head1\s+NAME/)      { $in_name = 1; next; }
            if ($in_name && /^=head1/) { last; }
            $buf .= $_ if $in_name;
        }
        close $fh;
        $buf =~ s/\s+-\s+.*\z//s;          # drop the " - description" tail
        $names{$_}{$sec} = 1 for ($buf =~ /([A-Za-z_]\w*)/g);
    }
    return %names;
}

sub check_file {
    my ($file, $changed) = @_;
    open my $fh, '<', $file or return;
    my @lines = <$fh>;
    close $fh;
    chomp @lines;
    my $is_hin = $file =~ /\.h\.in$/ ? 1 : 0;

    for my $p (@{ parse_prototypes(\@lines, $is_hin) }) {
        # Only new/changed declarations.
        next unless grep { $changed->{$_} } $p->{start} .. $p->{end};

        my ($block, $doxy) = preceding_block(\@lines, $p->{start});
        next if defined $block && $block =~ /doc-exempt/;   # opt-out

        if (!$doxy) {
            nit($file, $p->{start},
                "$p->{name}(): missing doxygen /** */ documentation block");
            next;
        }

        if (is_public($file)) {
            if ($block !~ /\@see\b[^*]*?\b\Q$p->{name}\E\s*\(3\)/s) {
                nit($file, $p->{start},
                    "$p->{name}(): doxygen block must link its manual page "
                    . "with \@see $p->{name}(3)");
            } elsif (!$doc_name{$p->{name}}{3}) {
                nit($file, $p->{start},
                    "$p->{name}(): \@see $p->{name}(3) has no matching "
                    . "doc/man3 page");
            }
        } else {
            # Report a function's missing tags on one line; they are all fixed
            # in the single doxygen block attached to the declaration.
            my @clauses;
            push @clauses, "\@returns for the return value"
                if !$p->{ret_void} && $block !~ /\@returns?\b/;
            my @params;
            unless ($p->{params_uncertain}) {        # fail open on parse doubt
                # Harvest the names doxygen actually documents.  Accept an
                # optional [in]/[out]/[in,out] direction attribute and a
                # comma-separated list of names on a single @param line.
                my %documented;
                while ($block =~ /\@param\b\s*(?:\[[^\]]*\])?\s*
                                  ([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)/gx) {
                    $documented{$_} = 1 for split /\s*,\s*/, $1;
                }
                for my $param (@{ $p->{params} }) {
                    push @params, "'$param'" unless $documented{$param};
                }
            }
            if (@params) {
                my $word = @params == 1 ? 'parameter' : 'parameters';
                push @clauses, "\@param for $word " . join(', ', @params);
            }
            nit($file, $p->{start},
                "$p->{name}(): doxygen block missing " . join(' and ', @clauses))
                if @clauses;
        }
    }
}

# Find the doxygen/comment block immediately preceding (adjacent to) $start
# (1-indexed).  Returns ($text, $is_doxygen).
sub preceding_block {
    my ($lines, $start) = @_;
    my $i = $start - 2;                    # 0-indexed line just above
    return (undef, 0) if $i < 0 || $lines->[$i] !~ m{\*/\s*$};
    my @blk;
    while ($i >= 0) {
        unshift @blk, $lines->[$i];
        last if $lines->[$i] =~ m{/\*};
        $i--;
    }
    my $doxy = ($blk[0] // '') =~ m{/\*\*} ? 1 : 0;
    return (join("\n", @blk), $doxy);
}

# Return arrayref of prototypes: { name, start, end, ret_void, params,
# params_uncertain }.  Comments are blanked first so they do not interfere.
sub parse_prototypes {
    my ($lines, $is_hin) = @_;
    my @code = blank_noncode($lines, $is_hin);

    # Prototypes appear at file scope or directly inside an extern "C" {}
    # linkage block; never inside a struct/union/enum body or a function
    # body.  So track a "skip depth": every '{' opens a skip scope EXCEPT an
    # extern "..." linkage block, which is transparent.  Prototypes are only
    # recorded when the skip depth is zero.
    my @protos;
    my @stack;                          # 1 = skip brace, 0 = transparent
    my ($stmt, $sline, $sskip, $skip) = ('', 0, 0, 0);
    for my $idx (0 .. $#code) {
        next if $lines->[$idx] =~ /^\s*#/;         # preprocessor directive
        for my $ch (split //, $code[$idx]) {
            if ($ch eq '{') {
                (my $pre = $stmt) =~ s/\s+$//;
                my $transparent = $pre =~ /\bextern\s*"[^"]*"$/ ? 1 : 0;
                push @stack, $transparent ? 0 : 1;
                $skip++ unless $transparent;
                $stmt = '';
            } elsif ($ch eq '}') {
                my $was = pop @stack;
                $skip-- if $was;
                $skip = 0 if $skip < 0;
                $stmt = '';
            } elsif ($ch eq ';') {
                if ($sskip == 0 && $stmt !~ /[{}]/) {
                    my $p = classify_stmt($stmt . ';', $sline, $idx + 1);
                    push @protos, $p if $p;
                }
                $stmt = '';
            } else {
                if ($stmt eq '' && $ch =~ /\S/) { $sline = $idx + 1; $sskip = $skip; }
                $stmt .= $ch if $stmt ne '' || $ch =~ /\S/;
            }
        }
        $stmt .= ' ' if $stmt ne '';
    }
    return \@protos;
}

sub classify_stmt {
    my ($raw, $start, $end) = @_;
    (my $s = $raw) =~ s/\s+/ /g;
    $s =~ s/^\s+//;
    return undef if $s =~ /^typedef\b/;                      # typedef
    return undef if $s =~ /^\s*static\b/;                    # static fn
    # Collapse the STACK_OF()/LHASH_OF() type macros to a plain type token so
    # a return type like "const STACK_OF(X509) *" does not get mistaken for a
    # function named STACK_OF.
    $s =~ s/\b(?:STACK_OF|LHASH_OF|SPARSE_ARRAY_OF)\s*\(\s*\w+\s*\)/OSSL_TYPE/g;
    # strip leading attribute / deprecation qualifier macros
    1 while $s =~ s/^(?:OSSL_DEPRECATEDIN_\S+|__owur|ossl_unused)\s+//;
    # ret-type (must contain a space or '*' before the name) then NAME(args);
    return undef unless
        $s =~ /^((?:\w[\w ]*?)[ \*]+)([A-Za-z_]\w*)\s*\((.*)\)\s*;$/;
    my ($ret, $name, $args) = ($1, $2, $3);
    (my $rt = $ret) =~ s/\s+$//;
    my $ret_void = ($rt eq 'void') ? 1 : 0;

    my ($params, $uncertain) = parse_params($args);
    return {
        name             => $name,
        start            => $start,
        end              => $end,
        ret_void         => $ret_void,
        params           => $params,
        params_uncertain => $uncertain,
    };
}

# Extract parameter names.  Returns (\@names, $uncertain).  We fail open
# (uncertain=1) on anything we cannot confidently name.
sub parse_params {
    my ($args) = @_;
    $args =~ s/^\s+//; $args =~ s/\s+$//;
    return ([], 0) if $args eq '' || $args eq 'void';
    return ([], 1) if $args =~ /\Q...\E/ || $args =~ /\(\s*\*/;  # varargs / fn-ptr
    my @names;
    for my $a (split /,/, $args) {
        $a =~ s/\[.*?\]//g;                       # drop array dims
        if ($a =~ /([A-Za-z_]\w*)\s*$/) {
            my $n = $1;
            # a trailing bare type keyword => unnamed parameter => uncertain
            return ([], 1) if $n =~ /^(void|int|char|long|short|unsigned|
                                       signed|size_t|double|float)$/x;
            push @names, $n;
        } else {
            return ([], 1);
        }
    }
    return (\@names, 0);
}

# Blank out /* */ and // comments, and (for .h.in files) {- ... -} template
# fragments, preserving line count and columns so line numbers stay accurate.
sub blank_noncode {
    my ($lines, $is_hin) = @_;
    my @out;
    my $mode = 0;                       # 0 code, 1 /* */ comment, 2 {- -} template
    for my $l (@$lines) {
        my ($o, $j) = ('', 0);
        while ($j < length $l) {
            my $two = substr($l, $j, 2);
            if ($mode == 1) {
                if ($two eq '*/') { $mode = 0; $o .= '  '; $j += 2; }
                else              { $o .= ' ';             $j++;    }
            } elsif ($mode == 2) {
                if ($two eq '-}') { $mode = 0; $o .= '  '; $j += 2; }
                else              { $o .= ' ';             $j++;    }
            } elsif ($two eq '/*')            { $mode = 1; $o .= '  '; $j += 2; }
            elsif ($is_hin && $two eq '{-')   { $mode = 2; $o .= '  '; $j += 2; }
            elsif ($two eq '//') { $o .= ' ' x (length($l) - $j);   last; }
            else                 { $o .= substr($l, $j, 1);         $j++;   }
        }
        push @out, $o;
    }
    return @out;
}
