#!/usr/bin/perl
#
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# openssl-format-check.pl
# - check source file(s) according to OpenSSL coding style
#
# usage:
#   openssl-format-check.pl <files>
#
# checks adherence to the formatting rules of the OpenSSL coding guidelines.
# This tool is in preliminary state: it is incomplete and yields some false
# positives. Still it should be useful for detecting most typical glitches.

use strict;
use List::Util qw[min max];

use constant INDENT_LEVEL => 4;
use constant MAX_LENGTH => 80;

my $indent;
my $line;
my $line_opening_brace;
my $contents_before;       # used only if $line > 1
my $contents_before2;      # used only if $line > 2
my $hanging_indent;
my $hanging_parens;        # used only if $hanging_indent != -1
my $hanging_braces;        # used only if $hanging_indent != -1
my $hanging_alt_indent;    # used only if $hanging_indent != -1
my $braceless_indent;
my $multiline_condition_indent;
my $in_multiline_macro;    # number of lines so far within macro
my $in_multiline_comment;
my $comment_indent;        # used only if $in_multiline_comment == 1

sub reset_file_state {
    $indent = 0;
    $line = 0;
    $line_opening_brace = 0;
    $hanging_indent = -1;
    $braceless_indent = 0;
    $multiline_condition_indent = -1;
    $in_multiline_macro = 0;
    $in_multiline_comment = 0;
}

reset_file_state();
while(<>) {
    $line++;
    my $orig_ = $_;

    if(m/[\x09]/) {
        print "$ARGV:$line:TAB: $orig_";
    }
    if(m/[\x0d]/) {
        print "$ARGV:$line:CR: $orig_";
    }
    if(m/[\x00-\x08\x0B-\x0C\x0E-\x1F]/) {
        print "$ARGV:$line:non-printable: $orig_";
    }
    if(m/[\x7F-\xFF]/) {
        print "$ARGV:$line:non-ASCII: $orig_";
    }

    my $len = length($_) - 1; # '- 1' avoids counting trailing \n
    my $hidden_esc_dblquot = $_;
    while($hidden_esc_dblquot =~ s/([^\"]\".*?\\)\"/$1\\/g) {} # TODO check this
    if($len > MAX_LENGTH &&
       !($hidden_esc_dblquot =~ m/^(.*?)\"[^\"]*\"\s*(,|[\)\}]*[,;]?)\s*$/
         && length($1) < MAX_LENGTH)) { # allow over-long trailing string literal with starting col before MAX_LENGTH
        print "$ARGV:$line:len=$len: $orig_";
    }
    if(m/\s\n$/) {
        print "$ARGV:$line:SPC\@EOL: $orig_";
    }

    m/^(\s*)(.?)(.?)/;
    my $count = length($1) - (m/^\s*$/ ? 1 : 0); # number of leading space characters (except newline), which basically should equal $indent as checked below
    my $local_indent = 0;
    my $local_hanging_indent = 0;
    if (!$in_multiline_comment) {
        if (m/^(.*?)\s*\\\s*$/) { # trailing '\' typically used in macro declarations
            $_ = "$1\n"; # remove it along with any preceding whitespace
        }
        $_ = "$1$2" if m/^(\s*extern\s*"C"\s*)\{(\s*)$/; # ignore opening brace in 'extern "C" {' (used with '#ifdef __cplusplus' in header files)
        if (m/^\n$/ || # empty line
            # ($2 eq "/" && $3 eq "*"); # do not ignore indent on line starting comment: '/*'
            m/^#/) { # preprocessor line, starting with '#'
            # ignore indent:
            $hanging_indent = -1;
            $braceless_indent = 0;
            $local_indent = $count - $indent;
        }
        if ($hanging_indent == -1) {
            if (m/^(\s*)(case|default)\W/) {
                $local_indent = -INDENT_LEVEL;
            } else {
                $local_indent = -($indent - 1) if (m/^(\s*)([a-z_0-9]+):/) #  && $2 ne "default"); # label
            }
        } else {
            $local_hanging_indent = INDENT_LEVEL if ($2 eq "&" && $3 eq "&") ||
                                                    ($2 eq "|" && $3 eq "|");  # line starting with && or ||
        }
    }

    # TODO make sure that any '{' and '}' in comments and string literals do not interfere with the following calculations
    m/^([^\{]*)/; # prefix before any opening {
    my $num_initial_closing_braces = $1 =~ tr/\}//;
    $local_indent -= $num_initial_closing_braces * INDENT_LEVEL;
    if ($indent + $local_indent < 0) {
        $local_indent = -$indent;
        print "$ARGV:$line:too many }:$orig_"
            unless $contents_before =~ m/^\s*#\s*ifdef\s*__cplusplus\s*$/; # ignore closing brace on line after '#ifdef __cplusplus' (used in header files)
    }
    if($in_multiline_comment) {
        print "$ARGV:$line:indent=$count!=$comment_indent: $orig_"
            if $count != $comment_indent;
    } elsif ($hanging_indent == -1) {
        my $tmp = $contents_before;
        my $parens_balance = $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
        if (($in_multiline_macro == 1 || $in_multiline_macro == 2 && $parens_balance == -1) && # first line of macro body, where we also match two-line macro headers
            $count == 0 && $indent == INDENT_LEVEL) {
            $indent -= INDENT_LEVEL; # workaround for macro started without indentation
        }
        print "$ARGV:$line:indent=$count!=".($indent+$braceless_indent+$local_indent).": $orig_"
            if $count != $indent + $braceless_indent + $local_indent;
    } else {
        $hanging_indent     += $local_hanging_indent;
        $hanging_alt_indent += $local_hanging_indent;
        # reduce hanging indent to adapt to given code. This prefers false negatives to false positives that would occur due to incompleteness of the paren/brace matching
        if ($count - $local_hanging_indent >=
            max($indent + $braceless_indent + $local_indent,
                $multiline_condition_indent)) {
            $hanging_indent     = $count if $count < $hanging_indent;
            $hanging_alt_indent = $count if $count < $hanging_alt_indent;
        }

        my $allowed = $hanging_alt_indent == -1 ? "$hanging_indent" : "{$hanging_alt_indent,$hanging_indent}";
        print "$ARGV:$line:indent=$count!=$allowed: $orig_"
            if $count != $hanging_indent &&
               ($hanging_alt_indent == -1 || $count != $hanging_alt_indent);
        $hanging_indent     -= $local_hanging_indent;
        $hanging_alt_indent -= $local_hanging_indent;
    }
    my $tmp = $_; my $brace_balance = ($tmp =~ tr/\{//) - $tmp =~ tr/\}//;
    $indent += $brace_balance * INDENT_LEVEL if $brace_balance != 0;
    if ($indent < 0) {
        $indent = 0;
        # print "$ARGV:$line:too many }:$orig_"; # already reported above
    }

    if (m/^(.*?)\*\/(.*)$/) { # ending comment: '*/'
        my $head = $1;
        my $tail = $2;
        if (!($head =~ m/\/\*/)) { # starting comment: '/*' handled below
            print "$ARGV:$line:*/ outside comment: $orig_" if $in_multiline_comment == 0;
            print "$ARGV:$line:... */: $orig_" if $head =~ m/\S/;
            $_ = $tail;
            $in_multiline_comment = 0;
        }
    }
  MATCH_COMMENT:
    if (m/^(.*?)\/\*-?(.*)$/) { # starting comment: '/*'
        my $head = $1;
        my $tail = $2;
        if ($tail =~ m/\*\/(.*)$/) { # strip contents up to comment end: */
            $_ = "$head $1\n";
            goto MATCH_COMMENT;
        } else {
            print "$ARGV:$line:/* inside comment: $orig_" if $in_multiline_comment == 1;
            print "$ARGV:$line:/* ...: $orig_" if $tail =~ m/\S/;
            $comment_indent = length($head) + 1;
            $in_multiline_comment = 1;
        }
    }
    if(!$in_multiline_comment) {
        if (m/^(\s*\S.*?)\{[^\}]*$/ && !($1 =~ m/=\s*$/)) { # last ... {, no directly preceded by '='
            my $head = $1;
            print "$ARGV:$line:outer {: $orig_"
                if !(m/^\s*(typedef|struct|union)/) &&
                   $in_multiline_macro == 0 &&
                   $indent == INDENT_LEVEL; # $indent is already incremented
            $line_opening_brace = $line;
        }
        if(m/^([^\}]*)\}/) { # first }
            my $head = $1;
            my $line_before = $line - 1;
            if($line_opening_brace &&
               $line_opening_brace == $line_before - 1) {
                print "$ARGV:$line_before:{1 line}:$contents_before" if !($contents_before2 =~ m/typedef|struct|union|static|void/); # including poor matching of function header decl
                # TODO do not show cases where there is another if .. else branch with a block containg more than one line
            }
            $line_opening_brace = 0;
        }

        if($hanging_indent == -1) {
            $hanging_parens = 0;
            $hanging_braces = 0;

            $multiline_condition_indent = -1;
            if (m/^\s*(if|(\}\s*)?else(\s*if)?|for|do|while)(\W.*)$/) {
                my ($head, $tail) = ($1, $4);
                if (!($tail =~ m/\{\s*$/)) { # no trailing '{'
                    my $tmp = $_;
                    my $parens_balance = $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
                    print "$ARGV:$line:too many ):$orig_" if $parens_balance < 0;
                    if (m/^(\s*((\}\s*)?(else\s*)?if|for|while)\s*\(?)/ && $parens_balance > 0) {
                        $multiline_condition_indent = length($1);
                    } else {
                        $braceless_indent += INDENT_LEVEL;
                    }
                }
            }
        }
      MATCH_PAREN:
        # TODO make sure that any '{', '(', ')', and '}' in string literals do not interfere with the following calculations
        # TODO the following assignments to $hanging_indent are just heuristics - nested closing parens and braces are not treated fully
        if (m/^(.*)\(([^\(]*)$/) { # last '('
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\)(.*)/) { # strip contents up to matching ')':
                $_ = "$head $1\n";
                goto MATCH_PAREN;
            }
            $hanging_indent = length($head) + 1;
            $hanging_alt_indent = -1;
            my $tmp = $_;
            $hanging_parens += $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
        }
        elsif (m/^(.*)\{(\s*[^\s\{][^\{]*\s*)$/) { # last '{' followed by non-space: struct initializer
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\}(.*)/) { # strip contents up to matching '}'
                $_ = "$head $1\n";
                goto MATCH_PAREN;
            }
            $hanging_indent = length($head) + 1;
            $hanging_alt_indent = -1;
            my $tmp = $_;
            $hanging_braces += $tmp =~ tr/\{// - $tmp =~ tr/\}//; # count balance of opening - closing braces
        } elsif ($hanging_indent != -1) {
            my $tmp = $_;
            $hanging_parens += $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
            $hanging_braces += $tmp =~ tr/\{// - $tmp =~ tr/\}//; # count balance of opening - closing braces

            my $trailing_brace = m/\{\s*$/;
            my $trailing_semicolon = m/;\s*$/;
            my $hanging_end = $multiline_condition_indent != -1
                ? ($hanging_parens == 0 &&
                   ($hanging_braces == 0 || ($hanging_braces == 1 && $trailing_brace)))
                : ($hanging_parens == 0 && $hanging_braces == 0 &&
                   ($hanging_alt_indent == -1 || $trailing_semicolon)); # assignment and return are terminated by ';', else we assume function header
            if ($hanging_end) {
                $hanging_indent = -1;      # reset hanging indent
                if ($multiline_condition_indent != -1 && !$trailing_brace) {
                    $braceless_indent += INDENT_LEVEL;
                }
            }
        }
        if ($hanging_indent == -1) {
            $braceless_indent = 0 if m/;\s*$/; # trailing ';'
            # at this point, matching (...) have been stripped, simplifying type decl matching
            if (m/^(\s*)((((\w+|\.|->|\[\]|\*)\s*)+=|return)\s*)[^;\{]*\s*$/) { # multi-line assignment: "[type] var = " or return without ;
                my $head = $1;
                my $var_eq = $2;
                $hanging_indent = length($head) + length($var_eq);
                $hanging_alt_indent = length($head) + INDENT_LEVEL;
            }
            # TODO add check for empty line after local variable decls
        }

        if ($orig_ =~ m/^(.*?)\s*\\\s*$/) { # trailing '\' typically used in macro declarations
            $indent += INDENT_LEVEL if $in_multiline_macro == 0;
            $in_multiline_macro += 1;
        } else {
            $indent -= INDENT_LEVEL if $in_multiline_macro
                && $indent >= INDENT_LEVEL; # workaround for macro started without indentation
            $in_multiline_macro = 0;
        }
    }

    $contents_before2 = $contents_before;
    $contents_before = $orig_;
    if(eof) {
        print "$ARGV:EOF:unbalanced nesting of {..}, indentation off by $indent" if $indent != 0;
        reset_file_state();
    }
}
