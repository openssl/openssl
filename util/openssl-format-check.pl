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
# - check formatting of C source according to OpenSSL coding style
#
# usage:
#   openssl-format-check.pl <files>
#
# checks adherence to the formatting rules of the OpenSSL coding guidelines.
# This pragmatic tool is incomplete and yields some false positives.
# Still it should be useful for detecting most typical glitches.

use strict;
use List::Util qw[min max];

use constant INDENT_LEVEL => 4;
use constant MAX_LENGTH => 80;

my $line;                  # current line number
my $contents;              # contens of current line
my $contents_before;       # contents of last non-comment line, used only if $line > 1
my $contents_before2;      # contents of but-last non-comment line, used only if $line > 2
my $line_opening_brace;    # number of last line with opening brace
my $indent;                # currently required indent
my $hanging_indent;        # currently hanging indent, else -1
my $hanging_open_parens;   # used only if $hanging_indent != -1
my $hanging_open_braces;   # used only if $hanging_indent != -1
my $hanging_alt_indent;    # alternative hanging indent (for assignments), used only if $hanging_indent != -1
my $extra_singular_indent; # extra indent for just one statement
my $multiline_condition_indent; # special indent after if/for/while
my $multiline_value_indent;# special indent at LHS of assignment or after return
my $in_enum;               # used to determine terminator of assignment
my $in_multiline_macro;    # number of lines so far within multi-line macro
my $multiline_macro_no_indent; # workaround for macro body without extra indent
my $in_multiline_comment;  # flag whether within multi-line comment
my $comment_indent;        # used only if $in_multiline_comment == 1

sub reset_file_state {
    $indent = 0;
    $line = 0;
    $line_opening_brace = 0;
    $hanging_indent = -1;
    $extra_singular_indent = 0;
    $multiline_condition_indent = $multiline_value_indent = -1;
    $in_enum = 0;
    $in_multiline_macro = 0;
    $in_multiline_comment = 0;
}

sub complain {
    my $msg = shift;
    print "$ARGV:$line:$msg: $contents";
}

reset_file_state();
while(<>) {
    $line++;
    $contents = $_;

    # check for TAB character(s)
    complain("TAB") if m/[\x09]/;

    # check for CR character(s)
    complain("CR") if m/[\x0d]/;

    # check for other non-printable ASCII character(s)
    complain("non-printable") if m/[\x00-\x08\x0B-\x0C\x0E-\x1F]/;

    # check for other non-ASCII character(s)
    complain("non-ASCII") if m/[\x7F-\xFF]/;

    # check for whitespace at EOL
    complain("SPC at EOL") if m/\s\n$/;

    # check for over-long lines,
    # while allowing trailing string literals to go past MAX_LENGTH
    my $len = length($_) - 1; # '- 1' avoids counting trailing \n
    my $hidden_esc_dblquot = $_;
    while($hidden_esc_dblquot =~ s/([^\"]\".*?\\)\"/$1\\/g) {} # TODO check this
    if($len > MAX_LENGTH &&
       !($hidden_esc_dblquot =~ m/^(.*?)\"[^\"]*\"\s*(,|[\)\}]*[,;]?)\s*$/
         && length($1) < MAX_LENGTH)) { # allow over-long trailing string literal with starting col before MAX_LENGTH
        complain("len=$len>".MAX_LENGTH);
    }

    # assign to $count the actual indent of the current line
    m/^(\s*)(.?)(.?)/;
    my $count = length($1) - (m/^\s*$/ ? 1 : 0); # number of leading space characters (except newline), which basically should equal $indent as checked below

    # set up local offsets to required indent
    my $label = 0;
    my $local_offset = 0; # due to line empty or starting with '#' (preprocessor directive) or label or case or default
    my $local_hanging_indent = 0; # due to line starting with '&&' or '||'
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
            $extra_singular_indent = 0;
            $local_offset = $count - $indent;
        }
        if ($hanging_indent == -1) {
            if (m/^(\s*)(case|default)\W/) {
                $local_offset = -INDENT_LEVEL;
            } else {
                if (m/^(\s*)([a-z_0-9]+):/) { #  && $2 ne "default")  # label
                    $label = 1;
                    $local_offset = -INDENT_LEVEL + 1 ;
                }
            }
        } else {
            $local_hanging_indent = INDENT_LEVEL if ($2 eq "&" && $3 eq "&") ||
                                                    ($2 eq "|" && $3 eq "|");  # line starting with && or ||
        }

        # TODO make sure that any '{' and '}' in string literals do not interfere with the following calculations
        m/^([^\{]*)/; # prefix before any opening {
        my $num_initial_closing_braces = $1 =~ tr/\}//;
        $local_offset -= $num_initial_closing_braces * INDENT_LEVEL;

        # sanity-check underflow due to closing braces
        if ($indent + $local_offset < 0) {
            $local_offset = -$indent;
            complain("too many }")
                unless $contents_before =~ m/^\s*#\s*ifdef\s*__cplusplus\s*$/; # ignore closing brace on line after '#ifdef __cplusplus' (used in header files)
        }
    }

    # check indent within multi-line comments
    if($in_multiline_comment) {
        complain("indent=$count!=$comment_indent") if $count != $comment_indent;
    }

    # check indent for other lines except hanging indent
    elsif ($hanging_indent == -1) {
        my $tmp = $contents_before;
        my $parens_balance = $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
        if ($in_multiline_macro == 1 ||
            $in_multiline_macro == 2 && $parens_balance < 0) {
            # first line of macro body, where we we've also matched two-line macro headers
            if ($count == $indent - INDENT_LEVEL) { # macro started with same indentation
                $indent -= INDENT_LEVEL;
                $multiline_macro_no_indent = 1;
            }
        }
        my $allowed = $indent+$extra_singular_indent+$local_offset;
        $allowed = "{1,$allowed}" if $label;
        complain("indent=$count!=$allowed")
            if $count != $indent + $extra_singular_indent + $local_offset &&
               (!$label || $count != 1);
    }

    # check hanging indent (outside multi-line comments)
    else {
        if ($count >=   # actual indent (count) is at least at minimum:
                max($indent + $extra_singular_indent + $local_offset,
                    max($multiline_condition_indent, $multiline_value_indent))
            || m/$\s*ASN1_ITEM_TEMPLATE_END/ && $multiline_value_indent != -1) {
            # reduce hanging indent to adapt to given code. This prefers false negatives over false positives that would occur due to incompleteness of the paren/brace matching
            $hanging_indent     = $count if $count < $hanging_indent;
            $hanging_alt_indent = $count if $count < $hanging_alt_indent;
        }

        my $allowed = "$hanging_indent";
        if ($hanging_alt_indent != $hanging_indent || $local_hanging_indent != 0) {
            $allowed = "{$hanging_indent";
            $allowed .= ",".($hanging_indent+$local_hanging_indent) if $local_hanging_indent != 0;
            if ($hanging_alt_indent != $hanging_indent) {
                $allowed .= ",$hanging_alt_indent";
                $allowed .= ",".($hanging_alt_indent+$local_hanging_indent) if $local_hanging_indent != 0;
            }
            $allowed .= "}";
        }
        complain("indent=$count!=$allowed")
            if $count != $hanging_indent &&
               $count != $hanging_indent + $local_hanging_indent &&
               $count != $hanging_alt_indent &&
               $count != $hanging_alt_indent + $local_hanging_indent;
    }

    if(!$in_multiline_comment) {
        # adapt indent for following lines according to braces
        my $tmp = $_; my $brace_balance = ($tmp =~ tr/\{//) - $tmp =~ tr/\}//;
        $indent += $brace_balance * INDENT_LEVEL;
        $hanging_indent += $brace_balance * INDENT_LEVEL if  $multiline_value_indent != -1;

        # sanity-check underflow due to closing braces
        if ($indent < 0) {
            $indent = 0;
            # complain("too many }"); # already reported above
        }

        # a rough check to determine whether inside enum
        $in_enum += 1 if m/\Wenum\s*\{[^\}]*$/;
        $in_enum += $brace_balance if $brace_balance < 0;
        $in_enum = 0 if $in_enum < 0;
    }

    # detect end comment, must be within multi-line comment, check if it is preceded by non-space text
    if (m/^(.*?)\*\/(.*)$/) { # ending comment: '*/'
        my $head = $1;
        my $tail = $2;
        if (!($head =~ m/\/\*/)) { # starting comment '/*' is handled below
            complain("*/ outside comment") if $in_multiline_comment == 0;
            complain("... */") if $head =~ m/\S/;
            $_ = $tail;
            $in_multiline_comment = 0;
        }
    }

    # detect start of multi-line comment, check if it is followed by non-space text
  MATCH_COMMENT:
    if (m/^(.*?)\/\*-?(.*)$/) { # starting comment: '/*'
        my $head = $1;
        my $tail = $2;
        if ($tail =~ m/\*\/(.*)$/) { # strip contents up to comment end: */
            $_ = "$head $1\n";
            goto MATCH_COMMENT;
        } else {
            complain("/* inside comment") if $in_multiline_comment == 1;
            complain("/* ...") if $tail =~ m/\S/;
            $comment_indent = length($head) + 1;
            $in_multiline_comment = 1;
        }
    }

    # for lines not inside multi-line comments
    if(!$in_multiline_comment) {

        # handle last opening brace in line
        if (m/^(.*?)\{[^\}]*$/) { # match ... {
            my $head = $1;
            my $before = $head =~ m/^\s*$/ ? $contents_before : $head;
            if (!($before =~ m/^\s*(typedef|struct|union)/) && # not type decl
                !($before =~ m/=\s*$/)) { # no directly preceded by '=' (assignment)
                if ($in_multiline_macro == 0 && $indent == INDENT_LEVEL) { # $indent has already been incremented, so this essentially checks for 0 (outermost level) 
                    # we assume end of function definition header, check if { is at end of line (rather than on next line)
                    complain("{ at EOL") if $head =~ m/\S/; # non-whitespace before {
                } else {
                    $line_opening_brace = $line;
                }
            }
        }

        # detect first closing brace in line, check if it closes a block containing a single line/statement
        if(m/^([^\}]*)\}/) { # first }
            my $head = $1;
            my $line_before = $line - 1;
            if($line_opening_brace != 0 &&
               $line_opening_brace == $line_before - 1) {
                print "$ARGV:$line_before:{1 line}:$contents_before" if !($contents_before2 =~ m/typedef|struct|union|static|void/); # including poor matching of function header decl
                # TODO do not complain about cases where there is another if .. else branch with a block containg more than one line
            }
            $line_opening_brace = 0;
        }

        # detect multi-line if/for/while condition (with ) and extra indent for one statement after if/else/for/do/while not followed by brace
        if($hanging_indent == -1) {
            $hanging_open_parens = 0;
            $hanging_open_braces = 0;

            $multiline_condition_indent = $multiline_value_indent = -1;
            if (m/^\s*(if|(\}\s*)?else(\s*if)?|for|do|while)(\W.*)$/) {
                my ($head, $tail) = ($1, $4);
                if (!($tail =~ m/\{\s*$/)) { # no trailing '{'
                    my $tmp = $_;
                    my $parens_balance = $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
                    complain("too many )") if $parens_balance < 0;
                    if (m/^(\s*((\}\s*)?(else\s*)?if|for|while)\s*\(?)/ && $parens_balance > 0) {
                        $multiline_condition_indent = length($1);
                    } else {
                        $extra_singular_indent += INDENT_LEVEL;
                    }
                }
            }
        }

        # adapt hanging_indent, hanging_alt_indent and the auxiliary hanging_open_parens and hanging_open_braces
        # potentially reduce extra_singular_indent
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
            $hanging_indent = $hanging_alt_indent = length($head) + 1;
            my $tmp = $_;
            $hanging_open_parens += $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
        }
        elsif (m/^(.*)\{(\s*[^\s\{][^\{]*\s*)$/) { # last '{' followed by non-space: struct initializer
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\}(.*)/) { # strip contents up to matching '}'
                $_ = "$head $1\n";
                goto MATCH_PAREN;
            }
            $hanging_indent = $hanging_alt_indent = length($head) + 1;
            my $tmp = $_;
            $hanging_open_braces += $tmp =~ tr/\{// - $tmp =~ tr/\}//; # count balance of opening - closing braces
        } elsif ($hanging_indent != -1) {
            my $tmp = $_;
            $hanging_open_parens += $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
            $hanging_open_braces += $tmp =~ tr/\{// - $tmp =~ tr/\}//; # count balance of opening - closing braces

            my $trailing_opening_brace = m/\{\s*$/;
            my $trailing_terminator = $in_enum > 0 ? m/,\s*$/ : m/;\s*$/;
            my $hanging_end = $multiline_condition_indent != -1
                ? ($hanging_open_parens == 0 &&
                   ($hanging_open_braces == 0 || ($hanging_open_braces == 1 && $trailing_opening_brace))) # this checks for end of multi-line condition
                : ($hanging_open_parens == 0 && $hanging_open_braces == 0 &&
                   ($multiline_value_indent == -1 || $trailing_terminator)); # assignment and return are terminated by ';' (but in enum by ','), otherwise we assume function header
            if ($hanging_end) {
                # reset hanging indents
                $hanging_indent = -1;
                if ($multiline_condition_indent != -1 && !$trailing_opening_brace) {
                    $extra_singular_indent += INDENT_LEVEL;
                }
                $multiline_condition_indent = -1;
                $multiline_value_indent = -1;
            }
        }

        if ($hanging_indent == -1) {
            # reset extra_singular_indent on trailing ';'
            $extra_singular_indent = 0 if m/;\s*$/; # trailing ';'

            # set hanging_indent and hanging_indent in case of multi-line (RHS of assignment or return) value
            # at this point, matching (...) have been stripped, simplifying type decl matching
            if ($in_enum > 0 ? m/^(\s*)((((\w+|->|[\.\[\]\*])\s*)+=|return)\s*)([^,\{]*)\s*$/
                             : m/^(\s*)((((\w+|->|[\.\[\]\*])\s*)+=|return)\s*)([^;\{]*)\s*$/
                ) { # multi-line value: "[type] var = " or return without ;
                my $head = $1;
                my $var_eq = $2;
                my $trail = $6;
                $multiline_value_indent =
                    $hanging_indent = $hanging_alt_indent = length($head) + INDENT_LEVEL;
                $hanging_alt_indent = length($head) + length($var_eq) if $trail =~ m/\S/; # non-space after '=' or 'return'
            }
            # TODO add check for empty line after local variable decls
        }

        # detect start and end of multi-line macro, potentially adapting indent
        if ($contents =~ m/^(.*?)\s*\\\s*$/) { # trailing '\' typically used in macro declarations
            if ($in_multiline_macro == 0) {
                $multiline_macro_no_indent = 0;
                $indent += INDENT_LEVEL ;
            }
            $in_multiline_macro += 1;
        } else {
            $indent -= INDENT_LEVEL if $in_multiline_macro && !$multiline_macro_no_indent;
            $in_multiline_macro = 0;
        }

        $contents_before2 = $contents_before;
        $contents_before = $contents;
    }

    if(eof) {
        # sanity-check balance of braces and final indent at end of file
        print "$ARGV:EOF:unbalanced nesting of {..}, indentation off by $indent" if $indent != 0;
        reset_file_state();
    }
}
