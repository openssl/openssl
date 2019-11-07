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
my $contents_before;       # contents of last line (except multi-line string literals and comments), used only if $line > 1
my $contents_before2;      # contents of but-last line (except multi-line string literals and comments), used only if $line > 2
my $multiline_string;      # accumulator for lines containing multi-line string
my $count;                 # number of leading whitespace characters (except newline) in current line, which basically should equal $indent
my $label;                 # current line contains label
my $local_offset;          # current line extra indent offset due to line empty or starting with '#' (preprocessor directive) or label or case or default
my $local_hanging_indent;  # current line allowed extra indent due to line starting with '&&' or '||'
my $line_opening_brace;    # number of last line with opening brace
my $indent;                # currently required indent
my $hanging_indent;        # currently hanging indent, else -1
my $hanging_open_parens;   # used only if $hanging_indent != -1
my $hanging_open_braces;   # used only if $hanging_indent != -1
my $hanging_alt_indent;    # alternative hanging indent (for assignments), used only if $hanging_indent != -1
my $extra_singular_indent; # extra indent for just one statement
my $multiline_condition_indent; # special indent after if/for/while
my $multiline_value_indent;# special indent at LHS of assignment or after return or typedef
my $in_enum;               # used to determine terminator of assignment
my $in_multiline_macro;    # number of lines so far within multi-line macro
my $multiline_macro_no_indent; # workaround for macro body without extra indent
my $in_multiline_comment;  # number of lines so far within multi-line comment
my $multiline_comment_indent; # used only if $in_multiline_comment > 0

sub reset_file_state {
    $indent = 0;
    $line = 0;
    undef $multiline_string;
    $line_opening_brace = 0;
    $hanging_indent = -1;
    $extra_singular_indent = 0;
    $multiline_condition_indent = $multiline_value_indent = -1;
    $in_enum = 0;
    $in_multiline_macro = 0;
    $in_multiline_comment = 0;
}

sub complain_contents {
    my $msg = shift;
    my $contents = shift;
    print "$ARGV:$line:$msg$contents";
}

sub complain {
    my $msg = shift;
    complain_contents($msg, ": $contents");
}

sub check_indent { # for lines outside multi-line comments and string literals
    if ($hanging_indent == -1) {
        my $allowed = $indent+$extra_singular_indent+$local_offset;
        $allowed = "{1,$allowed}" if $label;
        complain("indent=$count!=$allowed")
            if $count != $indent + $extra_singular_indent + $local_offset &&
               (!$label || $count != 1);
    }
    else {
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

    # assign to $count the actual indentation level of the current line
    chomp; # remove tailing \n
    m/^(\s*)/;
    $count = length $1;
    $label = 0;
    $local_offset = 0;
    $local_hanging_indent = 0;

    # check indent within multi-line comments
    if($in_multiline_comment > 0) {
        complain("indent=$count!=$multiline_comment_indent") if $count != $multiline_comment_indent;
        $in_multiline_comment++;
    }

    # detect end of comment, must be within multi-line comment, check if it is preceded by non-whitespace text
    if (m/^(.*?)\*\/(.*)$/) { # ending comment: '*/' - TODO ignore '*/' inside string literal
        my $head = $1;
        my $tail = $2;
        if (!($head =~ m/\/\*/)) { # starting comment '/*' is handled below
            complain("*/ outside comment") if $in_multiline_comment == 0;
            complain("... */") if $head =~ m/\S/;
            $_ = ($head =~ tr/ / /cr)."  $tail"; # blind comment text, retaining length
            $in_multiline_comment = 0;
            goto LINE_FINISHED if m/^\s*$/; # ignore any resulting all-whitespace line
        }
    }

    # detect start of multi-line comment, check if it is followed by non-space text
  MATCH_COMMENT:
    if (m/^(.*?)\/\*(-?)(.*)$/) { # starting comment: '/*' - TODO ignore '/*' inside string literal
        my $head = $1;
        my $opt_minus = $2;
        my $tail = $3;
        if ($tail =~ m/^(.*?)\*\/(.*)$/) { # comment end: */ on same line - TODO ignore '*/' inside string literal
            $_ = "$head  $opt_minus".($1 =~ tr/ / /cr)."  $2"; # blind comment text, retaining length
            goto LINE_FINISHED if m/^\s*$/; # ignore any resulting all-whitespace line
            goto MATCH_COMMENT;
        } else {
            complain("/* inside comment") if $in_multiline_comment == 1;
            complain("/* ...") if $tail =~ m/\S/;
            $multiline_comment_indent = length($head) + 1; # adopt actual indentation of first comment line
            $_ = "$head  ".($opt_minus =~ tr/ / /cr).($tail =~ tr/ / /cr); # blind comment text, retaining length
            $in_multiline_comment = 1;
            if (m/^\s*$/) { # all-whitespace line
                check_indent();
                goto LINE_FINISHED; # ignore all-whitespace line
            }
        }
    }

    $_ = "$1 $2" if m/^(\s*extern\s*"C"\s*)\{(\s*)$/; # ignore opening brace in 'extern "C" {' (used with '#ifdef __cplusplus' in header files)
    s/\\"/\\\\/g; # blind all '\"' (typically whithin string literals) to '\\'
    s#^([^"]*")([^"]*)(")#$1.($2 =~ tr/ / /cr).$3#eg; # blind contents of string literals; multi-line string literals are handled below

    # check for over-long lines,
    # while allowing trailing (also multi-line) string literals to go past MAX_LENGTH
    my $len = length; # total line length (without trailing \n)
    if($len > MAX_LENGTH &&
       !(m/^(.*?)"[^"]*("|\\)\s*(,|[\)\}]*[,;]?)\s*$/
         && length($1) < MAX_LENGTH)) { # allow over-long trailing string literal with starting col before MAX_LENGTH
        complain("len=$len>".MAX_LENGTH);
    }

    # handle multi-line string literals
    # this is not done for other uses of trailing '\' in order to be able to check layout of macro declarations
    if (defined $multiline_string) {
        $_ = $multiline_string.$_;
        undef $multiline_string;
        m/^(\s*)/;
        $count = length $1; # re-calculate count, like done above
    }
    if (m/^(([^"]*"[^"]*")*[^"]*"[^"]*)\\\s*$/) { # trailing '\' in last string literal
        $multiline_string = $1;
        goto LINE_FINISHED;
    }

    # set up local offsets to required indent
    if ($in_multiline_comment <= 1) {
        if (m/^(.*?)\s*\\\s*$/) { # trailing '\' typically used in macro declarations; multi-line string literals have already been handled
            $_ = $1; # remove it along with any preceding whitespace
        }
        if (m/^$/ || # empty line
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
            $local_hanging_indent = INDENT_LEVEL if m/^\s*(\&\&|\|\|)/;  # line starting with && or ||
        }

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

    if ($in_multiline_comment <= 1) {

        # adapatations of indent for first line of macro body
        my $tmp = $contents_before;
        my $parens_balance = $tmp =~ tr/\(// - $tmp =~ tr/\)//; # count balance of opening - closing parens
        if ($in_multiline_macro == 1 ||
            $in_multiline_macro == 2 && $parens_balance < 0) { # also match two-line macro headers
            if ($count == $indent - INDENT_LEVEL) { # macro started with same indentation
                $indent -= INDENT_LEVEL;
                $multiline_macro_no_indent = 1;
            }
        }

        # potentially reduce hanging indent to adapt to given code. This prefers false negatives over false positives that would occur due to incompleteness of the paren/brace matching
        if ($hanging_indent != -1 && $count >= # actual indent (count) is at least at minimum:
                max($indent + $extra_singular_indent + $local_offset,
                    max($multiline_condition_indent, $multiline_value_indent))
            || m/$\s*ASN1_ITEM_TEMPLATE_END/ && $multiline_value_indent != -1) {
            $hanging_indent     = $count if $count < $hanging_indent;
            $hanging_alt_indent = $count if $count < $hanging_alt_indent;
        }

        check_indent();

        # adapt indent for following lines according to braces
        my $tmp = $_; my $brace_balance = ($tmp =~ tr/\{//) - $tmp =~ tr/\}//;
        $indent += $brace_balance * INDENT_LEVEL;
        $hanging_indent += $brace_balance * INDENT_LEVEL if $multiline_value_indent != -1;

        # sanity-check underflow due to closing braces
        if ($indent < 0) {
            $indent = 0;
            # complain("too many }"); # already reported above
        }

        # a rough check to determine whether inside enum
        $in_enum += 1 if m/\Wenum\s*\{[^\}]*$/;
        $in_enum += $brace_balance if $brace_balance < 0;
        $in_enum = 0 if $in_enum < 0;

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
            if($line_opening_brace != 0 &&
               $line_opening_brace == $line - 2) {
                $line--;
                complain_contents("{1 line}", ": $contents_before") if !($contents_before2 =~ m/typedef|struct|union|static|void/); # including poor matching of function header decl
                # TODO do not complain about cases where there is another if .. else branch with a block containg more than one line
                $line++;
            }
            $line_opening_brace = 0;
        }

        # detect multi-line if/for/while condition (with ) and extra indent for one statement after if/else/for/do/while not followed by brace
        if($hanging_indent == -1) {
            $hanging_open_parens = 0;
            $hanging_open_braces = 0;

            $multiline_condition_indent = $multiline_value_indent = -1;
            if (m/^\s*(if|(\}\s*)?else(\s*if)?|for|do|while)((\W|$).*)$/) {
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
        # TODO the following assignments to $hanging_indent are just heuristics - nested closing parens and braces are not treated fully
        if (m/^(.*)\(([^\(]*)$/) { # last '('
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\)(.*)/) { # strip contents up to matching ')':
                $_ = "$head $1";
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
                $_ = "$head $1";
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
                   ($multiline_value_indent == -1 || $trailing_terminator)); # assignment, return, and typedef are terminated by ';' (but in enum by ','), otherwise we assume function header
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
        }

        # set multiline_value_indent and potentially set hanging_indent and hanging_indent in case of multi-line value or typedef expression
        # at this point, matching (...) have been stripped, simplifying type decl matching
        my $terminator = $in_enum > 0 ? "," : ";";
        if (m/^(\s*)((((\w+|->|[\.\[\]\*])\s*)+=|return|typedef)\s*)([^$terminator\{]*)\s*$/) { # multi-line value: "[type] var = " or return or typedef without ; or ,
            my $head = $1;
            my $var_eq = $2;
            my $trail = $6;
            $multiline_value_indent = length($head) + INDENT_LEVEL;
            if ($hanging_indent == -1) {
                $hanging_indent = $hanging_alt_indent = $multiline_value_indent;
                $hanging_alt_indent = length($head) + length($var_eq) if $trail =~ m/\S/; # non-space after '=' or 'return' or 'typedef'
            }
        }

        # TODO complain on missing empty line after local variable decls

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

  LINE_FINISHED:
    if(eof) {
        # check for all-whitespace line just before EOF
        complain("whitespace line before EOF") if $contents =~ m/^\s*$/;

        # sanity-check balance of braces and final indent at end of file
        $line = "EOF";
        complain_contents("indentation off by $indent, likely due to unbalanced nesting of {..}", "\n") if $indent != 0;
        reset_file_state();
    }
}
