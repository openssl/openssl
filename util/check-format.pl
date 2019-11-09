#!/usr/bin/perl
#
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# check-format.pl
# - check formatting of C source according to OpenSSL coding style
#
# usage:
#   check-format.pl [-l|--sloppy-len] [-e|--sloppy-expr] <files>
#
# checks adherence to the formatting rules of the OpenSSL coding guidelines.
# This pragmatic tool is incomplete and yields some false positives.
# Still it should be useful for detecting most typical glitches.

use strict;
use List::Util qw[min max];
use POSIX;

use constant INDENT_LEVEL => 4;
use constant MAX_LENGTH => 80;

# command-line options
my $max_length = MAX_LENGTH;
my $sloppy_expr = 0;

while($ARGV[0] =~ m/^-(\w|-[\w\-]+)$/) {
    my $arg = $1; shift;
    if($arg =~ m/^(l|-sloppy-len)$/) {
        $max_length += INDENT_LEVEL;
    }
    elsif($arg =~ m/^(e|-sloppy-expr)$/) {
        $sloppy_expr = 1;
    } else {
        die("unknown option: $arg");
    }
}

my $line;                  # current line number
my $contents;              # contens of current line
my $contents_before;       # contents of previous line (except multi-line string literals and comments), used only if $line > 1
my $contents_before2;      # contents of line before previous line (except multi-line string literals and comments), used only if $line > 2
my $multiline_string;      # accumulator for lines containing multi-line string
my $count;                 # number of leading whitespace characters (except newline) in current line, which basically should equal $indent
my $count_before;          # number of leading whitespace characters (except newline) in previous line
my $label;                 # current line contains label
my $local_offset;          # current line extra indent offset due to label or switch case/default or leading closing braces
my $local_hanging_indent;  # current line allowed extra indent due to line starting with '&&' or '||'
my $line_opening_brace;    # number of previous line with opening brace
my $indent;                # currently required indentation for normal code
my $directive_indent;      # currently required indentation for preprocessor directives
my $ifdef__cplusplus;      # line before contained '#ifdef __cplusplus' (used in header files)
my $hanging_indent;        # currently hanging indent, else 0
my $hanging_open_parens;   # used only if $hanging_indent != 0
my $hanging_open_braces;   # used only if $hanging_indent != 0
my $hanging_alt_indent;    # alternative hanging indent (for assignments), used only if $hanging_indent != 0
my $extra_singular_indent; # extra indent for just one statement
my $multiline_condition_indent; # special indent after if/for/while
my $multiline_value_indent;# special indent at LHS of assignment or after return or typedef
my $in_enum;               # used to determine terminator of assignment
my $in_multiline_directive; # number of lines so far within multi-line preprocessor directive, e.g., macro definition
my $multiline_macro_same_indent; # workaround for multiline macro body without extra indent
my $in_multiline_comment;  # number of lines so far within multi-line comment
my $multiline_comment_indent; # used only if $in_multiline_comment > 0

sub reset_file_state {
    $indent = 0;
    $directive_indent = 0;
    $ifdef__cplusplus = 0;
    $line = 0;
    undef $multiline_string;
    $line_opening_brace = 0;
    $hanging_indent = 0;
    $extra_singular_indent = 0;
    $multiline_condition_indent = $multiline_value_indent = 0;
    $in_enum = 0;
    $in_multiline_directive = 0;
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

sub parens_balance { # count balance of opening parentheses - closing parentheses
    my $str = shift;
    return $str =~ tr/\(// - $str =~ tr/\)//;
}

sub braces_balance { # count balance of opening braces - closing braces
    my $str = shift;
    return $str =~ tr/\{// - $str =~ tr/\}//;
}

sub check_indent { # for lines outside multi-line comments and string literals
    if ($hanging_indent == 0) {
        my $allowed = $indent+$extra_singular_indent+$local_offset;
        $allowed = "{1,$allowed}" if $label;
        complain("indent=$count!=$allowed")
            if $count != $indent + $extra_singular_indent + $local_offset &&
               (!$label || $count != 1);
    }
    else {
        if ($sloppy_expr) {
            return if $count == $count_before; # workaround in particular for struct initializers in *_err.c files
            return if substr($contents, $count, 1) eq ":" &&
                substr($contents_before, $count, 1) eq "?"; # in conditional expression, leading character is ":" with same position as "?" in line before
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
}

reset_file_state();
while(<>) { # loop over all lines of all input files
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
    if (m/^(.*?)\*\/(.*)$/ && $1 ne '/') { # ending comment: '*/' - TODO ignore '*/' inside string literal
        my $head = $1;
        my $tail = $2;
        if (!($head =~ m/\/\*/)) { # starting comment '/*' is handled below
            complain("*/ outside comment") if $in_multiline_comment == 0;
            complain("... */") if $head =~ m/\S/; # head contains non-whitespace
            $_ = ($head =~ tr/ / /cr)."  $tail"; # blind comment text, retaining length
            $in_multiline_comment = 0;
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
            complain("/* inside intra-line comment") if $1 =~ /\/\*/;
            goto MATCH_COMMENT;
        } else {
            if ($in_multiline_comment > 0) {
                complain("/* inside multi-line comment") ;
            } else {
                complain("/* ...") unless $tail =~ m/^\s*\\?\s*$/; # tail not essentially empty
            }
            $multiline_comment_indent = length($head) + 1 if $in_multiline_comment == 0; # adopt actual indentation of first comment line
            $_ = "$head  ".($opt_minus =~ tr/ / /cr).($tail =~ tr/ / /cr); # blind comment text, retaining length
            $in_multiline_comment++;
        }
    }

    # handle special case of line after '#ifdef __cplusplus' (which typically appears in header files)
    if ($ifdef__cplusplus) {
        $ifdef__cplusplus = 0;
        $_ = "$1 $2" if m/^(\s*extern\s*"C"\s*)\{(\s*)$/; # ignore opening brace in 'extern "C" {'
        goto LINE_FINISHED if m/^\s*\}\s*$/; # ignore closing brace
    }

    # blind contents of string literals; multi-line string literals are handled below

    s/\\"/\\\\/g; # blind all '\"' (typically whithin string literals) to '\\'
    s#^([^"]*")([^"]*)(")#$1.($2 =~ tr/ / /cr).$3#eg;

    # check for over-long lines,
    # while allowing trailing (also multi-line) string literals to go past $max_length
    my $len = length; # total line length (without trailing \n)
    if($len > $max_length &&
       !(m/^(.*?)"[^"]*("|\\)\s*(,|[\)\}]*[,;]?)\s*$/
         && length($1) < $max_length)) { # allow over-long trailing string literal with starting col before $max_length
        complain("len=$len>$max_length");
    }

    goto LINE_FINISHED if m/^\s*\\?\s*$/; # essentially empty line (just whitespace except potentially a single backslash)

    # handle preprocessor directives
    if (m/^\s*#(\s*)(\w+)/) { # line starting with '#'
        my $directive_count = length $1; # maybe could also use indentation before '#'
        my $directive = $2;
        complain("indent=$count!=0") if $count != 0;
        $directive_indent-- if $directive =~ m/^else|elsif|endif$/;
        if ($directive_indent < 0) {
            $directive_indent = 0;
            complain("unexpected #$directive");
        }
        complain("#indent=$directive_count!=$directive_indent")
                     if $directive_count != $directive_indent;
        $directive_indent++ if $directive =~ m/^if|ifdef|ifndef|else|elsif$/;
        $ifdef__cplusplus = m/^\s*#\s*ifdef\s+__cplusplus\s*$/;
        goto HANDLE_DIRECTIVE unless $directive =~ m/^define$/; # skip normal code line handling except for #define
        # TODO improve current mix of handling indents for normal C code and preprocessor directives
    }

    # handle multi-line string literals
    # this is not done for other uses of trailing '\' in order to be able to check layout of multi-line preprocessor directives
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

    goto LINE_FINISHED if $in_multiline_comment > 1;

    # set up local offsets to required indent
    if (m/^(.*?)\s*\\\s*$/) { # trailing '\' typically used in multi-line preprocessor directives such as macro definitions; multi-line string literals have already been handled
        $_ = $1; # strip it along with any preceding whitespace such that it does not interfere with various matching done below
    }
    if ($hanging_indent == 0) {
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

    # adapt required indent due to leading closing braces, potentially followed by terminator ';'
    m/^((\s*\})*)(\s*;)?/; # get prefix of } before any other text, plus any ;
    my $num_leading_closing_braces = $1 =~ tr/\}//;
    my $terminated = $3 ne "";
    if ($multiline_value_indent && $terminated) { # ';' after assignment etc.
        $local_offset -= $num_leading_closing_braces * INDENT_LEVEL;
        $local_offset = 0 if $hanging_indent > $indent; # workaround for structure assignment with extra indent on opening brace; TODO check
        $hanging_indent = 0; # reset hanging indents
    }
    elsif ($num_leading_closing_braces != 0) {
        $hanging_indent = 0; # reset any hanging indents; TODO check
        $local_offset -= $num_leading_closing_braces * INDENT_LEVEL;
    }
    # sanity-check underflow due to closing braces
    if ($indent + $local_offset < 0) {
        $local_offset = -$indent;
        complain("too many }");
    }
    $hanging_indent = 0 if m/$\s*ASN1_ITEM_TEMPLATE_END/; # reset hanging indent also on ASN1_ITEM_TEMPLATE_END

    # potential adaptations of indent in first line of macro body in multi-line macro definition
    my $more_lines = parens_balance($contents_before) < 0; # then match two-line macro headers - TODO improve to handle also more header lines
    if (($more_lines ? $contents_before2 : $contents_before) =~ m/^\s*#\s*define(\W|$)/ &&
        $in_multiline_directive == 1 + $more_lines) {
        if ($count == $indent - INDENT_LEVEL) { # macro body actually started with same indentation as preceding code
            $indent -= INDENT_LEVEL;
            $multiline_macro_same_indent = 1;
        }
    }

    if ($sloppy_expr) {
        # potentially reduce hanging indent to adapt to given code. This prefers false negatives over false positives that would occur due to incompleteness of the paren/brace matching
        if ($hanging_indent != 0 && $count >= # actual indent (count) is at least at minimum:
                max($indent + $extra_singular_indent + $local_offset,
                    max($multiline_condition_indent, $multiline_value_indent))
           ) {
            $hanging_indent     = $count if $count < $hanging_indent;
            $hanging_alt_indent = $count if $count < $hanging_alt_indent;
        }
    }

    check_indent() unless $contents =~ m/^\s*#\s*define(\W|$)/; # indent of #define has been handled above

    my $outermost_level =
         $indent == 0 ||
        ($indent == INDENT_LEVEL && $in_multiline_directive > 0 &&
                                    !$multiline_macro_same_indent);

    # handle last opening brace in line
    if (m/^(.*?)\{([^\{]*)$/) { # match ... {
        my $head = $1;
        my $tail = $2;
        my $before = $head =~ m/^\s*$/ ? $contents_before : $head;
        if ($multiline_value_indent == 0 &&
            !($before =~ m/=\s*$/)) { # not directly preceded by '=' (assignment)
            if (!($before =~ m/^\s*(typedef|struct|union)/)) { # not type decl
                if ($outermost_level) { # we assume end of function definition header
                    # check if { is at end of line (rather than on next line)
                    complain("{ at EOL") if $head =~ m/\S/; # non-whitespace before {
                } else {
                    $line_opening_brace = $line;
                }
            }
            complain("{ ...") if $tail=~ m/\S/; # non-whitespace after last {
        }
    }

    # check for code block containing a single line/statement
    if(!$outermost_level && m/^([^\}]*)\}/) { # first closing brace } in line
        my $head = $1;
        # TODO extend detection from single-line to potentially multi-line statement
        if($head =~ m/^\s*$/ &&
           $line_opening_brace != 0 &&
           $line_opening_brace == $line - 2) {
            $line--;
            complain_contents("{1 line}", ": $contents_before")
                if !($contents_before2 =~ m/typedef|struct|union|enum/); # exclude type decl
            # TODO do not complain about cases where there is another if .. else branch with a block containg more than one statement
            $line++;
        }
        $line_opening_brace = 0;
    }

    # adapt indent for following lines according to braces
    my $braces_balance = braces_balance($_);
    $indent += $braces_balance * INDENT_LEVEL;
    $hanging_indent += $braces_balance * INDENT_LEVEL if $hanging_indent != 0 && $multiline_value_indent != 0;

    # sanity-check underflow due to closing braces
    if ($indent < 0) {
        $indent = 0;
        # complain("too many }"); # already reported above
    }

    # a rough check to determine whether inside enum
    $in_enum += 1 if m/(^|\W)enum\s*\{[^\}]*$/;
    $in_enum += $braces_balance if $braces_balance < 0;
    $in_enum = 0 if $in_enum < 0;

    # detect multi-line if/for/while condition (with ) and extra indent for one statement after if/else/for/do/while not followed by brace
    if($hanging_indent == 0) {
        $hanging_open_parens = 0;
        $hanging_open_braces = 0;

        $multiline_condition_indent = $multiline_value_indent = 0;
        if (m/^\s*(if|(\}\s*)?else(\s*if)?|for|do|while)((\W|$).*)$/) {
            my ($head, $tail) = ($1, $4);
            my $parens_balance = parens_balance($_);
            complain("too many )") if $parens_balance < 0;
            if (!($tail =~ m/\{\s*$/)) { # no trailing '{'
                if (m/^(\s*((\}\s*)?(else\s*)?if|for|while)\s*\(?)/ && $parens_balance > 0) {
                    $multiline_condition_indent = length($1);
                } else {
                    $extra_singular_indent += INDENT_LEVEL;
                }
            }
        }
    }

    # adapt hanging_indent and hanging_alt_indent
    if ($sloppy_expr) {
        # the following assignments to $hanging_indent are just heuristics - nested closing parens and braces are not treated fully
        # adapt also the auxiliary hanging_open_parens and hanging_open_braces
        # potentially increase extra_singular_indent
      MATCH_PAREN:
        if (m/^(.*)\(([^\(]*)$/) { # last '('
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\)(.*)/) { # strip contents up to matching ')':
                $_ = "$head $1";
                goto MATCH_PAREN;
            }
            $hanging_indent = $hanging_alt_indent = length($head) + 1;
            $hanging_open_parens += parens_balance($_);
      }
        elsif (m/^(.*)\{(\s*[^\s\{][^\{]*\s*)$/) { # last '{' followed by non-space: struct initializer
            my $head = $1;
            my $tail = $2;
            if ($tail =~ m/\}(.*)/) { # strip contents up to matching '}'
                $_ = "$head $1";
                goto MATCH_PAREN;
            }
            $hanging_indent = $hanging_alt_indent = length($head) + 1;
            $hanging_open_braces += braces_balance($_);
      } elsif ($hanging_indent != 0) {
          $hanging_open_parens += parens_balance($_);
          $hanging_open_braces += braces_balance($_);

          my $trailing_opening_brace = m/\{\s*$/;
          my $trailing_terminator = $in_enum > 0 ? m/,\s*$/ : m/;\s*$/;
          my $hanging_end = $multiline_condition_indent != 0
                ? ($hanging_open_parens == 0 &&
                   ($hanging_open_braces == 0 || ($hanging_open_braces == 1 && $trailing_opening_brace))) # this checks for end of multi-line condition
                : ($hanging_open_parens == 0 && $hanging_open_braces == 0 &&
                   ($multiline_value_indent == 0 || $trailing_terminator)); # assignment, return, and typedef are terminated by ';' (but in enum by ','), otherwise we assume function header
          if ($hanging_end) {
              # reset hanging indents
              $hanging_indent = 0;
              if ($multiline_condition_indent != 0 && !$trailing_opening_brace) {
                  $extra_singular_indent += INDENT_LEVEL;
              }
              $multiline_condition_indent = 0;
              $multiline_value_indent = 0;
          }
        }
    }

    if ($hanging_indent == 0) {
        # reset extra_singular_indent on trailing ';'
        $extra_singular_indent = 0 if m/;\s*$/; # trailing ';'
    }

    # set multiline_value_indent and potentially set hanging_indent and hanging_indent in case of multi-line value or typedef expression
    # at this point, matching (...) have been stripped, simplifying type decl matching
    my $terminator = $in_enum > 0 ? "," : ";";
    if (m/^(\s*)((((\w+|->|[\.\[\]\*])\s*)+=|return|typedef)\s*)([^$terminator]*)\s*$/) { # multi-line value: "[type] var = " or return or typedef without ; or ,
        my $head = $1;
        my $var_eq = $2;
        my $trail = $6;
        $multiline_value_indent = length($head) + INDENT_LEVEL;
        if ($hanging_indent == 0) {
            $hanging_indent = $hanging_alt_indent = $multiline_value_indent;
            $hanging_alt_indent = length($head) + length($var_eq) if $trail =~ m/\S/; # non-space after '=' or 'return' or 'typedef'
        }
    }

    # TODO complain on missing empty line after local variable decls

  HANDLE_DIRECTIVE:
    # on start of multi-line preprocessor directive, adapt indent
    if ($contents =~ # need to use original line contents because trailing \ may have been stripped above
        m/^(.*?)\s*\\\s*$/) { # trailing '\', typically used in macro definitions (or other preprocessor directives)
        if ($in_multiline_directive == 0 && m/^(DEFINE_|\s*#)/) { # not only for #define
            $indent += INDENT_LEVEL ;
            $multiline_macro_same_indent = 0;
        }
        $in_multiline_directive += 1;
    }

    $contents_before2 = $contents_before;
    $contents_before = $contents;
    $count_before = $count;

  LINE_FINISHED:
    # on end of multi-line preprocessor directive, adapt indent
    unless ($contents =~ # need to use original line contents because trailing \ may have been stripped above
            m/^(.*?)\s*\\\s*$/) { # no trailing '\'
        $indent -= INDENT_LEVEL if $in_multiline_directive > 0 && !$multiline_macro_same_indent;
        $in_multiline_directive = 0;
    }

    if(eof) {
        # check for essentially empty line just before EOF
        complain("empty line before EOF") if $contents =~ m/^\s*\\?\s*$/;
        $line = "EOF";

        # sanity-check balance of { .. } via final indent at end of file
        complain_contents(ceil($indent / INDENT_LEVEL)." unclosed {", "\n") if $indent != 0;

        # sanity-check balance of #if .. #endif via final preprocessor directive indent at end of file
        complain_contents("$directive_indent unclosed #if", "\n") if $directive_indent != 0;

        reset_file_state();
    }
}
