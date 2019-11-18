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
#   check-format.pl [-l|--sloppy-len] [-s|--sloppy-space] [-e|--sloppy-expr] <files>
#
# checks adherence to the formatting rules of the OpenSSL coding guidelines.
# This pragmatic tool is incomplete and yields some false positives.
# Still it should be useful for detecting most typical glitches.
#
# options:
#  -l | --sloppy-len   increases accepted max line length from 80 to 84
#  -s | --sloppy-space disables reporting of whitespace nits
#  -e | --sloppy-expr  add grace when checking multi-line expr indentation
#
# There are known false positives in particular when correct detection would
# require look-ahead of lines:
# * The check for the rule that for
#   {
#       single-line statement;
#   }
#   the opening and closing braces should be left out except this is part of an
#   if .. else statement where blocks for other branches contain more than just
#   one single-line statement. The exception is not recognized - and thus false
#   positives are reported - where such blocks occur after the current position.
# * Use of multiple consecutive spaces is regarded a coding style nit except
#   when done in order to align certain columns over multiple lines, e.g.:
#   # define ABC 1
#   # define DE  2
#   # define F   3
#   The tool recognizes this pattern - and consequently does not report the use
#   of double space - if in at least two immediately prededing lines (if any)
#   there is a space followed by non-space charater at the same column position.
#   It does not recognize this pattern while handling the first two such lines.


use strict;
use List::Util qw[min max];
use POSIX;

use constant INDENT_LEVEL => 4;
use constant MAX_LENGTH => 80;

# command-line options
my $max_length = MAX_LENGTH;
my $sloppy_hang = 0;
my $sloppy_spc = 0;

while($ARGV[0] =~ m/^-(\w|-[\w\-]+)$/) {
    my $arg = $1; shift;
    if($arg =~ m/^(l|-sloppy-len)$/) {
        $max_length += INDENT_LEVEL;
    } elsif($arg =~ m/^(s|-sloppy-spc)$/) {
        $sloppy_spc = 1;
    } elsif($arg =~ m/^(h|-sloppy-hang)$/) {
        $sloppy_hang = 1;
    } else {
        die("unknown option: $arg");
    }
}

my $line;                  # current line number
my $contents;              # contens of current line
my $contents_before;       # contents of previous line (except multi-line string literals and comments),
                           # used only if $line > 1
my $contents_before2;      # contents of line before previous line (except multi-line string literals and comments),
                           # used only if $line > 2
my $multiline_string;      # accumulator for lines containing multi-line string
my $count;                 # number of leading whitespace characters (except newline) in current line,
                           # which basically should equal $indent or $hanging_indent, respectively
my $count_before;          # number of leading whitespace characters (except newline) in previous line
my $label;                 # current line contains label
my $local_offset;          # current line extra indent offset due to label or switch case/default or leading closing braces
my $line_opening_brace;    # number of previous line with opening brace outside expression or type declaration
my $indent;                # currently required indentation for normal code
my $directive_indent;      # currently required indentation for preprocessor directives
my $ifdef__cplusplus;      # line before contained '#ifdef __cplusplus' (used in header files)
my $hanging_indent;        # hanging indent within (multi-line) expressions and statements, else 0
my @nested_parens_indents; # stack of hanging indents due to parentheses
my @nested_braces_indents; # stack of hanging indents due to braces within expressions, used only if $in_expr
my @nested_brackets_indents; # stack of hanging indents due to brackets
my @nested_conds_indents;  # stack of hanging indents due to '?' ':'
my $extra_singular_indent; # extra indent for just one (hanging) statement or expression or typedef
my $in_expr;               # in expression (after if/for/while/switch/return/enum/LHS of assignment,
                           # implies use of $hanging_indent
my $in_paren_expr;         # in condition of if/for/while and expr of switch, used only if $hanging_indent != 0,
                           # implies $in_expr
my $in_typedecl;           # nesting level of typedef/struct/union/enum
my $in_multiline_directive; # number of lines so far within multi-line preprocessor directive, e.g., macro definition
my $multiline_macro_same_indent; # workaround for multiline macro body without extra indent
my $in_multiline_comment;  # number of lines so far within multi-line comment
my $multiline_comment_indent; # used only if $in_multiline_comment > 0
my $num_current_complaints = 0; # number of issues found on current line
my $num_complaints = 0;         # total number of issues found
my $num_SPC_complaints = 0;     # total number of whitespace issues found
my $num_indent_complaints = 0;  # total number of indentation issues found

sub complain_contents {
    my $msg = shift;
    my $contents = shift;
    print "$ARGV:$line:$msg$contents";
    $num_current_complaints++;
    $num_complaints++;
    $num_SPC_complaints++ if $msg =~ /SPC/;
    $num_indent_complaints++ if $msg =~ /indent/;
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
    my $normal_indent = my $alt_indent = $indent + $extra_singular_indent + $local_offset;
    if ($hanging_indent == 0) {
        my $allowed = $normal_indent;
        $alt_indent = 1 if $label;
        $allowed = "{$alt_indent,$normal_indent}" if $alt_indent != $normal_indent;
        complain("indent=$count!=$allowed")
            if $count != $normal_indent && $count != $alt_indent;
    }
    else {
        my $alt_indent = $hanging_indent;
        if ($sloppy_hang) {
            # do not report on repeated identical indentation potentially due to same violations
            return if $count == $count_before;

            if ($count >= $indent) { # actual indent is at least at minimum, not taking into account $extra_singular_indent + $local_offset
                # adapt to actual indent if contents have been shifted left to fit within line length limit
                $hanging_indent = $count if $count < $hanging_indent && length($contents) == MAX_LENGTH + length("\n");
            }
            # allow hanging expression etc. indent at normal indentation level, at least INDENT_LEVEL
            $alt_indent = max(INDENT_LEVEL, $normal_indent);
        }
        if(@nested_braces_indents) {
            $alt_indent = $normal_indent; # allow hanging initializer expression indent at normal indentation level
            # adapt hanging initializer expression indent to actual indentation level if it the normal one
            @nested_braces_indents[-1] = $normal_indent if $count == $normal_indent;
        }
        ($alt_indent, $hanging_indent) = ($hanging_indent, $alt_indent) if $alt_indent < $hanging_indent;
        my $optional_offset = m/^\s*(\&\&|\|\|)/ ? INDENT_LEVEL : 0; # line starting with && or ||
        my $allowed = "$hanging_indent";
        if ($alt_indent != $hanging_indent || $optional_offset != 0) {
            $allowed = "{$hanging_indent";
            $allowed .= ",".($hanging_indent + $optional_offset) if $optional_offset != 0;
            if ($alt_indent != $hanging_indent) {
                $allowed .= ",$alt_indent";
                $allowed .= ",".($alt_indent+$optional_offset) if $optional_offset != 0;
            }
            $allowed .= "}";
        }
        complain("hanging indent=$count!=$allowed")
            if $count != $hanging_indent && $count != $hanging_indent + $optional_offset &&
               $count != $alt_indent     && $count != $alt_indent     + $optional_offset;
    }
}

sub update_nested_indents {
    my $str = shift;
    my $start = shift; # defaults to 0
    my $end_in_paren_expr = 0;
    my $terminator_position = -1;
    for(my $i = $start; $i < length($str); $i++) {
        my $c = substr($str, $i, 1);
        $c = ";" if substr($str, $i) =~ m/^\w*ASN1_[A-Z_]+END\w*/; # *ASN1_*END* macros are defined with a leading ';'
        # stop at terminator outside 'for(..;..;..)'
        return ($end_in_paren_expr, $i)        if $c eq ";" && !($in_paren_expr && @nested_parens_indents);

        push(@nested_parens_indents  , $i + 1) if $c eq "(";
        push(@nested_braces_indents  , $i + 1) if $c eq "{" && $in_expr && !$end_in_paren_expr;
        push(@nested_brackets_indents, $i + 1) if $c eq "[";
        push(@nested_conds_indents   , $i    ) if $c eq "?";

        $end_in_paren_expr = 1 if ($c eq ")") && $in_paren_expr && @nested_parens_indents == 1;
        # note that this does not the check correct order of closing symbols
            @nested_parens_indents    ?
        pop(@nested_parens_indents)   : complain("too many )")  if ($c eq ")");
            @nested_braces_indents    ?
        pop(@nested_braces_indents)   :(complain("too many } in expr"),
                                       $hanging_indent += INDENT_LEVEL,
                                       $indent += INDENT_LEVEL) if $c eq "}" && $in_expr && !$end_in_paren_expr;
            @nested_brackets_indents  ?
        pop(@nested_brackets_indents) : complain("too many ]")  if $c eq "]";
            @nested_conds_indents     ?
        pop(@nested_conds_indents)    : complain("too many :")  if $c eq ":" # ignore in following situations:
                # not after initial label/case/default - TODO extend to multi-line expressions after 'case'
                && !($hanging_indent == 0 && substr($str, 0, $i) =~ m/^(\s*)(case\W.*$|\w+$)/)
                # bitfield length within unsigned type decl - TODO improve matching
                && !(!$in_expr && substr($str, $i + 1) =~ m/^\d+/);
    }
    return ($end_in_paren_expr, -1);
}

sub reset_hanging_indents { # reset $hanging_indent and subordinate variables
    my $position = shift;
    complain(+@nested_parens_indents  ." unclosed ( at $position") if @nested_parens_indents;
   (complain(+@nested_braces_indents  ." unclosed { at $position")
   ,$indent -= INDENT_LEVEL)                                       if @nested_braces_indents;
    complain(+@nested_brackets_indents." unclosed [ at $position") if @nested_brackets_indents;
    complain(+@nested_conds_indents   ." unclosed ? at $position") if @nested_conds_indents;
    @nested_parens_indents = @nested_braces_indents =
        @nested_brackets_indents = @nested_conds_indents = ();

    $hanging_indent = 0;
    $in_paren_expr = 0;
    $in_expr = 0;
}

sub reset_file_state {
    reset_hanging_indents("EOF");
    $extra_singular_indent = 0;
    $indent = 0;
    $directive_indent = 0;
    $ifdef__cplusplus = 0;
    $line = 0;
    undef $multiline_string;
    $line_opening_brace = 0;
    $in_typedecl = 0;
    $in_multiline_directive = 0;
    $in_multiline_comment = 0;
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
    complain("non-printable at ".(length $1)) if m/(.*?)[\x00-\x08\x0B-\x0C\x0E-\x1F]/;

    # check for other non-ASCII character(s)
    complain("non-ASCII '$1'") if m/([\x7F-\xFF])/;

    # check for whitespace at EOL
    complain("SPC at EOL") if m/\s\n$/;

    # assign to $count the actual indentation level of the current line
    chomp; # remove tailing \n
    m/^(\s*)/;
    $count = length $1;
    $label = 0;
    $local_offset = 0;

    # comments and character/string literals @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    # check indent within multi-line comments
    if($in_multiline_comment > 0) {
        complain("indent=$count!=$multiline_comment_indent") if $count != $multiline_comment_indent;
        $in_multiline_comment++;
    }

    # detect end of comment, must be within multi-line comment, check if it is preceded by non-whitespace text
    if (m/^(.*?)\*\/(.*)$/ && $1 ne '/') { # ending comment: '*/' - TODO ignore '*/' inside string literal
        my ($head, $tail) = ($1, $2);
        if (!($head =~ m/\/\*/)) { # starting comment '/*' is handled below
            complain("*/ outside comment") if $in_multiline_comment == 0;
            complain("... */") if $head =~ m/\S/; # head contains non-whitespace
            $_ = ($head =~ tr/ /@/cr)."  $tail"; # blind comment text, preserving length
            $in_multiline_comment = 0;
            goto LINE_FINISHED if $tail =~ m/^\s*$/; # ignore rest if just whitespace
        }
    }

    # detect start of multi-line comment, check if it is followed by non-space text
  MATCH_COMMENT:
    if (m/^(.*?)\/\*(-?)(.*)$/) { # starting comment: '/*' - TODO ignore '/*' inside string literal
        my ($head, $opt_minus, $tail) = ($1, $2, $3);
        if ($tail =~ m/^(.*?)\*\/(.*)$/) { # comment end: */ on same line - TODO ignore '*/' inside string literal
            complain("/* inside intra-line comment") if $1 =~ /\/\*/;
            # blind comment text, preserving length
            my ($comment_text, $rest) = ("$opt_minus$1", $2);
            complain("/*dbl SPC*/") if !$sloppy_spc && $comment_text =~ m/(^|[^.])\s\s\S/;
            $_ = $head.($rest =~ m/^\s*$/ # trailing commment
                        ? "  ".($comment_text =~ tr/ / /cr)."  " # blind trailing commment as space
                        : "@@".($comment_text =~ tr/ /@/cr)."@@" # blind intra-line comment as @
                        ).$rest;
            goto MATCH_COMMENT;
        } else {
            if ($in_multiline_comment > 0) {
                complain("/* inside multi-line comment") ;
            } else {
                complain("/* ...") unless $tail =~ m/^\s*\\?\s*$/; # tail not essentially empty
            }
            # adopt actual indentation of first comment line
            $multiline_comment_indent = length($head) + 1 if $in_multiline_comment == 0;
            # blind comment text, preserving length
            $_ = "$head  ".($opt_minus =~ tr/ /@/cr).($tail =~ tr/ /@/cr);
            $in_multiline_comment++;
        }
    }

    # handle special case of line after '#ifdef __cplusplus' (which typically appears in header files)
    if ($ifdef__cplusplus) {
        $ifdef__cplusplus = 0;
        $_ = "$1 $2" if m/^(\s*extern\s*"C"\s*)\{(\s*)$/; # ignore opening brace in 'extern "C" {'
        goto LINE_FINISHED if m/^\s*\}\s*$/; # ignore closing brace '}'
    }

    # blind contents of character and string literals, preserving length; multi-line string literals are handled below
    s/\\"/@@/g; # blind all '\"' (typically within character literals or string literals)
    s#("[^"]*")#$1 =~ tr/"/@/cr#eg;
    s#('[^']*')#$1 =~ tr/'/@/cr#eg;

    # check for over-long lines,
    # while allowing trailing (also multi-line) string literals to go past $max_length
    my $len = length; # total line length (without trailing \n)
    if($len > $max_length &&
       !(m/^(.*?)"[^"]*("|\\)\s*(,|[\)\}]*[,;]?)\s*$/
         && length($1) < $max_length)) { # allow over-long trailing string literal with starting col before $max_length
        complain("len=$len>$max_length");
    }

    if($in_multiline_comment > 1) {
        complain(" * dbl SPC") if !$sloppy_spc && $contents =~ m/(^|[^.])\s\s\S/;
        goto LINE_FINISHED;
    }

    # handle C++ / C99 - style end-of-line comments
    if(m|(.*?)//(.*$)|) {
        complain("//");  # the '//' comment style is not allowed for C90
        $_ = $1; # anyway remove comment text (not preserving length)
    }

    # intra-line whitespace nits @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    if(!$sloppy_spc) {
        m/^(\s*(#\s*)?)(.*?)\s*$/;
        my ($head, $intra_line) = ($1, $3);
        $intra_line =~ s/\\\s*$//; # strip any '\' at EOL
        my $start = length($head);
        for(my $col = $start; $col < $start + length($intra_line) - 2; $col++) {
            complain("dbl SPC") if substr($_, $col, 3) =~ m/\s\s\S/ && !# double space (after leading space)
                # allowed within multi-line column alignment
                # TODO improve to properly cover also first two lines of such an alignment:
                (($line <= 1 || (substr($contents_before , $col + 1, 2) =~ m/\s\S/)) &&
                 ($line <= 2 || (substr($contents_before2, $col + 1, 2) =~ m/\s\S/)));
        }
        # ignore (not preserving length) paths in #include
        $intra_line =~ s/^(include\s*)(".*?"|<.*?>)/$1/e if $1 =~ m/#/;
        # treat op= and comparison operators as simple '=' (not preserving length), simplifying matching below
        $intra_line =~ s/([\+\-\*\/\/%\&\|\^\!<>=]|<<|>>)=/=/g;
        # treat double &&, ||, <<, and >> as single ones (not preserving length), simplifying matching below
        $intra_line =~ s/(&&|\|\||<<|>>)/substr($1,0,1)/eg;
        # remove blinded comments etc. directly before ,;)}
        while($intra_line =~ s/\s*@+([,;\)\}\]])/$1/e) {} # /g does not work here
        # treat remaining blinded comments and string literals as (single) space during matching below
        $intra_line =~ s/(@+\s*)+/ /;
        $intra_line =~ s/\s+$//;                    # strip any (resulting) space at EOL
        $intra_line =~ s/(for\s*\();;(\))/"$1$2"/e; # strip ';;' in for (;;)
        $intra_line =~ s/(=\s*)\{ /"$1@ "/eg;       # do not complain about {SPC in initializers such as ' = { 0, };'
        $intra_line =~ s/, \};/, @;/g;              # do not complain about SPC} in initializers such as ' = { 0, };'
        $intra_line =~ s/\-\>|\+\+|\-\-/@@/g;       # blind '->,', '++', and '--', preserving length
        complain("SPC$1")       if $intra_line =~ m/\s([,;\)\]])/;     # space before ,;)]
        complain("$1SPC")       if $intra_line =~ m/([\(\[])\s/;       # space after ([
        complain("no SPC$1")    if $intra_line =~ m/\S([=\|\+\/%<>])/; # =|+/%<> without preceding space
        # - TODO same for '*' and '&' except in type/pointer expressions, same for '-' except after casts
        complain("$1no SPC")    if $intra_line =~ m/([,;=\|\/%])\S/;   # ,;=|/% without following space
        # - TODO same for '*' and '&' except in type/pointer expressions, same also for binary +-<>
        complain("'$2' no SPC") if $intra_line =~ m/(^|\W)(if|for|while|switch)[^\w\s]/;  # if etc. without following space
        complain("no SPC{")     if $intra_line =~ m/[^\s\{]\{/;        # '{' without preceding (space or '{')
        complain("}no SPC")     if $intra_line =~ m/\}[^\s,;\}]/;      # '}' without following (space or ',' ';' or '}')
    }

    # empty lines, preprocessor directives, and characters/string iterals @@@@@@

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
        goto POSTPROCESS_DIRECTIVE unless $directive =~ m/^define$/; # skip normal code line handling except for #define
        # TODO improve current mix of handling indents for normal C code and preprocessor directives
    }

    # handle multi-line string literals to avoid confusion on trailing '\' -
    # this is not done for other uses of trailing '\' in order to be able
    # to check layout of multi-line preprocessor directives
    if (defined $multiline_string) {
        $_ = $multiline_string.$_;
        undef $multiline_string;
        m/^(\s*)/;
        $count = length $1; # re-calculate count, like done above
    }
    if (m/^(([^"]*"[^"]*")*[^"]*"[^"]*)\\\s*$/) { # trailing '\' in last string literal
        $multiline_string = $1;
        goto LINE_FINISHED; # TODO check indents not only for first line of multi-line string
    }

    # trailing '\' is typically used in multi-line macro definitions;
    # strip it along with any preceding whitespace such that it does not interfere with various matching done below
    $_ = $1 if (m/^(.*?)\s*\\\s*$/); # trailing '\'

    # adapt required indentation @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    # temporarily adapt required indents according to leading closing symbols
    if ($hanging_indent != 0) {
        if(m/^(\s*)([\)\}\]:])(.*)$/) { # leading }, ), ], :
            my ($head, $closing_symbol, $tail) = ($1, $2, $3);
            $hanging_indent = @nested_parens_indents   >= 2 ? @nested_parens_indents  [-2] : 0 if $closing_symbol eq ")";
            $hanging_indent = @nested_braces_indents   >= 2 ? @nested_braces_indents  [-2] : 0 if $closing_symbol eq "}";
            $hanging_indent = @nested_brackets_indents >= 2 ? @nested_brackets_indents[-2] : 0 if $closing_symbol eq "]";
            $hanging_indent = @nested_conds_indents    >= 1 ? @nested_conds_indents   [-1] : 0 if $closing_symbol eq ":";
            if($closing_symbol eq "}" && @nested_braces_indents <= 1
               && @nested_parens_indents == 0 && @nested_brackets_indents == 0 && @nested_conds_indents == 0
               ) { # end of expr - TODO maybe add && $tail =~ m/;/ but terminator could be on a later line
                $hanging_indent = 0;
                $local_offset -= INDENT_LEVEL;
            }
        }
        elsif(m/^(\s*)(static_)?ASN1_ITEM_TEMPLATE_END(\W|$)/) {
            $hanging_indent = 0;
            $extra_singular_indent -= INDENT_LEVEL;
            #$local_offset -= INDENT_LEVEL; # these macros are used for formatting like an implicit '}'
        }
    } else { # outside expression/statement/type declaration/variable definition/function header
        complain("... }") if m/^\s*[^\s\{\}][^\{\}]*\}/; # non-whitespace non-} before first '}'
        if(m/^\s*((\}\s*)+)/) { # leading sequence of closing braces '}'
            # reduce to-be-cecked indent according to number of statement-level '}'
            my $num_leading_closing_braces = $1 =~ tr/\}//;
            $local_offset -= $num_leading_closing_braces * INDENT_LEVEL;
        }
        if (m/^\s*(case|default)(\W|$)/) {
            $local_offset = -INDENT_LEVEL;
        } else {
            if (m/^(\s*)(\w+):/) { # label, cannot be "default"
                $label = 1;
                $local_offset = -INDENT_LEVEL + 1 ;
            }
        }
    }

    # sanity-check underflow due to closing braces
    if ($indent + $local_offset < 0) {
        complain(-($indent + $local_offset)/INDENT_LEVEL." too many }");
        $local_offset = -$indent;
    }

    # potential adaptations of indent in first line of macro body in multi-line macro definition
    my $more_lines = parens_balance($contents_before) < 0; # then match two-line macro headers
    # - TODO handle also multiple header lines
    if (($more_lines ? $contents_before2 : $contents_before) =~ m/^\s*#\s*define(\W|$)/ &&
        $in_multiline_directive == 1 + $more_lines) {
        if ($count == $indent - INDENT_LEVEL) { # macro body actually started with same indentation as preceding code
            $indent -= INDENT_LEVEL;
            $multiline_macro_same_indent = 1;
        }
    }

    # check required indentation @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    check_indent() unless $contents =~ m/^\s*#\s*define(\W|$)/; # indent of #define has been handled above

    # do some further checkds @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    my $outermost_level =
         $indent == 0 ||
        ($indent == INDENT_LEVEL && $in_multiline_directive > 0 && !$multiline_macro_same_indent);

    # check for code block containing a single line/statement
    if(!$outermost_level && $in_typedecl == 0 && m/^\s*\}/) {
        # leading closing brace '}' in function body, not within type declaration
        # TODO extend detection from single-line to potentially multi-line statement?
        if($line_opening_brace != 0 &&
           $line_opening_brace == $line - 2) {
            # TODO do not complain about cases where a further if .. else branch
            # follows with a block containg more than one line/statement
            $line--;
            complain_contents("{1 line}", ": $contents_before");
            $line++;
        }
    }

    # TODO complain on empty line within local variable definitions

    # TODO complain on missing empty line after local variable definitions

    # adapt required indentation for following lines @@@@@@@@@@@@@@@@@@@@@@@@@@@

    # adapt indent for following lines according to balance of braces (also within expressions)
    my $braces_balance = braces_balance($_);
    $indent += $braces_balance * INDENT_LEVEL;
    $hanging_indent += $braces_balance * INDENT_LEVEL if $hanging_indent != 0
        && $in_expr; # the latter actually implies $hanging_indent != 0
    if ($indent < 0) { # sanity-check underflow due to closing braces
        $indent = 0;
        # complain(-$indent." too many }"); # already reported above
    }

    # detect start of if/for/while/switch expression
    my $in_else = m/\Welse(\W|$)/; # save (since it will be blinded) for below handling of $line_opening_brace
    if (m/^(.*\W(if|for|while|switch))((\W|$).*)$/) {
        my ($head, $tail) = ($1, $3);
        # start of expression
        $in_paren_expr = 1;
        $tail =~ m/^(\s*\(?)/;
        $in_expr = 1;
        $hanging_indent = length($head) + length($1);
        # blind non-space within head as @ to avoid confusing update_nested_indents() due to potential '{'
        $_ = $head =~ tr/ /@/cr . $tail;
        # then start of statement
        $extra_singular_indent += INDENT_LEVEL;
        # on 'do .. while' the latter += will be canceled after the 'while' because it is terminated by ';'
    }

    if (m/(^|\W)(typedef|struct|union|enum)(\W|$)/) { # type declaration
        $in_typedecl++;
    }

    # set extra_singular_indent for typedef/do/else
    # treat typedef followed by struct/union/enum as the latter, blinding it as @, preserving length
    s/(^\s*)typedef(\s*)(struct|union|enum)/$1."@@@@@@@".$2.$3/e;
    if (m/(^|\W)(typedef|else|do)(\W|$)/) { # TODO also handle multiple type decls per line
        $extra_singular_indent += INDENT_LEVEL;
    }

    # set extra_singular_indent, hanging_expr_indent and hanging_indent for return/enum/assignment
    s/[\!<>=]=/@@/g; # prevent matching (in-)equality on next line
    if (m/^(((.*\W(return|enum))|([^=]*)=)\s*)(.*)\s*$/) {
        # return or enum or assignment 'LHS = ' - TODO check if complex LHS of assignment needs to be handled
        my ($head, $tail) = ($1, $6);
        if (!$in_expr && @nested_parens_indents + parens_balance($head) == 0) # not nested assignment etc.
        {
            $in_expr = 1;
            $hanging_indent = $indent + INDENT_LEVEL;
            # blind non-space within head as @ to avoid confusing update_nested_indents() due to potential '{'
            $_ = $head =~ tr/ /@/cr . $tail;
            $extra_singular_indent += INDENT_LEVEL;
        }
    }

    my ($end_in_paren_expr, $terminator_position) = update_nested_indents($_);

    if ($in_paren_expr) { # if/for/while/switch
        if ($end_in_paren_expr) { # end of its (expr)
            # reset hanging indents while keeping extra_singular_indent
            reset_hanging_indents("end of (expr)");
        }
    } elsif ($in_expr || $hanging_indent != 0) {
        # reset hanging indents
        # on end of non-if/for/while/switch (multi-line) expression (i.e., return/enum/assignment) and
        # on end of statement/type declaration/variable definition/function header
        my $trailing_opening_brace = m/\{\s*$/;
        if ($terminator_position >= 0) {
            reset_hanging_indents("end of expr/stmt/decl");
        } elsif ($outermost_level && !$in_expr && @nested_parens_indents == 0 && !$trailing_opening_brace) {
            # assuming end of function header in function definition
            reset_hanging_indents("end of fn hdr");
        }
    }

    # on ';', which terminates the current statement/type declaration/variable definition/function declaration
    if ($terminator_position >= 0) {
        $extra_singular_indent = 0; # normal end, or cancel after 'do .. while'
        $in_typedecl-- if $in_typedecl > 0; # TODO also handle multiple type decls per line
        m/(;[^;]*)$/; # match last ';'
        # - this may be undefined in case of virtual terminator used in update_nested_indents(): /^\w*ASN1_[A-Z_]+END\w*/
        $terminator_position = length($_) - length($1) if $1;
        # the new $terminator_position value may be after the earlier one in case multiple terminators on current line
        # TODO check treatment in case multiple terminators on current line
        update_nested_indents($_, $terminator_position + 1);
    }

    # set hanging_indent according to nested indents
    my $max_indent = -1;
    $max_indent = max($max_indent, $nested_parens_indents  [-1]) if @nested_parens_indents;
    $max_indent = max($max_indent, $nested_braces_indents  [-1]) if @nested_braces_indents;
    $max_indent = max($max_indent, $nested_brackets_indents[-1]) if @nested_brackets_indents;
    # ":" is treated specially as closing symbol
  # $max_indent = max($max_indent, $nested_conds_indents   [-1]) if @nested_conds_indents;
    complain("unexpected requirement for hanging indent=0") if $max_indent == 0;
    # this sets $hanging_indent also outside expressions: in statement/type declaration/variable definition/function header
    $hanging_indent = $max_indent if $max_indent >= 0;

    # handle last (typically trailing) opening brace '{' in line
    if (m/^(.*?)\{([^\{]*)$/) { # match ... '{'
        my ($head, $tail) = ($1, $2);
        if (!$in_expr && $in_typedecl == 0) {
            if ($outermost_level) { # we assume end of function definition header (or statement or variable definition)
                # check if { is at end of line (rather than on next line)
                complain("{ at EOL") if $head =~ m/\S/; # non-whitespace before {
            } else {
                $line_opening_brace = $line unless $in_else && $line_opening_brace < $line - 2;
            }
            complain("{ ...") if $tail=~ m/\S/ && !($tail=~ m/\}/); # non-whitespace and no '}' after last '{'
        }
        $extra_singular_indent = 0 if $head =~ m/\S/; # cancel any hanging stmt/expr/typedef
    }

  POSTPROCESS_DIRECTIVE:
    # on start of multi-line preprocessor directive, adapt indent
    # need to use original line contents because trailing '\' may have been stripped above
    if ($contents =~ m/^(.*?)\s*\\\s*$/) { # trailing '\',
        # typically used in macro definitions (or other preprocessor directives)
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
    # need to use original line contents because trailing \ may have been stripped above
    unless ($contents =~ m/^(.*?)\s*\\\s*$/) { # no trailing '\'
        $indent -= INDENT_LEVEL if $in_multiline_directive > 0 && !$multiline_macro_same_indent;
        $in_multiline_directive = 0;
    }

    if($ARGV =~ m/check-format-test.c/) { # debugging
        my $should_complain = $contents =~ m/\*@(\d)?/ ? 1 : 0;
        $should_complain = +$1 if defined $1;
        print("$ARGV:$line:##"."##$num_current_complaints complaints##"."##:$contents")
            if $num_current_complaints != $should_complain;
    }
    $num_current_complaints = 0;

    # post-processing at end of file @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    if(eof) {
        # check for essentially empty line just before EOF
        complain("SPC/empty line at EOF") if $contents =~ m/^\s*\\?\s*$/;
        $line = "EOF";

        # sanity-check balance of { .. } via final indent at end of file
        complain_contents(ceil($indent / INDENT_LEVEL)." unclosed {", "\n") if $indent != 0;

        # sanity-check balance of #if .. #endif via final preprocessor directive indent at end of file
        complain_contents("$directive_indent unclosed #if", "\n") if $directive_indent != 0;

        reset_file_state();
    }
}

my $num_other_complaints = $num_complaints - $num_indent_complaints - $num_SPC_complaints;
print "$num_complaints ($num_indent_complaints indentation, $num_SPC_complaints whitespace,"
    ." $num_other_complaints other) issues have been found by $0\n";
