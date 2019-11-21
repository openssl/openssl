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
#   check-format.pl [-l|--sloppy-len] [-s|--sloppy-space]
#                   [-c|--sloppy-cmt] [-h|--sloppy-hang]
#                   <files>
#
# checks adherence to the formatting rules of the OpenSSL coding guidelines.
# This pragmatic tool is incomplete and yields some false positives.
# Still it should be useful for detecting most typical glitches.
#
# options:
#  -l | --sloppy-len   increases accepted max line length from 80 to 84
#  -s | --sloppy-space disables reporting whitespace nits
#  -c | --sloppy-cmt   allows any indentation for comments
#  -h | --sloppy-hang  when checking hanging indentation, suppresses reports for
#                      * same indentation as on line before
#                      * indentation moved left (not beyond non-hanging indent)
#                        just to fit contents within the line length limit
#                      and allows the non-hanging indent level as alternative
#
# There are known false positives such as the following.
#
# * There is the special OpenSSL rule not to unnecessarily use braces around
#   a single statement :
#   {
#       single statement;
#   }
#   except within if .. else constructs where some branch contains more than one
#   statement. The exception is not recognized - and thus false positives are
#   reported - when such a branch occurs after the current position.
#   Moreover, false negatives occur if the braces are more than two lines apart.
#
# * Use of multiple consecutive spaces is regarded a coding style nit except
#   when done in order to align certain columns over multiple lines, e.g.:
#   # define AB  1
#   # define CDE 22
#   # define F   3333
#   This pattern is recognized - and consequently double space not reported -
#   for a given line if in the line before or after (as far as these exist)
#   for each occurrence of "  \S" (where \S means non-space) in the given line
#   there is " \S" in the other line in the respective column position.
#   This may lead to both false negatives (in case of coincidental " \S")
#   and false negatives (in case of more complex multi-column alignment).

use strict;
use List::Util qw[min max];
use POSIX;

use constant INDENT_LEVEL => 4;
use constant MAX_LENGTH => 80;

# command-line options
my $max_length = MAX_LENGTH;
my $sloppy_SPC = 0;
my $sloppy_hang = 0;
my $sloppy_cmt = 0;

while($ARGV[0] =~ m/^-(\w|-[\w\-]+)$/) {
    my $arg = $1; shift;
    if($arg =~ m/^(l|-sloppy-len)$/) {
        $max_length += INDENT_LEVEL;
    } elsif($arg =~ m/^(s|-sloppy-spc)$/) {
        $sloppy_SPC = 1;
    } elsif($arg =~ m/^(h|-sloppy-hang)$/) {
        $sloppy_hang = 1;
    } elsif($arg =~ m/^(c|-sloppy-cmt)$/) {
        $sloppy_cmt = 1;
    } else {
        die("unknown option: $arg");
    }
}

my $self_test;
my $line;                  # current line number
my $contents;              # contents of current line
my $contents_before;       # contents of previous line, used only if $line > 1
my $contents_before_;      # contents of previous line after blinding comments etc., used only if $line > 1
my $contents_before2;      # contents of line before previous line, used only if $line > 2
my $contents_before_2;     # contents of line before previous line after blinding comments etc., used only if $line > 2
my $multiline_string;      # accumulator for lines containing multi-line string
my $count;                 # number of leading whitespace characters (except newline) in current line,
                           # which basically should equal $indent or $hanging_indent, respectively
my $count_before;          # number of leading whitespace characters (except newline) in previous line, used only if $line > 1
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
my $in_paren_expr;         # in condition of if/for/while and expr of switch, used only if $hanging_indent != 0
my $in_typedecl;           # nesting level of typedef/struct/union/enum
my $in_directive;          # number of lines so far within preprocessor directive, e.g., macro definition
my $in_define_header;      # number of open parentheses + 1 in (multi-line) header of #define, used only if $in_directive > 0
my $multiline_macro_same_indent; # workaround for multiline macro body without extra indent
my $in_comment;            # number of lines so far within multi-line comment, or -1 when end has been detected
my $comment_indent;        # used only if $in_comment > 0
my $num_reports_line = 0;  # number of issues found on current line
my $num_reports = 0;       # total number of issues found
my $num_SPC_reports = 0;   # total number of whitespace issues found
my $num_indent_reports = 0;# total number of indentation issues found

sub report_flex {
    my $line = shift;
    my $msg = shift;
    my $contents = shift;

    my $report_SPC = $msg =~ /SPC/;
    return if $report_SPC && $sloppy_SPC;

    print "$ARGV:$line:$msg:$contents" unless $self_test;
    $num_reports_line++;
    $num_reports++;
    $num_SPC_reports++ if $report_SPC;
    $num_indent_reports++ if $msg =~ /indent/;
}

sub report {
    my $msg = shift;
    report_flex($line, $msg, $contents);
}

sub parens_balance { # count balance of opening parentheses - closing parentheses
    my $str = shift;
    return $str =~ tr/\(// - $str =~ tr/\)//;
}

sub braces_balance { # count balance of opening braces - closing braces
    my $str = shift;
    return $str =~ tr/\{// - $str =~ tr/\}//;
}

sub blind_nonspace { # blind non-space text of comment as @, preserving length
    # the @ character is used because it cannot occur in normal program code so there is no confusion
    # comment text is not blinded to whitespace in order to be able to check dbl SPC also in comments
    my $comment_text = shift;
    $comment_text =~ s/\.\s\s/.. /g; # in dbl SPC checks allow one extra space after period '.' in comments
    return $comment_text =~ tr/ /@/cr;
}

sub check_indent { # for lines outside multi-line string literals
    my $normal_indent =
        my $alt_indent = $indent + $extra_singular_indent + $local_offset;
    if ($sloppy_cmt && substr($_, $count, 1) eq "@" && # line starting with comment
        ($in_comment == 0 || $in_comment == 1)) { # normal or first line of multi-line comment
        return;
    }
    if ($in_comment > 1 || $in_comment == -1) { # multi-line comment, not first line
        report("comment indent=$count!=$comment_indent") if $count != $comment_indent;
    } elsif ($hanging_indent == 0) {
        my $allowed = $normal_indent;
        $alt_indent = 1 if $label;
        $allowed = "{$alt_indent,$normal_indent}" if $alt_indent != $normal_indent;
        report("indent=$count!=$allowed") if $count != $normal_indent && $count != $alt_indent;
    }
    else {
        my $alt_indent = $hanging_indent;
        if ($sloppy_hang) {
            # do not report same indentation as on line before (potentially due to same violations)
            return if $line > 1 && $count == $count_before;

            # do not report if contents have been shifted left (but not left of normal indent) in order to fit within line length limit
            return if $indent <= $count && $count < $hanging_indent && length($contents) == MAX_LENGTH + length("\n");

            # in addition to hanging indent, allow normal indentation level
            $alt_indent = $normal_indent;
        } elsif (($in_expr || $hanging_indent != 0) && substr($_, $count, 1) eq ":") { # special treatment for leading ':'
            # allow hanging expression etc. indent of leading ":" at normal indentation level
            $alt_indent = $normal_indent;
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
        report("hanging indent=$count!=$allowed")
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
        pop(@nested_parens_indents)   : report("too many )")  if ($c eq ")");
            @nested_braces_indents    ?
        pop(@nested_braces_indents)   :(report("too many } in expr"),
                                       $hanging_indent += INDENT_LEVEL,
                                       $indent += INDENT_LEVEL) if $c eq "}" && $in_expr && !$end_in_paren_expr;
            @nested_brackets_indents  ?
        pop(@nested_brackets_indents) : report("too many ]")  if $c eq "]";
            @nested_conds_indents     ?
        pop(@nested_conds_indents)    : report("too many ':'")  if $c eq ":"
                && ($in_expr || $hanging_indent != 0 || !( # ignore in following situations:
                    # after initial label/case/default - TODO extend to multi-line expressions after 'case'
                                                           substr($str, 0, $i) =~ m/^(\s*)(case\W.*$|\w+$)/
                    # bitfield length within unsigned type decl - TODO improve matching
                                                        || substr($str, $i + 1) =~ m/^\s*\d+/));
    }
    return ($end_in_paren_expr, -1);
}

sub check_nested_indents {
    my $position = shift;
    report(+@nested_parens_indents  ." unclosed ( at $position") if @nested_parens_indents;
   (report(+@nested_braces_indents  ." unclosed { at $position")
   ,$indent -= INDENT_LEVEL)                                     if @nested_braces_indents;
    report(+@nested_brackets_indents." unclosed [ at $position") if @nested_brackets_indents;
    report(+@nested_conds_indents   ." unclosed ? at $position") if @nested_conds_indents;
    @nested_parens_indents = @nested_braces_indents =
        @nested_brackets_indents = @nested_conds_indents = ();
}

sub reset_file_state {
    check_nested_indents("EOF");
    $hanging_indent = 0;
    $in_paren_expr = 0;
    $in_expr = 0;
    $extra_singular_indent = 0;
    $indent = 0;
    $directive_indent = 0;
    $ifdef__cplusplus = 0;
    $line = 0;
    undef $multiline_string;
    $line_opening_brace = 0;
    $in_typedecl = 0;
    $in_directive = 0;
    $in_comment = 0;
}

reset_file_state();
while(<>) { # loop over all lines of all input files
    $self_test = $ARGV =~ m/check-format-test.c$/;
    $line++;
    $contents = $_;

    # check for TAB character(s)
    report("TAB") if m/[\x09]/;

    # check for CR character(s)
    report("CR") if m/[\x0d]/;

    # check for other non-printable ASCII character(s)
    report("non-printable at ".(length $1)) if m/(.*?)[\x00-\x08\x0B-\x0C\x0E-\x1F]/;

    # check for other non-ASCII character(s)
    report("non-ASCII '$1'") if m/([\x7F-\xFF])/;

    # check for whitespace at EOL
    report("SPC at EOL") if m/\s\n$/;

    # assign to $count the actual indentation level of the current line
    chomp; # remove tailing \n
    m/^(\s*)/;
    $count = length $1;
    $label = 0;
    $local_offset = 0;

    # comments and character/string literals @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    # do/prepare checks within multi-line comments
    my $self_test_exception = $self_test ? "@" : "";
    if($in_comment > 0) { # this includes the last line of multi-line commment
        m/^(\s*)(.?)(.*)$/;
        my ($head, $any_symbol, $comment_text) = ($1, $2, $3);
        if($any_symbol eq "*") {
            report("*no SPC")  if $comment_text =~ m|^[^/\s$self_test_exception]|;
        } else {
            report("no leading * in multi-line comment");
        }
        $in_comment++;
    }

    # detect end of comment, must be within multi-line comment, check if it is preceded by non-whitespace text
    if (m/^(.*?)\*\/(.*)$/ && $1 ne '/') { # ending comment: '*/' - TODO ignore '*/' inside string literal
        my ($head, $tail) = ($1, $2);
        report("no SPC*/") if $head =~ m/\S$/;
        report("*/no SPC") if $tail =~ m/^\S/;
        if (!($head =~ m/\/\*/)) { # not starting comment '/*', which is is handled below
            if ($in_comment == 0) {
                report("*/ outside comment");
                $_ = "$head@@".$tail; # blind the "*/"
            } else {
                report("... */") if $head =~ m/\S/; # head contains non-whitespace
                my $comment_text = $head;
                $_ = blind_nonspace($comment_text)."@@".$tail;
                $in_comment = -1;
            }
        }
    }

    # detect start of comment, check if it is followed by non-space text
  MATCH_COMMENT:
    if (m/^(.*?)\/\*(-?)(.*)$/) { # starting comment: '/*' - TODO ignore '/*' inside string literal
        my ($head, $opt_minus, $tail) = ($1, $2, $3);
        report("no SPC/*") if $head =~ m/[^\s]$/;
        report("/*no SPC") if $tail =~ m/^[^\s$self_test_exception]/;
        my $comment_text = $opt_minus.$tail; # preliminary
        if ($in_comment > 0) {
            report("/* inside multi-line comment");
        } elsif ($tail =~ m/^(.*?)\*\/(.*)$/) { # comment end: */ on same line - TODO ignore '*/' inside string literal
            report("/* inside intra-line comment") if $1 =~ /\/\*/;
            # blind comment text, preserving length
            ($comment_text, my $rest) = ($opt_minus.$1, $2);
            if ($head =~ m/\S/ && # not leading comment: non-whitespace before
                $rest =~ m/^\s*$/) { # trailing comment: only whitespace after
                report("/* dbl SPC */") if $comment_text =~ m/(^|[^.])\s\s\S/;
                # blind trailing commment as space - TODO replace by @ after improving matching of trailing items
                $_ = "$head  ".($comment_text =~ tr/ / /cr)."  $rest";
            } else { # leading or intra-line comment
                $_ = "$head@@".blind_nonspace($comment_text)."@@".$rest;
            }
            goto MATCH_COMMENT;
        } else { # start of multi-line comment
            report("/* ...") unless $tail =~ m/^.?\s*\\?\s*$/; # tail not essentially empty, first char already checked: "/*no SPC"
            # adopt actual indentation of first line
            $comment_indent = length($head) + 1;
            $_ = "$head@@".blind_nonspace($comment_text);
            $in_comment = 1;
        }
    }

    if($in_comment > 1) { # still inside multi-line comment (not at its start or end)
        m/^(\s*)\*?(\s*)(.*)$/;
        $_ = $1."@".$2.blind_nonspace($3);
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
        report("len=$len>$max_length");
    }

    # handle C++ / C99 - style end-of-line comments
    if(m|(.*?)//(.*$)|) {
        report("//");  # the '//' comment style is not allowed for C90
        report("// dbl SPC") if $2 =~ m/(^|[^.])\s\s\S/;
        # sacrifycing multi-line column alignment for this line - TODO blind by @ after improving matching of trailing items
        $_ = $1; # anyway ignore comment text (not preserving length)
    }

    # at this point comment text has been removed/ignored (after checking dbl SPC)
    # or at least the non-space portions of commment text have been blinded as @

    # intra-line whitespace nits @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    if(!$sloppy_SPC) {
        sub split_line_head {
            shift =~ m/^(\s*(#\s*)?)(.*?)\s*$/; # do not check for dbl SPC in leading spaces and any leading '#'
            return ($1, $3 =~ s/\s*\\\s*$//r); # strip any trailing '\' (and any whitespace around it)
        }
        my ($head , $intra_line ) = split_line_head($_);
        my ($head1, $intra_line1) = split_line_head($contents_before_ ) if $line > 1;
        my ($head2, $intra_line2) = split_line_head($contents_before_2) if $line > 2;
        if($line >= 2) { # check with one line delay, such that at least $contents_before is available
            sub column_alignments_only {
                my $head = shift;
                my $intra = shift;
                my $contents = shift;
                # check if all dbl SPC in $intra is used only for multi-line column alignment with $contents
                my $offset = length($head);
                for(my $col = 0; $col < length($intra) - 2; $col++) {
                   return 0 if substr($intra   , $col, 3) =~ m/\s\s\S/ # double space (after leading space)
                          && !(substr($contents, $col + $offset + 1, 2) =~ m/\s\S/)
                }
                return 1;
            }
            report_flex($line - 1, "dbl SPC", $contents_before) if $intra_line1 =~ m/\s\s\S/ && !
                (    column_alignments_only($head1, $intra_line1, $_                )    # compare with $line
                 || ($line > 2 &&
                     column_alignments_only($head1, $intra_line1, $contents_before_2))); # compare with $line - 2
            report("dbl SPC") if $intra_line  =~ m/\s\s\S/ && eof
                && ! column_alignments_only($head , $intra_line , $contents_before_ )  ; # compare with $line - 1
        } elsif(eof) { # special case: just one line exists
            report("dbl SPC") if $intra_line  =~ m/\s\s\S/;
        }
        # ignore paths in #include
        $intra_line =~ s/^(include\s*)(".*?"|<.*?>)/$1/e if $head =~ m/#/;
        # treat op= and comparison operators as simple '=', simplifying matching below
        $intra_line =~ s/([\+\-\*\/\/%\&\|\^\!<>=]|<<|>>)=/=/g;
        # treat double &&, ||, <<, and >> as single ones, simplifying matching below
        $intra_line =~ s/(&&|\|\||<<|>>)/substr($1,0,1)/eg;
        # remove blinded comments etc. directly before ,;)}
        while($intra_line =~ s/\s*@+([,;\)\}\]])/$1/e) {} # /g does not work here
        # treat remaining blinded comments and string literals as (single) space during matching below
        $intra_line =~ s/(@+\s*)+/ /g;
        $intra_line =~ s/\s+$//;                    # strip any (resulting) space at EOL
        $intra_line =~ s/(for\s*\();;(\))/"$1$2"/eg; # strip ';;' in for (;;)
        $intra_line =~ s/(=\s*)\{ /"$1@ "/eg;       # do not report {SPC in initializers such as ' = { 0, };'
        $intra_line =~ s/, \};/, @;/g;              # do not report SPC} in initializers such as ' = { 0, };'
        $intra_line =~ s/\-\>|\+\+|\-\-/@/g;       # blind '->,', '++', and '--'
        report("SPC$1")       if $intra_line =~ m/\s([,;\)\]])/;     # space before ,;)]
        report("$1SPC")       if $intra_line =~ m/([\(\[])\s/;       # space after ([
        report("no SPC$1")    if $intra_line =~ m/\S([=\|\+\/%<>])/; # =|+/%<> without preceding space
        # - TODO same for '*' and '&' except in type/pointer expressions, same for '-' except after casts
        report("$1no SPC")    if $intra_line =~ m/([,;=\|\/%])\S/;   # ,;=|/% without following space
        # - TODO same for '*' and '&' except in type/pointer expressions, same also for binary +-<>
        report("'$2' no SPC") if $intra_line =~ m/(^|\W)(if|for|while|switch)[^\w\s]/;  # if etc. without following space
        report("no SPC{")     if $intra_line =~ m/[^\s\{]\{/;        # '{' without preceding (space or '{')
        report("}no SPC")     if $intra_line =~ m/\}[^\s,;\}]/;      # '}' without following (space or ',' ';' or '}')
    }

    # empty lines, preprocessor directives, and characters/string iterals @@@@@@

    goto LINE_FINISHED if m/^\s*\\?\s*$/; # essentially empty line (just whitespace except potentially a single backslash)

    # handle preprocessor directives
    if (m/^\s*#(\s*)(\w+)/) { # line starting with '#'
        my $directive_count = length $1; # maybe could also use indentation before '#'
        my $directive = $2;
        report("indent=$count!=0") if $count != 0;
        $directive_indent-- if $directive =~ m/^else|elsif|endif$/;
        if ($directive_indent < 0) {
            $directive_indent = 0;
            report("unexpected #$directive");
        }
        report("#indent=$directive_count!=$directive_indent")
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
        m/^(\s*)/; $count = length $1; # re-calculate count, like done above
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
    if ($in_expr || $hanging_indent != 0) {
        if(m/^(\s*)([\)\}\]:])(.*)$/) { # leading '}', ')', ']', ':'
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
        } elsif(m/^(\s*)(static_)?ASN1_ITEM_TEMPLATE_END(\W|$)/) {
            $hanging_indent = 0;
            $extra_singular_indent -= INDENT_LEVEL;
        }
    } else { # outside expression/statement/type declaration/variable definition/function header
        report("... }") if m/^\s*[^\s\{\}][^\{\}]*\}/; # non-whitespace non-} before first '}'
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
        report(-($indent + $local_offset)/INDENT_LEVEL." too many }");
        $local_offset = -$indent;
    }

    # potential adaptations of indent in first line of macro body in multi-line macro definition
    if ($in_directive > 0 && $in_define_header > 0) {
        if ($in_define_header > 1) { # still in macro definition header
            $in_define_header += parens_balance($_);
        } else { # start of macro body
            $in_define_header = 0;
            if ($count == $indent - INDENT_LEVEL) { # macro body started with same indentation as preceding code
                $indent -= INDENT_LEVEL;
                $multiline_macro_same_indent = 1;
            }
        }
    }

    # check required indentation @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    check_indent() unless $contents =~ m/^\s*#\s*define(\W|$)/; # indent of #define has been handled above

    $in_comment = 0 if $in_comment == -1; # multi-line comment has ended

    # do some further checks @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    my $outermost_level =
         $indent == 0 ||
        ($indent == INDENT_LEVEL && $in_directive > 0 && !$multiline_macro_same_indent);

    # check for code block containing a single line/statement
    if($line > 2 && !$outermost_level && $in_typedecl == 0 && m/^\s*\}/) {
        # leading closing brace '}' in function body, not within type declaration
        # TODO extend detection from single-line to potentially multi-line statement
        if($line_opening_brace != 0 &&
           $line_opening_brace == $line - 2) {
            # TODO do not report cases where a further else branch
            # follows with a block containg more than one line/statement
            report_flex($line - 1, "{1 line}", $contents_before);
        }
    }

    # TODO report empty line within local variable definitions

    # TODO report missing empty line after local variable definitions

    # adapt required indentation for following lines @@@@@@@@@@@@@@@@@@@@@@@@@@@

    # adapt indent for following lines according to balance of braces (also within expressions)
    my $braces_balance = braces_balance($_);
    $indent += $braces_balance * INDENT_LEVEL;
    $hanging_indent += $braces_balance * INDENT_LEVEL if $hanging_indent != 0
        && $in_expr; # the latter actually implies $hanging_indent != 0
    if ($indent < 0) { # sanity-check underflow due to closing braces
        $indent = 0;
        # report(-$indent." too many }"); # already reported above
    }

    # detect start of if/for/while/switch expression
    my $in_else = m/\Welse(\W|$)/; # save (since it will be blinded) for below handling of $line_opening_brace
    if (m/^(.*\W(if|for|while|switch))((\W|$).*)$/) {
        my ($head, $tail) = ($1, $3);
        # start of expression
        $in_expr = 1;
        $in_paren_expr = 1;
        $tail =~ m/^(\s*\(?)/;
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
            # blind non-space within head as @ to avoid confusing update_nested_indents() due to potential '{'
            $_ = $head =~ tr/ /@/cr . $tail;
            $extra_singular_indent += INDENT_LEVEL;
        }
    }

    my ($end_in_paren_expr, $terminator_position) = update_nested_indents($_);

    if ($in_paren_expr) { # if/for/while/switch
        if ($end_in_paren_expr) { # end of its (expr)
            # reset hanging indents while keeping extra_singular_indent
            check_nested_indents("end of (expr)");
            $in_expr = 0;
            $in_paren_expr = 0;
        }
    } elsif ($in_expr || $hanging_indent != 0) {
        # reset hanging indents
        # on end of non-if/for/while/switch (multi-line) expression (i.e., return/enum/assignment) and
        # on end of statement/type declaration/variable definition/function header
        my $trailing_opening_brace = m/\{\s*$/;
        if ($terminator_position >= 0) {
            check_nested_indents("end of expr/stmt/decl");
            $in_expr = 0;
        } elsif ($outermost_level && !$in_expr && @nested_parens_indents == 0 && !$trailing_opening_brace) {
            # assuming end of function header in function definition
            check_nested_indents("end of fn hdr");
            $in_expr = 0;
        }
    }

    # on ';', which terminates the current statement/type declaration/variable definition/function declaration
    if ($terminator_position >= 0) {
        $extra_singular_indent = 0; # normal end, or cancel after 'do .. while'
        $in_typedecl-- if $in_typedecl > 0; # TODO also handle multiple type decls per line
        m/(;[^;]*)$/; # match last ';'
        $terminator_position = length($_) - length($1) if $1;
        # the new $terminator_position value may be after the earlier one in case multiple terminators on current line
        # TODO check treatment in case of multiple terminators on current line
        update_nested_indents($_, $terminator_position + 1);
    }

    # set hanging_indent according to nested indents
    my $max_indent = -1;
    $max_indent = max($max_indent, $nested_parens_indents  [-1]) if @nested_parens_indents;
    $max_indent = max($max_indent, $nested_braces_indents  [-1]) if @nested_braces_indents;
    $max_indent = max($max_indent, $nested_brackets_indents[-1]) if @nested_brackets_indents;
    # ":" is treated specially as closing symbol
  # $max_indent = max($max_indent, $nested_conds_indents   [-1]) if @nested_conds_indents;
    report("unexpected requirement for hanging indent=0") if $max_indent == 0;
    # this sets $hanging_indent also outside expressions: in statement/type declaration/variable definition/function header
    $hanging_indent = $max_indent >= 0 ? $max_indent : 0;

    # handle last (typically trailing) opening brace '{' in line
    if (m/^(.*?)\{([^\{]*)$/) { # match last ... '{'
        my ($head, $tail) = ($1, $2);
        if (!$in_expr && $in_typedecl == 0) {
            if ($outermost_level) { # we assume end of function definition header (or statement or variable definition)
                # check if { is at end of line (rather than on next line)
                report("{ at EOL") if $head =~ m/\S/; # non-whitespace before {
            } else {
                $line_opening_brace = $line unless $in_else && $line_opening_brace < $line - 2;
            }
            report("{ ...") if $tail=~ m/\S/ && !($tail=~ m/\}/); # non-whitespace and no '}' after last '{'
        }
        $extra_singular_indent = 0 if $head =~ m/\S/; # cancel any hanging stmt/expr/typedef
    }

  POSTPROCESS_DIRECTIVE:
    # on start of multi-line preprocessor directive, adapt indent
    # need to use original line contents because trailing '\' may have been stripped above
    if ($contents =~ m/^(.*?)\s*\\\s*$/) { # trailing '\',
        # typically used in macro definitions (or other preprocessor directives)
        $in_define_header = 0;
        if ($in_directive == 0 && m/^DEFINE_|\s*#\s*(define(\W|$))?(.*)/) { # start, not only for #define
            $in_define_header = 1 + parens_balance($2) if defined $1;
            $indent += INDENT_LEVEL ;
            $multiline_macro_same_indent = 0;
        }
        $in_directive += 1;
    }

  LINE_FINISHED:
    # on end of multi-line preprocessor directive, adapt indent
    # need to use original line contents because trailing \ may have been stripped
    unless ($contents =~ m/^(.*?)\s*\\\s*$/) { # no trailing '\'
        $indent -= INDENT_LEVEL if $in_directive > 0 && !$multiline_macro_same_indent;
        $in_directive = 0;
    }

    $contents_before2  = $contents_before;
    $contents_before_2 = $contents_before_;
    $contents_before   = $contents;
    $contents_before_  = $_;
    $count_before = $count;

    if($self_test) { # debugging
        my $should_report = $contents =~ m/\*@(\d)?/ ? 1 : 0;
        $should_report = +$1 if defined $1;
        print("$ARGV:$line:$num_reports_line reports on:$contents")
            if $num_reports_line != $should_report;
    }
    $num_reports_line = 0;

    # post-processing at end of file @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    if(eof) {
        # check for essentially empty line just before EOF
        report("SPC/empty line at EOF") if $contents =~ m/^\s*\\?\s*$/;

        # sanity-check balance of { .. } via final indent at end of file
        report_flex("$line (EOF)", ceil($indent / INDENT_LEVEL)." unclosed {", "\n") if $indent != 0;

        # sanity-check balance of #if .. #endif via final preprocessor directive indent at end of file
        report_flex("$line (EOF)", "$directive_indent unclosed #if", "\n") if $directive_indent != 0;

        reset_file_state();
    }
}

my $num_other_reports = $num_reports - $num_indent_reports - $num_SPC_reports;
print "$num_reports ($num_indent_reports indentation, $num_SPC_reports whitespace,"
    ." $num_other_reports other) issues have been found by $0\n" unless $self_test;
