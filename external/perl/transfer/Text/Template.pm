#! /usr/bin/perl

# Quick transfer to the downloaded Text::Template

BEGIN {
    use File::Spec::Functions;
    use File::Basename;
    use lib catdir(dirname(__FILE__), "..", "..");
    my $texttemplate = catfile("Text-Template-1.46", "lib", "Text", "Template.pm");
    require $texttemplate;
}
1;
