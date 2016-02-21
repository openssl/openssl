#! /usr/bin/perl

# Quick transfer to the downloaded Text::Template

BEGIN {
    use File::Spec::Functions;
    use File::Basename;
    use lib catdir(dirname(__FILE__), "..", "..", "Text-Template-1.46", "lib");
    # Some unpackers on VMS convert periods in directory names to underscores
    use lib catdir(dirname(__FILE__), "..", "..", "Text-Template-1_46", "lib");
    use Text::Template;
    shift @INC;                 # Takes away the effect of use lib
    shift @INC;                 # Takes away the effect of use lib
}
1;
