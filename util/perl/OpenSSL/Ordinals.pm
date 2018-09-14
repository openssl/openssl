#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

package OpenSSL::Ordinals;

use strict;
use warnings;
use Carp;
use Scalar::Util qw(blessed);

=head1 NAME

OpenSSL::Ordinals - a private module to read and walk through ordinals

=head1 SYNOPSIS

  use OpenSSL::Ordinals;

  my $ordinals = OpenSSL::Ordinals->new(from => "foo.num");
  # or alternatively
  my $ordinals = OpenSSL::Ordinals->new();
  $ordinals->load("foo.num");

  foreach ($ordinals->items(comparator => by_name()) {
    print $_->name(), "\n";
  }

=head1 DESCRIPTION

This is a OpenSSL private module to load an ordinals (F<.num>) file and
write out the data you want, sorted and filtered according to your rules.

An ordinals file is a file that enumerates all the symbols that a shared
library or loadable module must export.  Each of them have a unique
assigned number as well as other attributes to indicate if they only exist
on a subset of the supported platforms, or if they are specific to certain
features.

The unique numbers each symbol gets assigned needs to be maintained for a
shared library or module to stay compatible with previous versions on
platforms that maintain a transfer vector indexed by position rather than
by name.  They also help keep information on certain symbols that are
aliases for others for certain platforms, or that have different forms
on different platforms.

=head2 Main methods

=over  4

=cut

=item B<new> I<%options>

Creates a new instance of the C<OpenSSL::Ordinals> class.  It takes options
in keyed pair form, i.e. a series of C<key =E<gt> value> pairs.  Available
options are:

=over 4

=item B<from =E<gt> FILENAME>

Not only create a new instance, but immediately load it with data from the
ordinals file FILENAME.

=back

=cut

sub new {
    my $class = shift;
    my %opts = @_;

    my $instance = {
        contents        => [],    # The items themselves
    };
    bless $instance, $class;

    $instance->load($opts{from}) if defined($opts{from});

    return $instance;
}

=item B<$ordinals-E<gt>load FILENAME>

Loads the data from FILENAME into the instance.  Any previously loaded data
is dropped.

=cut

sub load {
    my $self = shift;
    my $filename = shift;

    croak "Bad instance" unless blessed($self);
    croak "Undefined filename" unless defined($filename);

    my @tmp_contents;
    my $max_num = 0;
    open F, '<', $filename or croak "Unable to open $filename";
    while (<F>) {
        s|\R$||;                # Better chomp
        s|#.*||;
        next if /^\s*$/;

        my $item = OpenSSL::Ordinals::Item->new(from => $_);
        my $num = $item->number();

        croak "Disordered ordinals, $num < $max_num"
            if $num < $max_num;

        push @tmp_contents, $item;
    }
    close F;

    $self->{contents} = [ @tmp_contents ];
    return 1;
}

=item B<$ordinals-E<gt>items> I<%options>

Returns a list of items according to a set of criteria.  The criteria is
given in form keyed pair form, i.e. a series of C<key =E<gt> value> pairs.
Available options are:

=over 4

=item B<sort =E<gt> SORTFUNCTION>

SORTFUNCTION is a reference to a function that takes two arguments, which
correspond to the classic C<$a> and C<$b> that are available in a C<sort>
block.

=item B<filter =E<gt> FILTERFUNCTION>

FILTERFUNTION is a reference to a function that takes one argument, which
is every OpenSSL::Ordinals::Item element available.

=back

=cut

sub items {
    my $self = shift;
    my %opts = @_;

    my $comparator = $opts{sort};
    my $filter = $opts{filter} // sub { 1; };

    my @l = grep { $filter->($_) } @{$self->{contents}};
    return sort { $comparator->($a, $b); } @l
        if (defined $comparator);
    return @l;
}

=back

=head2 Data elements

Data elements, which is each line in an ordinals file, are instances
of a separate class, OpenSSL::Ordinals::Item, with its own methods:

=over 4

=cut

package OpenSSL::Ordinals::Item;

use strict;
use warnings;
use Carp;

=item B<new> I<%options>

Creates a new instance of the C<OpenSSL::Ordinals::Item> class.  It takes
options in keyed pair form, i.e. a series of C<key =E<gt> value> pairs.
Available options are:

=over 4

=item B<from =E<gt> STRING>

MANDATORY OPTION!

This will create a new item, filled with data coming from STRING.

STRING must conform to the following EBNF description:

  ordinal string = symbol, spaces, ordinal, spaces, version, spaces,
                   exist, ":", platforms, ":", type, ":", features;
  spaces         = space, { space };
  space          = " " | "\t";
  symbol         = ( letter | "_"), { letter | digit | "_" };
  ordinal        = number;
  version        = number, "_", number, "_", number, letter, [ letter ];
  exist          = "EXIST" | "NOEXIST";
  platforms      = platform, { ",", platform };
  platform       = ( letter | "_" ) { letter | digit | "_" };
  type           = "FUNCTION" | "VARIABLE";
  features       = feature, { ",", feature };
  feature        = ( letter | "_" ) { letter | digit | "_" };
  number         = digit, { digit };

(C<letter> and C<digit> are assumed self evident)

=back

=cut

sub new {
    my $class = shift;
    my %opts = @_;

    my $string = $opts{from};

    croak "No ordinals string given" unless defined $string;

    my @a = split /\s+/, $string;

    croak "Badly formatted ordinals string: $string"
        unless ( scalar @a == 4
                 && $a[0] =~ /^[A-Za-z_][A-Za-z_0-9]*$/
                 && $a[1] =~ /^\d+$/
                 && $a[2] =~ /^\d+_\d+_\d+(?:[a-z]{0,2})$/
                 && $a[3] =~ /^
                              (?:NO)?EXIST:
                              [^:]*:
                              (?:FUNCTION|VARIABLE):
                              [^:]*
                              $
                             /x );

    my @b = split /:/, $a[3];
    my $instance = { name       => $a[0],
                     number     => $a[1],
                     version    => $a[2],
                     exists     => $b[0] eq 'EXIST',
                     platforms  => { map { m|^(!)?|; $' => !$1 }
                                         split /,/,$b[1] },
                     type       => $b[2],
                     features   => [ split /,/,$b[3] // '' ] };

    return bless $instance, $class;
}

sub DESTROY {
}

=item B<$item-E<gt>name>

The symbol name for this item.

=item B<$item-E<gt>number>

The positional number for this item.

=item B<$item-E<gt>version>

The version number for this item.  Please note that these version numbers
have underscore (C<_>) as a separator the the version parts.

=item B<$item-E<gt>exists>

A boolean that tells if this symbol exists in code or not.

=item B<$item-E<gt>platforms>

A hash table reference.  The keys of the hash table are the names of
the specified platforms, with a value of 0 to indicate that this symbol
isn't available on that platform, and 1 to indicate that it is.  Platforms
that aren't mentioned default to 1.

=item B<$item-E<gt>type>

C<FUNCTION> or C<VARIABLE>, depending on what the symbol represents.
Some platforms do not care about this, others do.

=item B<$item-E<gt>features>

An array reference, where every item indicates a feature where this symbol
is available.  If no features are mentioned, the symbol is always available.
If any feature is mentioned, this symbol is I<only> available when those
features are enabled.

=cut

our $AUTOLOAD;

# Generic getter
sub AUTOLOAD {
    my $self = shift;
    my $funcname = $AUTOLOAD;
    (my $item = $funcname) =~ s|.*::||g;

    croak "$funcname called as setter" if @_;
    croak "$funcname invalid" unless exists $self->{$item};
    return $self->{$item} if ref($self->{$item}) eq '';
    return @{$self->{$item}} if ref($self->{$item}) eq 'ARRAY';
    return %{$self->{$item}} if ref($self->{$item}) eq 'HASH';
}

=item B<$item-E<gt>to_string>

Converts the item to a string that can be saved in an ordinals file.

=cut

sub to_string {
    my $self = shift;

    croak "Too many arguments" if @_;
    my %platforms = $self->platforms();
    my @features = $self->features();
    return sprintf "%-39s %d\t%s\t%s:%s:%s:%s",
        $self->name(),
        $self->number(),
        $self->version(),
        $self->exists() ? 'EXIST' : 'NOEXIST',
        join(',', (map { ($platforms{$_} ? '' : '!') . $_ }
                   sort keys %platforms)),
        $self->type(),
        join(',', @features);
}

=back

=head2 Comparators and filters

For the B<$ordinals-E<gt>items> method, there are a few functions to create
comparators based on specific data:

=over 4

=cut

# Go back to the main package to create comparators and filters
package OpenSSL::Ordinals;

# Comparators...

=item B<by_name>

Returns a comparator that will compare the names of two OpenSSL::Ordinals::Item
objects.

=cut

sub by_name {
    return sub { $_[0]->name() cmp $_[1]->name() };
}

=item B<by_number>

Returns a comparator that will compare the ordinal numbers of two
OpenSSL::Ordinals::Item objects.

=cut

sub by_number {
    return sub { $_[0]->number() <=> $_[1]->number() };
}

=item B<by_version>

Returns a comparator that will compare the version of two
OpenSSL::Ordinals::Item objects.

=cut

sub by_version {
    sub _ossl_versionsplit {
        my $textversion = shift;
        my ($major,$minor,$edit,$patch) =
            $textversion =~ /^(\d+)_(\d+)_(\d+)([a-z]{0,2})$/;
        return ($major,$minor,$edit,$patch);
    }

    return sub {
        my @a_split = _ossl_versionsplit($_[0]->version());
        my @b_split = _ossl_versionsplit($_[1]->version());
        my $verdict = 0;
        while (@a_split) {
            if (scalar @a_split == 1) {
                $verdict = $a_split[0] cmp $b_split[0];
            } else {
                $verdict = $a_split[0] <=> $b_split[0];
            }
            shift @a_split;
            shift @b_split;
            last unless $verdict == 0;
        }
        $verdict;
    };
}

=back

There are also the following filters:

=over 4

=cut

# Filters...  these are called by grep, the return sub must use $_ for
# the item to check

=item B<f_version VERSION>

Returns a filter that only lets through symbols with a version number
matching B<VERSION>.

=cut

sub f_version {
    my $version = shift;

    $version =~ s|\.|_|g if $version;
    croak "No version specified"
        unless $version && $version =~ /^\d_\d_\d[a-z]{0,2}$/;

    return sub { $_[0]->version() eq $version };
}

=back

=head1 AUTHORS

Richard Levitte E<lt>levitte@openssl.orgE<gt>.

=cut

1;
