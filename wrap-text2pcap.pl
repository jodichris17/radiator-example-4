#!/usr/bin/perl

# $Id$

=head1 NAME

wrap-text2pcap.pl - wrapper around C<text2pcap> and C<mergecap>

=head1 SYNOPSIS

A wrapper to transform text2pcap formatted txt files into proper C<.pcap> files.

  wrap-text2pcap -w outfile < messagelog-radius-text2pcap

=cut

use strict;
use warnings;

use File::Temp;
use File::Copy;
use Getopt::Std;

my $VERSION = '$Revision$';
my $DEBUG   = 0;

#############
# option processing
my %opts;
getopts( 'dw:', \%opts )
  or usage();

$DEBUG++ if $opts{d};

my $output_file = $opts{w}
  or usage('ERR: missing outfile');

die "STOPPED: outfile '$output_file' already exists and is not empty,"
  if -e -s $output_file;

#############
# script global variables

# current number of processed packet
my $pkt_counter = 0;

# current number of bytes in stash
my $bytes_in_stash = 0;

# stash to save the packets, keys are the different directives
# like '-t %s. -i 17 -4 17.12.246.54,193.60.1.8 -u 1645,1812'
my %stash;

# max number of different directives before flushing
my $FLUSH_MAX_DIFFERENT = 500;

# max number of MBytes before flushing
my $FLUSH_MAX_BYTES = 10 * 1024 * 1024;

#
# We write all packets with text2pcap in a tmp_dir.
# We can't just run text2pcap over the MessageLog
# file as a whole, since text2pcap doesn't honor
# the per packet directive for timestamp, IP addresses, ...
#
# Example text2pcap directive from MessageLog:
#
# ##TEXT2PCAP -t %s. -i 17 -4 17.12.246.54,193.60.1.8 -u 1645,1812
#
my $tmp_dir = File::Temp->newdir( CLEANUP => 1 )
  or die "Can't create temp dir: $!,";

###
# parse ##TEXT2PCAP directive and the following packet until eof from STDIN

my ( $directive, $packet );
while ( my $line = <> ) {

    # strip leading and trailing whitespace except of line ending newline
    $line =~ s/^\s+//g;
    $line =~ s/\s+$/\n/g;

    # find a proper packet border and TEXT2PCAP directive line
    if ( $line =~ m/^#+\s*TEXT2PCAP\s+(.+)\s*$/ ) {
        $directive = $1;
        next;
    }

    # rest of lines that start with # are treated as comments
    next if $line =~ /^#/;

    $packet = $line;

    # save and process later all packets with identical directive together
    $stash{$directive} .= $packet;

    # do some bookkeeping
    $pkt_counter++;
    $bytes_in_stash += length($packet);

    if (   ( scalar keys %stash >= $FLUSH_MAX_DIFFERENT )
        || ( $bytes_in_stash >= $FLUSH_MAX_BYTES ) )
    {

        flush_stash();
    }
}

# flush the rest
flush_stash();

warn "DEBUG: processed $pkt_counter packets\n" if $DEBUG;

exit 0;

###############################################################

sub flush_stash {

    warn "DEBUG: packet counter is at: $pkt_counter\n" if $DEBUG;
    warn "DEBUG: bytes in stash: $bytes_in_stash\n"    if $DEBUG;
    warn "DEBUG: directives in stash: " . ( scalar keys %stash ) . "\n" if $DEBUG;

    ###
    # run text2pcap for the packets in stash
    #
    # text2pcap needs a file as input:
    # we use a new tmp_file for each directive, it gets destroyed at out of scope,
    #
    my $iter;
    foreach my $directive ( keys %stash ) {
        $iter++;

        my $tmp_file = File::Temp->new()
          or die "Can't create temp file: $!,";

        # write packets with same directive to tmp_file
        print $tmp_file $stash{$directive};

        # output file to tmp_dir
        my $output = "$tmp_dir/text2pcap.$iter";

        warn "DEBUG: run text2pcap with '$directive'\n" if $DEBUG;

        # Strip whitespace and split directive to separate arguments
        my @directive = split(" ", $directive);

        # don't be quiet if you need more process info
        my @cmd;
        if ($DEBUG) {
            @cmd = ('text2pcap',  @directive, "$tmp_file", "$output");
        }
        else {
            @cmd = ('text2pcap', '-q', @directive, "$tmp_file", "$output");
        }
        system(@cmd) == 0 or die "system text2pcap failed: $?,";
    }

    ###
    # run mergecap for these files

    my $glob_str = "$tmp_dir/text2pcap.*";
    my @files2merge = glob($glob_str) or return;

    # QUIRKS: mergecap(1) must be called in stages (Too many open files).
    # merge in output file from prior flushes
    if ( -e -s $output_file ) {

        # mergecap creates or truncates output file
        # save old output file from prior flush
        copy($output_file, "$output_file.tmp") or die "copy failed: $!\n";

        # and add output file from prior flush to the files to merge
        push @files2merge, "$output_file.tmp";
    }

    warn "DEBUG: run mergecap for " . ( scalar @files2merge ) . " files\n" if $DEBUG;

    # mergecap creates or truncates output file

    # be verbose if you need more process info
    my @cmd;
    if ($DEBUG) {
        @cmd = ("mergecap", "-v", "-w", "$output_file", @files2merge);
    }
    else {
        @cmd = ("mergecap", "-w", "$output_file", @files2merge);
    }

    system(@cmd) == 0 or die "mergecap failed: $?,";

    ### housekeeping
    # delete all merged packet files

    unlink @files2merge or die "ERR: failed to unlink some files: $?,";

    # reset stash
    undef %stash;
    undef $bytes_in_stash;
}

sub usage {
    my @msg = @_;
    die <<EOT;
@msg

Usage: $0 [-d] -w outfile <messagelog-radius-text2pcap
	-w	outfile
	[-d]	debug
EOT
}

=head1 DESCRIPTION

RADIATOR is able to write packet loggs in text2pcap format as input for the C<text2pcap> utility. RADIATOR puts option hints for I<timestamp>, I<protocol>, I<ip addresses> and I<port numbers> in front of each packet line, but C<text2pcap> does not parse these directives yet.

C<wrap-text2pacp> splits the text2pcap file in packets, calls C<text2pcap> for the packets with the same per packet directives and calls C<mergecap> to produce again one single file, now in C<.pcap> format ready as input for wireshark.

=head1 AUTHOR

Karl Gaissmaier <karl.gaissmaier at uni-ulm.de>

=head1 COPYRIGHT & LICENSE

This software is copyright (c) 2017 by Karl Gaissmaier.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

Terms of the Perl programming language system itself

a) the GNU General Public License as published by the Free
   Software Foundation; either version 1, or (at your option) any
   later version, or
b) the "Artistic License"

=cut

# vim: sw=4

