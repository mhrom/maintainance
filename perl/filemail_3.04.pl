#!/usr/bin/perl -w
# @(#) filemail.pl	Email utility for large binary files.
#			Version 3.04, 2011-11-29.
#
# Copyright (c) 2005 Graham Jenkins <grahjenk@cpan.org>. All rights reserved.
# This program is free software; you can redistribute it and/or modify it under
# the same terms as Perl itself.

use strict;
use File::Basename;
use Sys::Hostname;
use Socket;
use Net::Config;
use Net::SMTP;
use MIME::Base64;
my $PSize = 700;	# Default (input) part-size.
my ($Count,$Sum,$Size,$Total,$InpBuf,$InpLen,$OutBuf,$j,$PriBuf,@Fqdn,@Hosts);
if ($#ARGV ge 0) { if ($ARGV[0] =~ m/^-\d+$/ ) { $PSize=0-$ARGV[0]; shift } } 

die "Usage: cat file  |".basename($0)." [-KbPerPart] filename addr1 [addr2..]".
    "\n e.g.: tar cf - .|".basename($0)." -64 mydir.tar smith\@popser.acme.com".
    "\n(Note: default un-encoded part size = $PSize","kb)\n"  if ($#ARGV lt 1);
die "No SMTP Hosts defined!\n" if ! (@Hosts=@{$NetConfig{smtp_hosts}});
die "Can't read input!\n"      if ! open(INFILE,"-");
die "Can't determine FQDN!\n"  if ! (@Fqdn=gethostbyaddr(inet_aton(hostname),
                                                                     AF_INET));
my $Fname=$ARGV[0]; shift;
my $List= $ARGV[0]; for (my $k=1;$k<=$#ARGV;$k++) {$List.=", $ARGV[$k]"}
my $logname=$ENV{LOGNAME} || $ENV{USER} || "root";

binmode INFILE;
$Count=0; $Total="";   # Loop until no further input available.

do { $InpLen = read(INFILE, $InpBuf, 1024 * $PSize);
     $Total  = $Count if $InpLen lt 1;
     do { $Size = length($OutBuf);
          print STDERR "$Fname part $Count/$Total, $Size bytes => $List\n";
          $Sum  = unpack("%32C*", $OutBuf);
          foreach $j (1,2) {$Sum = ($Sum & 0xffff) + int($Sum/0x10000)}
          $j = $Count ; while (length($j) < 3 ) { $j = "0" . $j }
          $j = dirname($Fname)."/".$j if dirname($Fname) ne "."; 
          $j =$j."_".basename($Fname);
          $PriBuf="Subject: ".
            "$Fname part $Count/$Total size/sum $Size/$Sum\n".
            "To: $List\n".
            "MIME-Version: 1.0\n".
            "Content-Type: multipart/mixed; boundary=\"--=_$$\"\n".
            "Content-Transfer-Encoding: 8bit\n\n".
            "----=_$$\n".
            "Content-Type: application/octet-stream; name=\"$j\"\n".
            "Content-Transfer-Encoding: base64\n".
            "Content-Disposition: attachment; filename=\"$j\"\n\n";
          foreach my $Host (@Hosts) {
            my $smtp;
            if (($smtp=Net::SMTP->new($Host))                               &&
                 $smtp->mail($logname."\@".$Fqdn[0])                        &&
                 $smtp->to(@ARGV,{SkipBad=>1})                              &&
                 $smtp->data($PriBuf.encode_base64($OutBuf)."\n----=_$$\n") &&
                                            $smtp->quit ) { $PriBuf=""; last } 
          }
          die "Failed!\n" if length($PriBuf) > 0
                                                        } if $Count gt 0;
     $Count++; $OutBuf = $InpBuf                          } until $InpLen lt 1;

exit 0
__END__

=head1 NAME

filemail - an email utility for large binary files

=head1 README

filemail breaks an input stream into parts, then encodes
each part and emails it to designated recipients.

=head1 DESCRIPTION

This is a simple utility for emailing large
binary files. An input stream is broken into parts,
and each part is encoded for transmission to
one or more email addresses.

Base64 encoding is used for efficiency, and
an option is available to change the default part
size.

=head1 USAGE

=over 4

filemail [-part_size] file_name addr1 [addr2..]

=back

By default, the input stream is broken into parts of size
700kb. This can be adjusted by specifying a part-size
on the command line (e.g. -500 for a 500kb part-size).

Each part is then named by prepending "001_", "002_", etc. to
the basename of the designated file-name, and encoded for
transmission.

A list of SMTP servers is determined using Net::Config and
each is tried in turn if necessary.

The recipients can recover the original data stream by
decoding each part, then concatenating the parts.

=head1 SCRIPT CATEGORIES

UNIX/System_administration
Networking

=head1 AUTHOR

Graham Jenkins <grahjenk@cpan.org>

=head1 COPYRIGHT

Copyright (c) 2005 Graham Jenkins. All rights reserved.
This program is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=cut
