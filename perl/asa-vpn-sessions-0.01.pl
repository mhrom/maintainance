#!/usr/bin/perl

=head1 NAME

  asa-vpn-sessions

=head1 SYNOPSIS

 asa-vpn-sessions [-d] [-h] [-l] [-u user] [-i ip-addr]

=cut

use strict;
use warnings;

#################### ATTENTION #########################
# cfg data, must be changed
########################################################
#
our $ASA   = 'my.asa.com';
our $OPER  = 'operator';
our $PASS  = '********';
#
########################################################

our $VERSION = 0.01;

use Pod::Usage qw(pod2usage);
use Getopt::Std qw(getopts);
use LWP::UserAgent qw();

our $IP_SEC_CLIENT_URL = "https://$OPER:$PASS\@$ASA/"
  . "admin/exec/show%20vpn-sessiondb%20detail%20full%20remote";

our $IP_SSL_CLIENT_URL = "https://$OPER:$PASS\@$ASA/"
  . "admin/exec/show%20vpn-sessiondb%20detail%20full%20svc";

our $DEBUG = 0;

our %opts;
pod2usage( -exitval => 1, -verbose => 1 )
  unless getopts( 'dhlu:i:', \%opts );

pod2usage(
  -exitval => 1,
  -verbose => 1,
  -message => 'options u and i are exclusive'
) if $opts{'u'} && $opts{'i'};

pod2usage( -exitval => 0, -verbose => 2 )
  if $opts{'h'};

$DEBUG = 1 if $opts{'d'};

# fetch the vpn client infos unparsed from the ASA
our @ip_sec_clients = fetch_url($IP_SEC_CLIENT_URL);
our @ip_ssl_clients = fetch_url($IP_SSL_CLIENT_URL);

if ($DEBUG) {
  warn join( "\n", @ip_sec_clients ), "\n\n";
  warn join( "\n", @ip_ssl_clients ), "\n\n";
}

our $stash;
our $users;
our $addrs;

parse_all( @ip_sec_clients, @ip_ssl_clients );

if ( $opts{'i'} or $opts{'u'} ) {
  list_session();
}
else {
  list_all_sessions();
}

exit 0;

############################################################
# end of main
############################################################

sub fetch_url {
  my $url = shift or die "Internal error, missing arg,";

  my $ua = LWP::UserAgent->new( timeout => 5, requests_redirectable => [] )
    or die "Can't create LWP UA object,";

  my $response = $ua->get($url);

  unless ( $response->is_success ) {
    die "Error fetching URL from ASA: ", $response->status_line, "\n";
  }

  return split /\n/, $response->content;
}

sub parse_all {
  my @lines = @_;

  foreach my $line (@lines) {

    # skip lines without usefull info
    next if $line =~ m/^\s*$/;
    next if $line =~ m/^\s*INFO:/;
    next if $line =~ m/^\s*Type: NAC/;
    next if $line =~ m/^\s*Session Type:/;
    next if $line =~ m/^\s*IKE Tunnels:/;
    next if $line =~ m/^\s*Clientless Tunnels:/;

    parse_session($line)   && next if $line =~ m/^\s*Session ID:/;
    parse_ike($line)       && next if $line =~ m/^\s*Type: IKE/;
    parse_ipsecnatt($line) && next if $line =~ m/^\s*Type: IPsecOverNatT/;
    parse_ipsectcp($line)  && next if $line =~ m/^\s*Type: IPsecOverTCP/;
    parse_ipsec($line)     && next if $line =~ m/^\s*Type: IPsec/;
    parse_webvpn($line)    && next if $line =~ m/^\s*Type: Clientless/;
    parse_ssl($line)       && next if $line =~ m/^\s*Type: SSL-Tunnel/;
    parse_dtls($line)      && next if $line =~ m/^\s*Type: DTLS-Tunnel/;

    warn "Can't parse this line:\n";
    warn $line;
  }
}

sub parse_session {
  my $line = shift;

  my $session_stash = split_line($line);

  my $session_id = $session_stash->{'session id'}
    or die "Can't parse unique Session ID!\n";

  my $user = $session_stash->{'username'}
    or die "Can't parse Username!\n";

  my $ip = $session_stash->{'ip addr'}
    or die "Can't parse IP Addr!\n";

  $stash->{$session_id}{'session'} = $session_stash;

  # cache user->sessid und ip->session for easy access
  $users->{$user} = $session_id;
  $addrs->{$ip}   = $session_id;

  return 1;
}

sub parse_ike {
  my $line = shift;

  my $ike_stash = split_line($line);

  my $session_id = $ike_stash->{'tunnel id'}
    or die "Can't parse unique Session ID!\n";

  # cut off the sub-session id from session-id
  $session_id =~ s/\.\d+//;

  $stash->{$session_id}{'ike'} = $ike_stash;

  return 1;
}

sub parse_ipsec {
  my $line = shift;

  my $ipsec_stash = split_line($line);

  my $session_id = $ipsec_stash->{'tunnel id'}
    or die "Can't parse unique Session ID!\n";

  # cut off the sub-session id from session-id
  $session_id =~ s/\.\d+//;

  $stash->{$session_id}{'ipsec'} = $ipsec_stash;

  return 1;
}

sub parse_ipsecnatt {
  my $line = shift;

  my $ipsecnatt_stash = split_line($line);

  my $session_id = $ipsecnatt_stash->{'tunnel id'}
    or die "Can't parse unique Session ID!\n";

  # cut off the sub-session id from session-id
  $session_id =~ s/\.\d+//;

  $stash->{$session_id}{'ipsecnatt'} = $ipsecnatt_stash;

  return 1;
}

sub parse_ipsectcp {
  my $line = shift;

  my $ipsectcp_stash = split_line($line);

  my $session_id = $ipsectcp_stash->{'tunnel id'}
    or die "Can't parse unique Session ID!\n";

  # cut off the sub-session id from session-id
  $session_id =~ s/\.\d+//;

  $stash->{$session_id}{'ipsectcp'} = $ipsectcp_stash;

  return 1;
}

sub parse_webvpn {
  my $line = shift;

  my $webvpn_stash = split_line($line);

  my $session_id = $webvpn_stash->{'tunnel id'}
    or die "Can't parse unique Session ID!\n";

  # cut off the sub-session id from session-id
  $session_id =~ s/\.\d+//;

  $stash->{$session_id}{'webvpn'} = $webvpn_stash;

  return 1;
}

sub parse_ssl {
  my $line = shift;

  my $ssl_stash = split_line($line);

  my $session_id = $ssl_stash->{'tunnel id'}
    or die "Can't parse unique Session ID!\n";

  # cut off the sub-session id from session-id
  $session_id =~ s/\.\d+//;

  $stash->{$session_id}{'ssl'} = $ssl_stash;

  return 1;
}

sub parse_dtls {
  my $line = shift;

  my $dtls_stash = split_line($line);

  my $session_id = $dtls_stash->{'tunnel id'}
    or die "Can't parse unique Session ID!\n";

  # cut off the sub-session id from session-id
  $session_id =~ s/\.\d+//;

  $stash->{$session_id}{'dtls'} = $dtls_stash;

  return 1;
}

sub split_line {
  my $line = shift;

  # fix bloody Cisco errors, missing the ':' between key and val
  $line =~ s/Assigned IP /Assigned IP: /;

  $line =~ s/UDP Source Port /UDP Source Port: /;
  $line =~ s/UDP Destination Port /UDP Destination Port: /;

  $line =~ s/TCP Src Port /TCP Src Port: /;
  $line =~ s/TCP Dst Port /TCP Dst Port: /;

  # remove trailing '||'
  $line =~ s/\|\| \s* $//x;

  # split the records into columns at the '|'
  my @columns = split /\|\s+/, $line;

  my $column_stash = {};

  # split the columns into (k,v) tuples at the ':'
  foreach my $column (@columns) {
    my ( $key, $val ) = split /:\s+/, $column;

    next unless defined $key;
    warn "split error for key: '$key'\n" unless defined $val;

    # trim
    $key =~ s/^\s*|\s*$//g;
    $val =~ s/^\s*|\s*$//g;

    # normalize
    $key = lc $key;

    $column_stash->{$key} = $val;
  }

  return $column_stash;
}

sub list_all_sessions {
  foreach my $session ( sort keys %$stash ) {
    print_session($session);
  }
}

sub list_session {

  my $lookup_user = $opts{'u'};
  my $lookup_ip   = $opts{'i'};

  if ($lookup_ip) {
    foreach my $ip ( sort keys %$addrs ) {
      print_session( $addrs->{$ip} ) if $ip =~ m/^\Q$lookup_ip\E$/i;
    }
  }
  elsif ($lookup_user) {
    foreach my $user ( sort keys %$users ) {
      print_session( $users->{$user} ) if $user =~ m/\Q$lookup_user\E/i;
    }
  }
}

sub print_session {
  my $id = shift;

  printf "%-14s <- %-15s %-14s %s\n",
    $stash->{$id}{'session'}{'ip addr'},
    $stash->{$id}{'session'}{'public ip'},

       $stash->{$id}{'ipsec'}{'type'}
    || $stash->{$id}{'ipsecnatt'}{'type'}
    || $stash->{$id}{'ipsectcp'}{'type'}
    || $stash->{$id}{'dtls'}{'type'}
    || $stash->{$id}{'ssl'}{'type'}
    || $stash->{$id}{'webvpn'}{'type'},

    $stash->{$id}{'session'}{'username'};

  if ( $opts{'l'} ) {

    printf " SESSION: %-16s %-21s Bytes rx/tx: %d/%d\n",
      $stash->{$id}{'session'}{'group'},
      $stash->{$id}{'session'}{'duration'},
      $stash->{$id}{'session'}{'bytes rx'},
      $stash->{$id}{'session'}{'bytes tx'},
      ;

    printf "   IPSEC: %-16s %-21s %s\n", $stash->{$id}{'ipsec'}{'type'}
      || $stash->{$id}{'ipsecnatt'}{'type'}
      || $stash->{$id}{'ipsectcp'}{'type'},
      $stash->{$id}{'ike'}{'client os type'},
      $stash->{$id}{'ike'}{'client os ver'},
      if $stash->{$id}{'ike'};

    printf "    DTLS: %-16s %-21s %s\n",
      $stash->{$id}{'dtls'}{'encapsulation'},
      $stash->{$id}{'dtls'}{'client type'},
      $stash->{$id}{'dtls'}{'client ver'},
      if $stash->{$id}{'dtls'};

    print "\n";
  }
}

=head1 OPTIONS

    -h			help
    -d  		debug
    -l  		long listing

    -i  ip-addr		client ip address
    -u  username	substring allowed

=head1 README

A script to list the Cisco-ASA vpn-sessions

At time of writing (8/2010), the ASA has a faulty SNMP implementation for the CISCO-REMOTE-ACCESS-MONITOR-MIB. This script fetches the session tables via https:

  https://oper:pass@my.asa/admin/exec/show%20vpn-sessiondb ...

=head1 PREREQUISITES

This script requires the C<LWP::UserAgent> module with SSL support.

=head1 SCRIPT CATEGORIES

Networking

=head1 SECURITY

This script doesn't verify the ASAs SSL certificate. Add the verification or use it with a low-privileged operator account only.

The following configuration enables a low-privileged operator account for http access:

=over

=item * add a low-privileged LOCAL operator account

  asa(config)# username operator password ******** privilege 1

=item * enable LOCAL http authentication

  asa(config)# aaa authentication http console LOCAL 

=item * enable LOCAL command authorization

  asa(config)# aaa authorization command LOCAL

=item * reduce the needed privilege for show vpn-sessiondb

  asa(config)# privilege show level 0 mode exec command vpn-sessiondb

=item * enable the http server for ASDM management

  asa(config)# http server enable

=item * allow your monitoring hosts

  asa(config)# http your.ip.address your.netmask your-mgmt-if

=back

=head1 AUTHOR

Karl Gaissmaier, gaissmai (at) cpan.org

=head1 COPYRIGHT

Copyright (C) 8/2010 by Karl Gaissmaier

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

# vim: sw=2
