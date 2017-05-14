#!/usr/bin/perl
# USAGE
#       mkfifo /var/log/auth.info.pipe
#
#     - FOR SYSLOG (Centos,FC,debian,Mandrake,Ubuntu)
#       Edit syslog.conf and put below line
#	auth.info       |/var/log/auth.info.pipe
#       
#     - FOR SYSLOG-NG (Gentoo)      
#       Edit syslog-ng.conf and put below lines
#       destination authlog { pipe("/var/log/auth.info.pipe"); };
#       filter f_auth { facility(auth); };
#       filter f_info { level(info..emerg); };
#       log { source(src); filter(f_auth); filter(f_info); destination(authlog); };
#
#       EDIT THE SCRIPT TO SPECIFY the log pipe and threshold of login attempts
#	To run:  ssh-anti-brute-1.3.pl& OR csh -cf 'perlssh-anti-brute-1.3.pl&'
#       And leave it running
#
# IMPORTANT
#       On some Linux distros ssh log the hostnames and not ips. To avoid this ....
#       Make sure /etc/ssh/sshd_config has this  'UseDNS no' Or put it there and restart sshd
#  
#  
# SEE ALSO
#
#   perldoc ssh-anti-brute-1.2.pl

#Automatically block ips attempting ssh brute force

#Pipe configured in syslog
 my $pipe = "/var/log/auth.info.pipe";
#Numper of attemtps to block
 my $threshold = 3;
 my $debuging = 1;
 my $debugfile = "/var/log/ssh-anti-brute.log";

#Nothing configureable below
my $failedstring;
my $acceptedstring;

$failedstring = "Failed password" if(-e "/etc/mandrakelinux-release");
$failedstring = "Failed password" if(-e "/etc/redhat-release");
$failedstring = "Authentication failure" if(-e "/etc/gentoo-release");
$failedstring = "Authentication failure" if(-e "/etc/debian_version");

$acceptedstring = "Accepted password" if(-e "/etc/mandrakelinux-release");
$acceptedstring = "Accepted password" if(-e "/etc/redhat-release");
$acceptedstring = "Accepted" if(-e "/etc/gentoo-release");
$acceptedstring = "Accepted" if(-e "/etc/debian_version");

logit("Failed string to monitor is: $failedstring") if($debuging == 1);
logit("Accepted password string to monitor is: $acceptedstring") if($debuging == 1);


my %ips;
open(FIFO,"<$pipe");
while(my $line = <FIFO>)
  {
      if($line =~ /$failedstring/)
        {
            my ($a) = ( $line =~  m/(\d+\.\d+\.\d+\.\d+)\s/ );
            getit($a);
        }elsif($line =~ /$acceptedstring/)
        {
            my ($a) = ( $line =~  m/(\d+\.\d+\.\d+\.\d+)\s/ );
            releaseit($a);
            logit("$a Password Accepted.") if($debuging == 1);
        }
   }
close(FIFO);

sub getit
{
  my($ip) = @_;
   if($ips{$ip} > 0)
    {
       $ips{$ip} = $ips{$ip} + 1;
    }else
    {
       $ips{$ip} = 1;
    }
    if($ips{$ip} > $threshold)
     {
       `iptables -A INPUT -p tcp -s $ip --dport 22 -j DROP`;
        releaseit($ip);
        logit("$ip Blocked") if($debuging == 1);
        return;
     }
    logit("$ip Attempt $ips{$ip}") if($debuging == 1);
}

sub releaseit
{
  my($ip) = @_;
  delete($ips{$ip});
}


sub logit
{
 my($str) = @_;
 open(DAT,">>$debugfile") || die("Cannot Open Debuging Log File");
 print DAT $str . "\n";
 close(DAT);
}

=head1 NAME

ssh-anti-brute-1.3.pl - Automatically block ips attempting ssh brute force

=head1 SCRIPT CATEGORIES

Networking

=head1 README

This script read a named pipe which is configured in syslog for auth.info and block the ips trying to bruteforce ssh.


=head1 OSNAMES

Centos,Redhat,Mandriva,Fedora

=head1 PREREQUISITES
   A named pipe must be configured in syslog to receive auth.info
   iptables must be installed

=head1 COREQUISITES

=head1 SYNOPSIS

=head1 AUTHOR

Jamshaid Faisal

 { 
   domain   => "gmail", 
   tld      => "com", 
   username => "j.faisal" 
 }

=cut
