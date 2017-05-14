#!/usr/bin/perl
# USAGE
#	perl open-port-xml-1.2.pl
# SEE ALSO
#
#   perldoc open-port-xml-1.2.pl


use XML::Smart;

#/proc files to get data
$PROC_TCP="/proc/net/tcp";
$PROC_UDP="/proc/net/udp";
$OUTPUT = "data.xml";

my $xml = XML::Smart->new() ;
$xml->{"TCP"}->set_node(1);

my @tcp = read_file($PROC_TCP);
my @udp = read_file($PROC_UDP);

get_ports('TCP',@tcp);
get_ports('UDP',@udp);

$xml->save($OUTPUT) ;

sub get_ports
{
   my($proto,@lines) = @_;
   foreach $line (@lines)
    {
     my($dump,$sl,$local_address,$rem_address,$st,$rx_queue,$tr,$retrnsmt,$uid,$timeout,$inode,$inodeid) = split(/\s+/,$line);
     if($sl eq "sl") { next;};

     if(!($inode eq "0"))
        {
          my($l_ip,$l_port) = hextoip($local_address);
          my $PID = get_pid_of_inode($inode);
          my $portdata = {
			  Port     => "$l_port" ,
			  IP    => "$l_ip" ,
			  UID   => "$uid",
			  inode => "$inode",
                          PID   => $PID,
			  Exe   => get_process_exe_path($PID)
			  } ;
          push(@{$xml->{$proto}{Listener}}, $portdata);
#         print "UID: $uid IP: $l_ip, port: $l_port : $inode_id\n";        
        }
    }
}



sub read_file
{
  my($file) = @_;
  open(FILE, $file);
  my @lines = <FILE>;
  close(FILE);
  return @lines;
}


sub hextoip
{
 my($hexvalue) = @_;
 my($hexip,$hexport) = split(/\:/,$hexvalue);
 my $port = hex($hexport);
 my $ipvalue = hexip_to_normalip($hexip);
 return $ipvalue,$port;
}


sub hexip_to_normalip
{
 my($hexvalue) = @_;
 my($h4,$h3,$h2,$h1) = $hexvalue =~ m/([\d.a-f.A-F][\d.a-f.A-F])([\d.a-f.A-F][\d.a-f.A-F])([\d.a-f.A-F][\d.a-f.A-F])([\d.a-f.A-F][\d.a-f.A-F])/;
 my $normal = hex($h1).".".hex($h2).".".hex($h3).".".hex($h4);
 return $normal;
}

sub get_pid_of_inode
{
 my($inode) = @_;
 opendir (PROC, "/proc") || die "proc";
 for $f (readdir(PROC))
 {
     next if (! ($f=~/[0-9]+/) );
     if (! opendir (PORTS, "/proc/$f/fd")) 
     {
  	closedir PORTS;
	next;
     }
    for $g (readdir(PORTS)) 
    {
    next if (! ($g=~/[0-9]+/) );
    $r=readlink("/proc/$f/fd/$g");
    ($dev,$ino)=($r=~/^(socket|\[[0-9a-fA-F]+\]):\[?([0-9]+)\]?$/);
    if (($dev == "[0000]" || $dev == "socket") && $ino eq $inode) 
	{
	  closedir PORTS;
	  closedir PROC;
          return $f;
        }
	    closedir PORTS;
	}
	closedir PROC;
    }
}

sub get_process_exe_path
{
  my($pid) = @_;
  return readlink("/proc/$pid/exe");
}

__END__

=head1 NAME

open-port-xml-1.2.pl - Get open ports informatio in xml format

=head1 SCRIPT CATEGORIES

Networking

=head1 README

This script retrive the information of Listening ports and save the information in xml format.


=head1 OSNAMES

Linux

=head1 PREREQUISITES

C<XML::Smart>

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
