### Nagios Bulk Import (nbi.pl)
#
#This perl script will take a nmap generated "grepable" file and create a host file for nagios
# nmap <IP Range> -s[S|T|A|W] -O -oG <FILENAME>
# ./nbi.pl <FILENAME>
# You need to add the service.cfg, command.cfg & the hostgroups.cfg below to your existing files
# 
# Created on Jan 16, 2012 by ldecker (ldecker@gmail.com)
# License: GPL
# No warranties in any way given.
# 
# CHANGELOG
# Revision 1.0  2012/01/16 14:46:05 ldecker
# initial version
# 
# 
# 
# 


use strict;
use warnings;

my(@dataseg, @tempseg, $recfile, $recline, $out1, $elem, $i, $portflg, $osflg);
my($hostname, $hostaddr, $hostos, $hostgrps, $openptrport, $tempfile, $outhost);

sub init
{
 if( $#ARGV eq -1)
 {
  print "nbi.pl <(nmap <IP Range> -s[S|T|A] -O -oG) INPUT FILE>\n";
  exit;
 }
 else
 {
  $recfile=$ARGV[0];
  $outhost="hosts.cfg";
  $tempfile="tempfile$$";
  system("rm $outhost tempfile*");
# This grep statement removes all the single "Up" lines and replaces the () with ^ so the hostname will equal the hostIP - there was no DNS entry
  system("grep -v Up $recfile | sed  \"s/\(\)/^/g\"  | sed  \"s/\(//g\" | sed \"s/\)//g\" | sed \"s/\\//\|/g\" | sed \"s/\|\|\|/\|/g\" | sed \"s/\|\|/\|/g\"  | sed \"s/\t/ /g\" | grep -i -v nmap > $tempfile");
 }
}

sub read_nmap
{
 open(OUTHOST,"> $outhost");
 open(RECFILE,"< $tempfile");
 while($recline=<RECFILE>)
{
  if(length($recline)>0)
  {
   chomp($recline);
   @dataseg = split(/ /,$recline);
   $elem = @dataseg;
   $openptrport=0;
   $portflg=0;
   $osflg=0;
   $hostgrps="";
   $hostos="";
   $hostaddr=$dataseg[1];
# Set the hostname equal to the hostIP - there was no DNS entry
   $hostname=($dataseg[2] eq '^')?$dataseg[1]:$dataseg[2];
   for($i=2;$i<$elem;$i++)
   {
    if($dataseg[$i] eq "Ports:") { $osflg=0;$portflg=1; }
    elsif($dataseg[$i] eq "OS:") { $portflg=0;$osflg=1; }
    elsif($portflg)
    {
     if($dataseg[$i] =~ /open/)
     {
      @tempseg = split(/\|/,$dataseg[$i]);
# This switch block is used to setup the hostgroup membership based on the ports that were
# found open during the nmap run
      SWITCH: {
      if ($tempseg[0] eq 21)   { $hostgrps = $hostgrps."ftp, "; last SWITCH; }
      if ($tempseg[0] eq 22)   { $hostgrps = $hostgrps."ssh, "; last SWITCH; }
      if ($tempseg[0] eq 23)   { $hostgrps = $hostgrps."telnet, "; last SWITCH; }
      if ($tempseg[0] eq 25)   { $hostgrps = $hostgrps."smtp, "; last SWITCH; }
      if ($tempseg[0] eq 53)   { $hostgrps = $hostgrps."dns, "; last SWITCH; }
      if ($tempseg[0] eq 80)   { $hostgrps = $hostgrps."http, "; last SWITCH; }
      if ($tempseg[0] eq 443)  { $hostgrps = $hostgrps."https, "; last SWITCH; }
      if ($tempseg[0] eq 515)  { $hostgrps = $hostgrps."lpd, "; last SWITCH; }
      if ($tempseg[0] eq 631)  { $hostgrps = $hostgrps."ipp, "; last SWITCH; }
      if ($tempseg[0] eq 1433) { $hostgrps = $hostgrps."mssql, "; last SWITCH; }
      if ($tempseg[0] eq 3306) { $hostgrps = $hostgrps."mysql, "; last SWITCH; }
      if ($tempseg[0] eq 3389) { $hostgrps = $hostgrps."termsrv, "; last SWITCH; }
# Remd this port out until I can test correctly VNC
#      if ($tempseg[0] =~/5900/) { $hostgrps = $hostgrps."vnc, "; last SWITCH; }
# Put a switch here because windows shows 9100 port open but I couldn't get an answer
      if ($tempseg[0] =~/9100/) { $openptrport=1; last SWITCH; }
# Template
#      if ($tempseg[0] =~/<port>/) { $hostgrps = $hostgrps."<hostgroupname "; last SWITCH; }
      }
     }   
    }
    elsif($osflg)
    {
     if($dataseg[$i] =~ /Linux|HP-UX|NetBSD|Solaris/i) { $hostos="linux-server"; $hostgrps = $hostgrps."linux "; $osflg=0; }
     elsif($dataseg[$i] =~ /Microsoft/i)               { $hostos="windows-server"; $hostgrps = $hostgrps."windows "; $osflg=0; }
     elsif($dataseg[$i] =~ /Cisco/i)                   { $hostos="generic-switch"; $hostgrps = $hostgrps."switches "; }
     elsif($dataseg[$i] =~ /Aironet/i)                 { $hostos="generic-switch"; $hostgrps = "aironet, switches "; $osflg=0; }
     elsif($dataseg[$i] =~ /printer/i)                 { $hostos="generic-printer";$hostgrps = $openptrport ? $hostgrps."jdir, printers ": $hostgrps."printers "; $osflg=0; }
     elsif($dataseg[$i] =~ /APC/i)                     { $hostos="generic-device"; $hostgrps = $hostgrps."ups "; $osflg=0; }
     elsif($dataseg[$i] =~ /:/)                        { $osflg=0; }
    }
   }
# Default host OS if no host OS was found
  
  }
 }
 close(OUTHOST);
 close(RECFILE);
}

&init;
&read_nmap;













