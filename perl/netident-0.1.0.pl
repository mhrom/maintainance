#!/usr/bin/perl
#Copyright (c) 2008, Zane C. Bowers
#All rights reserved.
#
#Redistribution and use in source and binary forms, with or without modification,
#are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
#INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
#BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
#DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
#THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use Getopt::Std;
use IO::Socket;
use IO::Interface;
use Net::CIDR::Lite;
#use Net::DHCPClient;

#print version
sub main::VERSION_MESSAGE {
	print "netident 0.1.0\n";
};

#exit after printing help or version
$Getopt::Std::STANDARD_HELP_VERSION="TRUE";

#print help
sub main::HELP_MESSAGE {
	print "-f <file>   The file to use.\n".
			"-d <test file dir>   The directory with test files in it to run.\n".
			"-F <flag dir>   The directory to use that contains the flag files.\n".
			"-h   Print this\n.".
			"-v   Print the version.\n";
	
};

sub runline{
	my $check=$_[0];
	my $expect=$_[1];
	my %args=%{$_[2]};

	my $returned=undef;

	if ($check eq "pingmac"){
		$returned=pingmac(\%args);
	};

	if ($check eq "defgateway"){
		$returned=defgateway(\%args);
	};

	if ($check eq "cidr"){
		$returned=cidr(\%args);
	};

	if ($returned eq $expect){
		return 1;
	};

	return 0;
};

#parse the name line of the file
sub parseName{
	#$_[0]=the first line of a 
	
	my $name=$_[0];

	chomp($name);
	
	my $check=$name;
	if($check =~ s/\///g){
		print "The name contained a /, which is a illegal character.\n";
		exit 1;
	};

	return($name);
};

#parse and run a file
sub runfile{
	#$_[0]=the file
	
	open("thefile", $_[0])||die("Could not open '".$_[0]."'!");
	my @rawdata=<thefile>;
	close("thefile");

	my $name=parseName($rawdata[0]);
	
	my $int=1; #starts at one since line 0 has been hit already
	while(defined($rawdata[$int])){
		my $line=$rawdata[$int];
		chomp($line);
		my @linesplit=split(/\|/, $line);

		my $check=$linesplit[0]; #the check to run
		my $expect=$linesplit[1]; #if true or false should be expected for a test
		
		my %args=();

		#puts a hash of arguements together
		my $argInt=1; #starting at 2 as it is the next in the line
		while(defined($linesplit[$argInt])){
			my @argsplit=split(/=/, $linesplit[$argInt]);
			$args{$argsplit[0]}="";
			
			my $argsAssembleInt=1;
			
			while(defined $argsplit[$argsAssembleInt]){
				#Adds = onto the arg if it is more than one.
				#This is placed here add = back into it and then only after the first one.
				if($argsAssembleInt > 1){
					$args{$argsplit[0]}=$args{$argsplit[0]}."=";
				};
				$args{$argsplit[0]}=$argsplit[$argsAssembleInt];
				
				$argsAssembleInt++;
			};


			
			$argInt++;
		};

		my $lineReturn=runline($check, $expect, \%args);
		
		if(!$lineReturn){
			return (0, $name);
		};

		$int++;
	};
	return (1, $name);
};

#pings a ip address and checks the mac
sub pingmac{
#  my $subargs = { %{$_[0]} };
  my %args= %{$_[0]};

  system("ping -c 1 ".$args{ip}." > /dev/null");
  if ( $? == 0 ){
    my $arpline=`arp $args{ip}`;
    my @a=split(/ at /, $arpline);
    my @b=split(/ on /, $a[1]);
    if ($b[0] eq $args{mac}){
      return "1";
      print "it works\n";
    };
  };

  return "0";
};

#do a default gateway test
sub defgateway{
	my %args= %{$_[0]};
  
  	#gets it and breaks it down to a string
	my @raw=`route get default`;
	my @gateway=grep(/gateway:/, @raw);
	$gateway[0] =~ s/ //g;
	$gateway[0] =~ s/gateway://g;
	chomp($gateway[0]);

	if($args{ip} eq $gateway[0]){
		return 1;
	};

	return "0";
};

#do a default gateway test
sub cidr{
	my %args= %{$_[0]};

	my $cidr = Net::CIDR::Lite->new;
	
	$cidr->add($args{cidr});
	
	my $socket = IO::Socket::INET->new(Proto=>'udp');
	
	my @iflist=$socket->if_list(); 
	
	#if a interface is not specified, make sure it exists
	if(defined($args{if})){
		my $iflistInt=0;#used for intering through @iflist
		while(defined($iflist[$iflistInt])){
			#checks if this is the interface in question
			if($iflist[$iflistInt] eq $args{if}){
				#gets the address
				my $address=$socket->if_addr($args{if});
				#if the interface does not have a address, don't check it
				if(defined($address)){
					#checks this address is with in this cidr
					if ($cidr->find($address)){
						return 1;
					};
				};
			};
			
			$iflistInt++;
		};
		
		#if a specific IP is defined and it reaches this point, it means it was now found
		return "0";
	};

	#if a interface is not specified, make sure it exists
	my $iflistInt=0;#used for intering through @iflist
	while(defined($iflist[$iflistInt])){
		#gets the address
		my $address=$socket->if_addr($iflist[$iflistInt]);
		#if the interface does not have a address, don't check it
		if(defined($address)){
			#checks this address is with in this cidr
			if ($cidr->find($address)){
				return 1;
			};
		};
		$iflistInt++;
	};

	return "0";
};

#holds the config
my %config;

#get the ops
my %opts;
getopts("d:f:F:hv", \%opts);

if (defined($opts{h})){
	&main::VERSION_MESSAGE;
	&main::HELP_MESSAGE;
	exit;
};

if (defined($opts{v})){
	&main::VERSION_MESSAGE;
	exit;
};

#sets the file it will use as the config
if(defined($opts{f})){
	if (defined($opts{d})){
		print "Can't be defined with -d and -f.\n";
	};
	$config{file}=$opts{f};
}else{
	#sets the directory it reads the configs from
	if(!defined($opts{d})){
		$config{dir}="/usr/local/etc/netident/";
		if(!-e $config{dir}){
			print $config{dir}." does not exist.\n";
			exit 1;
		};
	}else{
		$config{dir}=$opts{d};
		if(!-e $config{dir}){
			print $config{dir}." does not exist.\n";
			exit 1;
		};	
	};	
};

#get the flags dir
if(defined($opts{F})){
	$config{flagdir}=$opts{F};
}else{
	$config{flagdir}='/var/db/netident';
};
#make sure the flag dir exists
if (!-d $config{flagdir}){
	if(!mkdir($config{flagdir})){
		print "Could not create the flag directory, '".$config{flagdir}."'.\n";
		exit 1;
	};
};

if(defined($config{file})){
	my ($returned, $name)=runfile($config{file});

	#create the flag file if true
	#remove it if false and it exists
	if($returned){
		if(open("FLAGFILE", '>', $config{flagdir}."/".$name)){
			print FLAGFILE "";
			close("FLAGFILE");
			exit 0;				
		}else{
			print "Could not not create flag file '".$config{flagdir}."/".$name."'.\n";
			exit 1;
		};
	}else{
		if(-e $config{flagdir}."/".$name){
			if(!unlink($config{flagdir}."/".$name)){
				print "Could not not remove flag file '".$config{flagdir}."/".$name."'.\n";
				exit 1;
			};
		};
		exit 0;
	};
};

if (defined($config{dir})){
	#reads the directory and get the list of test file
	if(!opendir(TESTDIR, $config{dir})){
		print "Could not open directory ".$config{dir}."'\n";
		exit 1;
	};
	my @testfiles=readdir(TESTDIR);
	closedir(TESTDIR);

	@testfiles=grep(!/^\./, @testfiles);

	#tests all the files
	my $testfilesInt=0;
	while(defined($testfiles[$testfilesInt])){
		#tests the file
		my ($returned, $name)=runfile($config{dir}."/".$testfiles[$testfilesInt]);
		
		#create the flag file if true
		#remove it if false and it exists
		if($returned){
			if(open("FLAGFILE", '>', $config{flagdir}."/".$name)){
				print FLAGFILE "";
				close("FLAGFILE");				
			}else{
				print "Could not not create flag file '".$config{flagdir}."/".$name."'.\n";
			};
		}else{
			if(-e $config{flagdir}."/".$name){
				if(!unlink($config{flagdir}."/".$name)){
					print "Could not not remove flag file '".$config{flagdir}."/".$name."'.\n";
				};
			};
		};

		$testfilesInt++;		
	};
};

#-----------------------------------------------------------
# POD documentation section
#-----------------------------------------------------------
=pod

=head1 NAME

netident - A tool for helping identify what network a machine is on. 

=head1 SYNOPSIS

netident [B<-F> <flag dir>] B<-f> <test file>

netident [B<-F> <flag dir>] B<-d> <test dir>

=head1 FLAGS

=item -F <flag dir>

The directory in which the flags are created or removed from. The default is
"/var/db/netident/".

=item -f <file>

The file that is used for the test. This option can't be in conjunction with -d.

=item -d <test dir>

This is a directory that contains the test files. The default is "/usr/local/etc/netident". 

=head1 TEST FILE

The first line contains the name of the test file. This can not contain a "/".

Every line after that is a test. A test has multiple sections and "|" is used as a
delimiter. The first check, followed by the expected boolean return, and the rest are
arguements.

The boolean expected return are 0 or 1 only. 0 means false and 1 means true.

The arguements are in the form of variable=value.

The following example is for a test file that generates the flag "example". It checks
for a IP of "192.168.0.1" with a MAC of "00:11:22:33:44:55". After that it checks
to see if the default gateway is "192.168.0.1".

	test
	pingmac|1|ip=192.168.0.1|mac=00:11:22:33:44:55
	defgateway|1|ip=192.168.0.1

=head1 TESTS

=item pingmac

This test pings a IP to make sure it is in the ARP table and then checks to see if the MAC maches.

The arguement for the IP is "ip".

The arguement for the MAC is "mac".

=item defgateway

This checks the routing table for the default route and compares it to passed variable.

The arguement "ip" is used for the default gateway.

=item cidr

This checks if a specific interface or any of them have a address that matches a given CIDR.

The arguement "cidr" is CIDR to be matched.

The arguement "if" is optional arguement for the interface.

=head1 FLAGS

These are created in 

=head1 CHANGELOG

=item 0.1.0

The initial release.

=head1 AUTHOR

Zane C. Bowers <vvelox@vvelox.net>
=head1 COPYRIGHT

Copyright (c) 2008, Zame C. Bowers <vvelox@vvelox.net>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS` OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=head1 SCRIPT CATEGORIES

Networking

=head1 OSNAMES

unix

=head1 README

netident - A tool for helping identify what network a machine is on.

=cut
#-----------------------------------------------------------
# End of POD documentation
#-----------------------------------------------------------
