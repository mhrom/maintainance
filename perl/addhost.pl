#!/usr/bin/perl
#
#
# Usage: Perl script to add hosts for Nagios monigoing
# Written by: brandon.w.thompson
#
#use strict;

my $ugly_file = shift;
if(!defined $ugly_file){
print "Usage: $0 >> file.cfg>\n";
exit;
}
our @ARGV = ("use", "host_name", "alias", "address", "hostgroups", "contact_groups");
open(FILE, $ugly_file);
while(){
chomp;
# if (/!! Start !!/ .. /!! End !!/) { #Uncomment this line to process certain part of file#
# if (1..10); #Uncomment this line to process certain concecutive lines#
($field1, $field2, $field3, $field4, $field5, $field6)=split("\t");
print "define host{\n\t$ARGV[0]\t\t$field1\n\t$ARGV[1]\t$field2\n\t$ARGV[2]\t\t$field3\n\t$ARGV[3]\t\t$field4\n\t$ARGV[4]\t$field5\n\t$ARGV[5]\t$field6\n}\n";
# }
}
close(FILE);
exit;