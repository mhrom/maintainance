#!/usr/bin/perl
#Copyright (c) 2007, Zane C. Bowers
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

sub main::VERSION_MESSAGE{
        print "randMACgen v. 1.0.0";
};

sub main::HELP_MESSAGE{

        print "\n-h      Print this out.\n".
        	"-3      Just prints half a MAC number.\n".
        	"\n".
        	"This program prints out a MAC number.\n";

        exit 1;
};

sub randHEX{
	my $randHEX=sprintf("%X", int(rand("255")));
	
	if (length($randHEX) == 1){
		$randHEX="0".$randHEX;
	};

	return $randHEX;
};

my %opts=();
getopts('h3', \%opts);

if (defined($opts{h})){
	&VERSION_MESSAGE;
	&HELP_MESSAGE;
};

if (defined($opts{3})){
	print &randHEX.":".&randHEX.":".&randHEX;
}else{
	print &randHEX.":".&randHEX.":".&randHEX.":".&randHEX.":".&randHEX.":".&randHEX;
};


#-----------------------------------------------------------
# POD documentation section
#-----------------------------------------------------------

=head1 NAME

randMACgen - generate a random MAC number

=head1 USAGE

Prints either a random MAC number or half of one.

=head1 FLAGS

=item B<-3>

Prints half a MAC number.

=item B<-h>

Prints help info.

=head1 AUTHOR

Zane C. Bowers <vvelox@vvelox.net>

=head1 COPYRIGHT

Copyright (c) 2006, Zame C. Bowers <vvelox@vvelox.net>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
    * Neither the name of the Midwest Connections Inc. nor the names of its
     contributors may be used to endorse or promote products derived from
     this software without specific prior written permission.

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

any

=head1 README

Prints out a MAC number or half a MAC number.

=cut

#-----------------------------------------------------------
# End of POD documentation
#-----------------------------------------------------------
