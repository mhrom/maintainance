#!/usr/bin/perl -w

# This program is free software in the public domain.

use Net::FTP ;
use File::Temp ;

=pod

=head1 README

This script robustly uploads a large file via FTP, working around the pesky problem "Unexpected EOF on command channel" which can happen while uploading large files through some servers.

=head1 NAME

tuff-ftp-put.pl  - Robustly uploads a large file via FTP, working around the pesky problem "Unexpected EOF on command channel".

=head1 SYNOPSIS

tuff-ftp-put.pl  <localPath> <destinDirFullPath> <destinFilename> <domain> <accountName> <password>

=head1 DESCRIPTION

This script robustly uploads a large file via FTP, working around the pesky problem "Unexpected EOF on command channel".

Some of internet routers have been found to time out the FTP 'command channel' due to inactivity on it during large uploads.  We  predictably get this on the DSL line at our house if an upload takes any longer than 60 seconds.  This script works around the issue by ignoring errors during the upload, and then to compensate for ignoring errors, verifies the upload success by downloading the file after uploading, counting the bytes, and performing a diff (bit-by-bit comparison).

This script takes more time to complete than a normal FTP put.  This is due to (1) the verification download, (2) the fact that the timeout on the command channel, if it occurs during the upload, does not commence until after the file upload is done, causing a pause of typically 60 seconds, and (3) ditto for command channel timeout during the verification download.

This script is the culmination of months of frustration with my web host and internet service provider.  It is good enough for my purposes, and I need to move on.  But there are lots of things that could be improved in it I'm sure, particularly in controlling the crap that gets printed to stdout and stderr.  Or maybe there is a better way to scriptfully upload large files without using FTP.  Any suggestions would be appreciated.

=head1 OPTIONS

None

=head1 PARAMETERS (ARGUMENTS)

All of the following parameters are required, in the following order.

=over

=item <localPath>

Full path to local file to be uploaded

=back

=over

=item <destinDirFullPath>

Path from the FTP account root on the server to which the file should be uploaded.  Should end in a slash.  Examples:  "public_html/whatever/" "www/path/to/whatever/"

=back

=over

=item <destinFilename>

Name of the file as it should appear on the server.  May or may not be the same as the filename at the end of <localPath>.  Example: "MyMovie.mov"

=back

=over

=item <domain>

Internet domain name into which the file should be uploaded.  Example: "sheepsystems.com"

=back

=over

=item <accountName>

Account name required to upload files into the given internet domain.

=back

=over

=item <password>

Account password required to upload files into the given internet domain.

=back

=head1 RESULT

This script will log progress information to stdout and stderr.  If there is any indication that the file may not have been uploaded successfully, this script will die.

=head1 PREREQUISITES

=over

=item <Net::FTP>

=item <File::Temp>

=back

=head1 COREQUISITES

None

=head1 OSNAMES

Script has been tested in Mac OS X 10.8>

=head1 VERSION

1.0.3

=head1 AUTHOR

Jerry Krinock <jerry@sheepsystems.com>

=head1 CREDITS

Thanks to Mike Abdullah, who was the only one in the world able to get near to the bottom of the FTP control channel timeout issue, when he fixed a bug I reported, caused by this issue, in the Sandvox app that he was working on for Karelia Software.

=head1 COPYRIGHT

Copyright (c) 2012, Jerry Krinock <jerry@sheepsystems.com>

All rights reserved.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 SCRIPT CATEGORIES

Networking
Web    

=cut

use Net::FTP ;

my $argc = @ARGV; 
if ($argc != 6) {
	usageErrorDie() ;
}

my $localPath = $ARGV[0] ;
my $destinDirFullPath = $ARGV[1] ;
my $destinFilename = $ARGV[2] ;
my $domain = $ARGV[3] ;
my $accountName = $ARGV[4] ;
my $password = $ARGV[5] ;

my $ftp ;

# Get size, for information to be printed
my $upBytes = -s $localPath ;

# Open ftp in destination directory
$ftp = openFtpForBinary($domain, $accountName, $password, $destinDirFullPath) ;

# Put file
print "Uploading: $localPath\n" ;
print "       To: $destinFilename\n" ;
print "       In: $destinDirFullPath\n" ;
print "       On: $domain\n" ;
print "     Size: $upBytes bytes\n" ;
print "*** Note: Unexpected EOF on command channel during the following STOR is *NOT* unexpected.\n" ;
# Ignore return value of next line because indicate have an FTP command channel timeout
$ftp->put($localPath, $destinFilename) ;
print "*** Note: Unexpected EOF on command channel during the preceding STOR is *NOT* unexpected.\n" ;

# Close ftp, because we assume that its control channel closed down due to a timeout
$ftp->quit ;

# Download the just-uploaded file
my $tempPath = tmpnam() ;
# Re-open ftp in destination directory
$ftp = openFtpForBinary($domain, $accountName, $password, $destinDirFullPath) ;

# Get file to verify by diff
print ("Upload is done.\n") ;
print ("Downloading uploaded file to verify...\n") ;
my $destinPath = "$destinDirFullPath$destinFilename" ;
print "*** Note: Unexpected EOF on command channel during the following RETR is *NOT* unexpected.\n" ;
# Ignore return value of next line because indicate have an FTP command channel timeout
$ftp->get($destinFilename, $tempPath) ;
print "*** Note: Unexpected EOF on command channel during the preceding RETR is *NOT* unexpected.\n" ;
	
# Close ftp
$ftp->quit ;

# Diff
# Get file sizes using "-s", one of Perl's handy File Test Operators
my $downBytes = -s $tempPath ;
my $diffResult = `/usr/bin/diff "$tempPath" "$localPath"` ;
chomp ($diffResult) ;
print "Comparing just-downloaded $destinFilename to what was uploaded\n" ;
print "        uploaded: $upBytes bytes\n" ;
print "      downloaded: $downBytes bytes\n" ;
print "     diff result: $diffResult\n" ;
if (length($diffResult) == 0) {
	print "--- Good news!  File survived round-trip upload and download with no diff.\n" ;
}
else {
	die "tuffFtp: Uploaded file differed after downloading.  Differences:\n $diffResult" ;
}

unlink ($tempPath) ;


sub openFtpForBinary {
	my $domain = shift ;
	my $accountName = shift ;
	my $password = shift ;
	my $directory = shift ;

	my $ftpObject = Net::FTP->new($domain, Debug => 1)
		or die "tuffFtp: Connect to $domain failed: $@";
	$ftpObject->login("$accountName","$password")
		or die "tuffFtp: Login failed: ", $ftpObject->message ;
	print "Will change server dir to $directory\n" ;
	$ftpObject->cwd("$directory")
		or die "tuffFtp:: Change to $directory failed: ", $ftpObject->message ;
	$ftpObject->binary ;
	
	return $ftpObject ;
}

sub usageErrorDie {

	print "tuff-ftp-put robustly uploads a large file via FTP, working around the pesky problem \"Unexpected EOF on command channel\".  There are 0 options.  The following parameters (arguments) are required, in this order:\n" ;

	print "   <localPath>  Full path to local file to be uploaded\n" ;
	print "   <destinDirFullPath>  Path from the FTP account root on the server to which the file should be uploaded.  Should end in a slash.  Examples:  \"public_html/whatever/\" \"www/path/to/whatever/\"\n" ;
	print "   <destinFilename>  Name of the file as it should appear on the server.  May or may not be the same as the filename at the end of <localPath>.  Example: \"MyMovie.mov\"\n" ;
	print "   <domain>  Internet domain name into which the file should be uploaded.  Example: \"sheepsystems.com\"\n" ;
	print "   <accountName>  Account name required to upload files into the given internet domain.n" ;
	print "   <password>  Account password required to upload files into the given internet domain.\n" ;

	die() ;
}
