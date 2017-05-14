#!/usr/bin/perl -w

# $Id: metawall.pl,v 1.11 2002/10/31 04:01:44 ssnodgra Exp $
# metawall.pl - Generate firewall rules using a metalanguage
# Copyright (C)2002 Steven R. Snodgrass
# See the COPYRIGHT section in this file for full licensing details

#
# Initialization
#

# Directives
use strict;

# Modules
use Getopt::Std;
use NetAddr::IP;

# Globals (initialized constants)
my $COMMENT = '#';
my $EXEC;
my $IPTABLES = '/sbin/iptables';
my $VERSION = '0.12';

# Supported backend targets
# Possible future targets: ipf, ipfks, ios, iosre, iosfw
my %TARGETS = ( ipt => 1, iptct => 1 );

# ICMP request/reply type pairs
my %ICMPPAIR = (
    8	=>  0,	    # echo
    13	=>  14,	    # timestamp
    15	=>  16,	    # information
    17	=>  18,	    # address mask
    33	=>  34,	    # IPv6 where-are-you
    35	=>  36,	    # mobile registration
    37	=>  38	    # domain name
);

# Valid TCP flags
my %TCPFLAGS = (URG => 1, ACK => 1, PSH => 1, RST => 1, SYN => 1, FIN => 1);

# Initialize the network definitions table
# This is a hash of NetAddr::IP arrays
my %NetDef = (
    RFC1918 =>	[ (new NetAddr::IP '10.0.0.0/8'),
		  (new NetAddr::IP '172.16.0.0/12'),
		  (new NetAddr::IP '192.168.0.0/16') ],
);

# Initialize the protocol definitions table
# TCP and UDP protocols have a pair of port ranges, ICMP has type and code
my %ProDef = (
    ip	    => ['ip'],
    icmp    => ['icmp', undef, undef],
    tcp	    => ['tcp', undef, undef, undef],
    udp	    => ['udp', undef, undef],
    ping    => ['icmp', 8, undef],
    ftp	    => ['tcp', undef, [21, 21], undef],
    ssh	    => ['tcp', undef, [22, 22], undef],
    telnet  => ['tcp', undef, [23, 23], undef],
    smtp    => ['tcp', undef, [25, 25], undef],
    dns	    => ['udp', undef, [53, 53]],
    dnsxfr  => ['tcp', undef, [53, 53], undef],
    tftp    => ['udp', undef, [69, 69]],
    http    => ['tcp', undef, [80, 80], undef],
    pop3    => ['tcp', undef, [110, 110], undef],
    nntp    => ['tcp', undef, [119, 119], undef],
    ntp     => ['udp', undef, [123, 123]],
    imap    => ['tcp', undef, [143, 143], undef],
    snmp    => ['udp', undef, [161, 161]],
    ldap    => ['tcp', undef, [389, 389], undef],
    https   => ['tcp', undef, [443, 443], undef],
    imaps   => ['tcp', undef, [993, 993], undef],
);

# Initialize the chains table
# This keeps track of what chains have already been created
my %Chain = (INPUT => 1, FORWARD => 1, OUTPUT => 1);

#
# Subroutines
#

# Convert a comma-separated list of CIDR blocks and/or defined macros into
# a reference to an array of IP::NetAddr objects.  Note that duplicate CIDR
# blocks are eliminated and contiguous CIDR blocks merged when possible by
# the NetAddr compact function.
sub BuildIPList {
    my ($iparg) = @_;
    if (lc($iparg) eq 'any') {
	return [ new NetAddr::IP '0.0.0.0/0' ];
    }
    my @iplist;
    foreach my $ippart (split /,/, $iparg) {
	if (defined $NetDef{$ippart}) {
	    push @iplist, @{$NetDef{$ippart}};
	}
	else {
	    my $netaddr = new NetAddr::IP $ippart;
	    die "Bad network address $ippart" unless
		(defined $netaddr && $netaddr == $netaddr->network());
	    push @iplist, $netaddr;
	}
    }
    NetAddr::IP::compactref(\@iplist);
}

# Verifies that defined and protocol symbols consists of only alphanumeric
# and underscore characters beginning with an alpha.
sub CheckSymbol {
    my ($symbol) = @_;
    die "Invalid symbol $symbol" unless $symbol =~ /^[a-zA-Z][-\w]*$/;
    die "Reserved symbol $symbol" if $symbol =~ /^(ip|icmp|tcp|udp)$/;
}

# Execute or print a backend command
sub DoCommand {
    my ($rule) = @_;
    if ($EXEC) {
	my @rulelist = split /\s+/, $rule;
	system @rulelist;
    }
    else {
	print $rule, "\n";
    }
}

# Create a new chain
sub CreateChain {
    my ($chain, $backend) = @_;
    DoCommand("$IPTABLES -N $chain");
    $Chain{$chain} = 1;
}

# Initialize the main chain with necessary rules
sub InitChain {
    my ($name, $backend) = @_;
    DoCommand("$IPTABLES -P $name DROP") if $name =~ /^(FORWARD|INPUT|OUTPUT)$/;
    DoCommand("$IPTABLES -F $name");
    if ($backend eq 'iptct') {
	DoCommand("$IPTABLES -A $name -m state --state ESTABLISHED,RELATED -j ACCEPT");
    }
}

# Parse a TCP/UDP port range and return low and high values
# Input: portnum or loport: or :hiport or loport:hiport
# Output: [loport, hiport]
sub ParsePort {
    my ($loport, $hiport) = split /:/, $_[0];
    $hiport = $loport unless defined $hiport;
    $loport ||= 0;
    $hiport ||= 65535;
    die "Invalid port specification" unless
	(0 <= $loport && $loport <= $hiport && $hiport <= 65535);
    return [$loport, $hiport];
}

# Parse a comma-separated list of TCP flags with optional not (!) operators
# Returns hash reference with flag names and 0 for unwanted, 1 for wanted
sub ParseTCPFlags {
    my (@flaglist) = split /,/, $_[0];
    my %flag;
    foreach my $item (@flaglist) {
	my ($baseflag, $value);
	if ($item =~ /^!/) {
	    $value = 0;
	    $baseflag = uc(substr($item, 1));
	}
	else {
	    $value = 1;
	    $baseflag = uc($item);
	}
	die "Invalid TCP flag $baseflag" unless exists $TCPFLAGS{$baseflag};
	$flag{$baseflag} = $value;
    }
    return \%flag;
}

# Parse a protocol definition and return a protocol descriptor
# We take all the attributes from the existing definition for the specified
# protocol, then override them with any user-supplied parameters
sub ParseProto {
    my ($proto, @pdef) = @_;
    my ($ipproto, $type, $code, $sport, $dport, $flags);

    # Set up default options from the protocol definition table
    if (exists $ProDef{$proto}) {
	$ipproto = $ProDef{$proto}->[0];
	if ($ipproto eq 'icmp') {
	    $type = $ProDef{$proto}->[1];
	    $code = $ProDef{$proto}->[2];
	}
	elsif ($ipproto eq 'tcp' || $ipproto eq 'udp') {
	    $sport = $ProDef{$proto}->[1];
	    $dport = $ProDef{$proto}->[2];
	}
    }
    elsif ($proto =~ /^\d+$/ && $proto > 0 && $proto <= 255) {
	$ipproto = $proto;
    }
    else {
	die "Invalid protocol $proto" unless getprotobyname($proto);
	$ipproto = $proto;
    }

    # Parse the user specified options
    if ($ipproto eq 'icmp') {
	while (@pdef) {
	    my $arg = shift @pdef;
	    if ($arg eq 'type')	    { $type = shift @pdef; }
	    elsif ($arg eq 'code')  { $code = shift @pdef; }
	    else		    { die "Invalid protocol option $arg"; }
	}
	if (defined $code && !defined $type) {
	    die "Cannot specify ICMP code without type";
	}
	if (defined $type) {
	    die "Invalid ICMP type" unless ($type >= 0 && $type <= 255);
	    if (defined $code) {
		die "Invalid ICMP code" unless ($code >= 0 && $code <= 255);
	    }
	}
	return [$ipproto, $type, $code];
    }
    elsif ($ipproto eq 'tcp') {
	while (@pdef) {
	    my $arg = shift @pdef;
	    if ($arg eq 'sport')    { $sport = ParsePort(shift @pdef); }
	    elsif ($arg eq 'dport') { $dport = ParsePort(shift @pdef); }
	    elsif ($arg eq 'flags') { $flags = ParseTCPFlags(shift @pdef); }
	    else		    { die "Invalid protocol option $arg"; }
	}
	return [$ipproto, $sport, $dport, $flags];
    }
    elsif ($ipproto eq 'udp') {
	while (@pdef) {
	    my $arg = shift @pdef;
	    if ($arg eq 'sport')    { $sport = ParsePort(shift @pdef); }
	    elsif ($arg eq 'dport') { $dport = ParsePort(shift @pdef); }
	    else		    { die "Invalid protocol option $arg"; }
	}
	return [$ipproto, $sport, $dport];
    }
    else {
	die "Invalid protocol option @pdef" if @pdef;
	return [$ipproto];
    }
}

# Put an IP block in iptables format
# 'IP_address' for hosts
# 'IP_address/mask' for blocks
sub FormatIptIP {
    my ($ip) = @_;
    ($ip->masklen() == 32) ? $ip->addr() : "$ip";
}

# Returns true if the port pair restricts the port range
sub IsPortRange {
    my ($loport, $hiport) = @_;
    return ($loport != 0 || $hiport != 65535);
}

# Put a port specification in iptables format
sub FormatIptPort {
    my ($loport, $hiport) = @{$_[0]};
    if ($loport == $hiport) {
	return $loport;
    }
    elsif ($loport == 0) {
	return ":$hiport";
    }
    elsif ($hiport == 65535) {
	return "$loport:";
    }
    else {
	return "$loport:$hiport";
    }
}

# Put an ICMP specification in type/code format
sub FormatIptICMP {
    my ($type, $code) = @_;
    return "$type/$code" if defined $code;
    return $type;
}

# Put TCP flags in iptables format
sub FormatIptFlags {
    my ($flags) = @_;
    my $mask = join(',', sort keys %$flags);
    my $result = join(',', grep { $flags->{$_} } (sort keys %$flags));
    $result ||= 'NONE';
    return "$mask $result";
}

# Generate the source/dest address/port ("middle") portion of a rule
sub GenerateMiddle {
    my ($backend, $source, $dest, $pdesc, %oopt) = @_;
    my ($proto, @popt) = @$pdesc;
    my $spart = "";
    my $dpart = "";
    $spart .= " -s " . FormatIptIP($source) if $source->masklen();
    $dpart .= " -d " . FormatIptIP($dest) if $dest->masklen();
    if ($proto eq 'tcp' || $proto eq 'udp') {
	$spart .= " --sport " . FormatIptPort($popt[0]) if $popt[0];
	$dpart .= " --dport " . FormatIptPort($popt[1]) if $popt[1];
    }
    elsif ($proto eq 'icmp') {
	$dpart .= " --icmp-type " . FormatIptICMP(@popt) if defined $popt[0]; 
    }
    $spart .= " -i $oopt{iint}" if $oopt{iint};
    $dpart .= " -o $oopt{oint}" if $oopt{oint};
    if ($proto eq 'tcp' && $popt[2]) {
	$dpart .= " --tcp-flags " . FormatIptFlags($popt[2]);
    }
    return $spart . $dpart;
}

# Generate the reversed portion of a rule for stateless replies
sub GenerateReverse {
    my ($backend, $source, $dest, $pdesc, %oopt) = @_;
    return undef unless ($backend eq 'ipt' && !$oopt{oneway});
    my ($proto, @popt) = @$pdesc;
    my $spart = "";
    my $dpart = "";
    $spart .= " -s " . FormatIptIP($dest) if $dest->masklen();
    $dpart .= " -d " . FormatIptIP($source) if $source->masklen();
    if ($proto eq 'icmp') {
	# Don't generate reverse ICMP rules unless we are specifying an
	# ICMP type (and no code) with an obvious corresponding reply
	return undef unless defined $popt[0];
	my ($type, $code) = @popt;
	return undef unless exists $ICMPPAIR{$type};
	return undef if defined $code;
	$dpart .= " --icmp-type " . FormatIptICMP($ICMPPAIR{$type}, $code);
    }
    elsif ($proto eq 'tcp' || $proto eq 'udp') {
	# Don't generate a reply rule if TCP flags are specified
	return undef if ($proto eq 'tcp' && $popt[2]);
	$spart .= " --sport " . FormatIptPort($popt[1]) if $popt[1];
	$dpart .= " --dport " . FormatIptPort($popt[0]) if $popt[0];
	$dpart .= " ! --syn" if $proto eq 'tcp';
    }
    $spart .= " -i $oopt{oint}" if $oopt{oint};
    $dpart .= " -o $oopt{iint}" if $oopt{iint};
    return $spart . $dpart;
}

# Parse the various sections of a rule
# Returns: (command, pdesc, sip, dip, oopts)
sub ParseRule {
    my ($command, $protname, @args) = @_;
    my ($sip, $dip, @popts, %oopt);
    while (@args) {
	my $token = shift @args;
	if ($token =~ /^(type|code|sport|dport|flags)$/) {
	    push @popts, $token, shift @args;
	}
	elsif ($token =~ /^(iint|oint|chain)$/) {
	    $oopt{$token} = shift @args;
	}
	elsif ($token =~ /^(oneway|log)$/) {
	    $oopt{$token} = 1;
	}
	else {
	    if (!defined $sip)	    { $sip = BuildIPList($token); }
	    elsif (!defined $dip)   { $dip = BuildIPList($token); }
	    else		    { die "Unrecognized keyword $token"; }
	}
    }
    my $pdesc = ParseProto($protname, @popts);
    return ($command, $pdesc, $sip, $dip, %oopt);
}

# Generate actual backend rules from metawall syntax
sub GenerateRules {
    my ($chain, $backend, @args) = @_;
    my %actions = (
	permit	=>  'ACCEPT',
	accept	=>  'ACCEPT',
	deny	=>  'DROP',
	drop	=>  'DROP',
	reject	=>  'REJECT'
    );
    print "\n$COMMENT @args\n";
    my ($command, $pdesc, $sip, $dip, %oopt) = ParseRule(@args);
    my $rulebeg = "$IPTABLES -A $chain";
    $rulebeg .= " -p $pdesc->[0]" unless $pdesc->[0] eq 'ip';
    my $action;
    if ($command eq 'jump') {
	die "No jump target" unless exists $oopt{chain};
	$action = $oopt{chain};
    }
    else {
	$action = $actions{$command};
    }
    foreach my $src (@$sip) {
	foreach my $dst (@$dip) {
	    my $rulemid = GenerateMiddle($backend, $src, $dst, $pdesc, %oopt);
	    DoCommand("$rulebeg$rulemid -j LOG") if $oopt{log};
	    DoCommand("$rulebeg$rulemid -j $action");
	    if ($action eq 'ACCEPT') {
		my $rulerev;
		$rulerev = GenerateReverse($backend, $src, $dst, $pdesc, %oopt);
		if (defined $rulerev && $rulerev ne $rulemid) {
		    DoCommand("$rulebeg$rulerev -j LOG") if $oopt{log};
		    DoCommand("$rulebeg$rulerev -j $action");
		}
	    }
	}
    }
}

# Display the usage message
sub PrintUsage {
    print "Usage: $0 [-hnpvx] [-b backend] [-c chain] [rulefile ...]\n";
    print "   -b Select backend target (default: iptct)\n";
    print "   -c Set the name of the main rule chain (default: metawall)\n";
    print "   -h Print this help message\n";
    print "   -n Print a list of builtin networks\n";
    print "   -p Print a list of builtin protocols\n";
    print "   -v Print the version number\n";
    print "   -x Execute rules instead of printing them\n";
    print "\nRun 'perldoc $0' for more detailed documentation.\n";
    exit;
}

# Display the currently defined protocols
sub PrintProtocols {
    foreach my $key (sort keys %ProDef) {
	my $proto = $ProDef{$key}->[0];
	print "$key\t$proto";
	if ($proto eq 'icmp') {
	    my ($type, $code) = @{$ProDef{$key}}[1,2];
	    print " type $type" if defined $type;
	    print " code $code" if defined $code;
	}
	elsif ($proto eq 'tcp' || $proto eq 'udp') {
	    my ($sport, $dport) = @{$ProDef{$key}}[1,2];
	    print " sport ", FormatIptPort($sport) if defined $sport;
	    print " dport ", FormatIptPort($dport) if defined $dport;
	}
	print "\n";
    }
    exit;
}

# Display the currently defined networks
sub PrintNetworks {
    foreach my $key (sort keys %NetDef) {
	print "$key: @{$NetDef{$key}}\n";
    }
    exit;
}

# Process a statement from the input configuration
sub ProcessConfig {
    my ($cref, $backend, $command, @args) = @_;
    if ($command eq 'define') {
	die "Invalid define statement" unless @args == 2;
	my ($alias, $value) = @args;
	CheckSymbol($alias);
	$NetDef{$alias} = BuildIPList($value);
    }
    elsif ($command eq 'protocol') {
	die "Insufficient arguments for protocol statement" unless @args > 1;
	my $proto = shift @args;
	CheckSymbol($proto);
	warn "Redefining protocol $proto" if exists $ProDef{$proto};
	$ProDef{$proto} = ParseProto(@args);
    }
    elsif ($command =~ /^(permit|accept|deny|drop|reject|jump)$/) {
	die "Insufficient arguments for $command" if @args < 3;
	GenerateRules($$cref, $backend, $command, @args);
    }
    elsif ($command eq 'chain') {
	die "Invalid chain statement" unless @args == 1;
	my $name = shift @args;
	CheckSymbol($name);
	print "\n$COMMENT $command $name\n";
	CreateChain($name) unless exists $Chain{$name};
	$$cref = $name;
    }
    else {
	die "Unrecognized keyword $command";
    }
}

#
# Main Code
#

# Process command line options
my %opt;
getopts('b:c:hnpvx', \%opt);
PrintUsage() if $opt{h};
PrintNetworks() if $opt{n};
PrintProtocols() if $opt{p};
if ($opt{v}) { print "$VERSION\n"; exit; }
my $backend = lc($opt{b}) || 'iptct';
die "Unsupported backend $backend" unless $TARGETS{$backend};
my $chain = $opt{c} || 'metawall';
$EXEC = $opt{x};

# Create the default chain
CreateChain($chain, $backend) unless exists $Chain{$chain};

# Install any necessary initital rules into the main chain
InitChain($chain, $backend);

# Process configuration
while (<>) {
    chop;
    next if /^\s*#/;
    next if /^\s*$/;
    ProcessConfig(\$chain, $backend, split);
}

__END__

=head1 NAME

metawall.pl - Generate firewall rules using a metalanguage

=head1 SYNOPSIS

metawall.pl [-hnpvx] [-b I<backend>] [-c I<chain>] I<rulefile>

=head1 DESCRIPTION

Metawall is a tool that generates low-level packet filtering rules using a
higher-level language that allows you to define your own protocols and netblock
macros.  A unique feature of metawall is its support for multiple backend
targets, allowing you to generate stateful or stateless firewalls on different
packet filtering platforms using the same source files.

This release of metawall supports two backends.  The 'iptct' backend is the
default and generates stateful rules for iptables using the connection tracking
module.  The other option is 'ipt', which generates stateless iptables rules
that do not require the connection tracking module.  There will hopefully be
more backend support in the future, with IP Filter being the next likely
candidate.

WARNING: This release of metawall is considered B<alpha> quality, both because
it has received only limited testing, and because the command language is still
subject to change in future releases.  Metawall is intended for use by someone
who understands IP security; it is not a magic bullet that will secure your
network.  Metawall is provided as is without warranty of any kind, either
expressed or implied.  To paraphrase a well-known virus parody, "Metawall may
recalibrate your refrigerator's coolness setting so all your ice cream goes
melty, demagnetize the strips on all your credit cards, screw up the tracking
on your television and use subspace field harmonics to scratch any CD's you try
to play."

=head1 PREREQUISITES

Metawall was developed under Perl 5.6.1, though it may run on earlier versions.
It requires the C<NetAddr::IP> module (available on CPAN).

=head1 OPTIONS

=over 4

=item -b I<backend>

This option allows you to select the backend target for rule generation.
Currently the valid selections are ipt or iptct.  The default is iptct.
See the BACKENDS section for more details.

=item -c I<chain>

Set the name used for the main rule chain.  The default name is C<metawall>.
This can be used to install rulesets directly into the FORWARD, INPUT, or
OUTPUT chains if desired, or simply to control where the rules go.  This
can be helpful during ruleset testing or in startup scripts.

=item -h

Display the help text.

=item -n

Display the definitions of the builtin network macros.  Currently the
only builtin netblock is RFC1918.

=item -p

Display the definitions of the builtin protocols.  Some common application
level protocols are predefined in the metawall script (e.g. http).  These
definitions can be overridden by the protocol statement, though doing so will
generate a runtime warning.

=item -v

Display the metawall version number.

=item -x

Execute the iptables commands produced by metawall.  The default is to just
print the commands.

=back

=head1 BACKENDS

Metawall supports different backend packet filtering systems.  Backends are
selected with the -b command line option.  Details on each backend are below.

=over 4

=item iptct

The iptct backend generates iptables rules that require the connection tracking
module.  Connection tracking performs stateful monitoring of IP flows and can
dynamically allow reply packets for existing connections.  When using this
backend, a rule will automatically be generated at the beginning of the main
chain which permits all reply traffic to existing connections.

=item ipt

The ipt backend generates stateless iptables rules which do not require the
connection tracking module.  In stateless mode, metawall generates a pair of
rules for each permit/accept command, one of which allows the reply traffic for
the rule.  This behavior can be suppressed by using the C<oneway> option in a
rule.  There are some exceptions to this; ICMP rules don't generate reply rules
unless they are one of the "request" ICMP types.  TCP rules that specify flags
do not generate reply rules either.

=back

=head1 COMMANDS

The primary input to metawall is a rule file written in metawall's own
language.  Lines are processed individually with one rule per line.  Blank
lines and lines beginning with the hash mark (#) are ignored.  Each line begins
with a command which is followed by some number of parameters, depending on the
specific command being used.  The best way to learn to use these commands is
probably by looking at the EXAMPLES section.  Valid commands are listed below.

=over 4

=item chain I<name>

A chain is simply a list of packet filtering rules that are executed
sequentially.  Metawall supports the iptables feature of multiple chains.  The
chain command selects the current chain and creates a new chain if necessary.
All rules generated after the chain command become part of that chain.  The
jump command can be used to create a rule that transfers control to a different
chain.  The default chain is named metawall.

=item define I<name> I<netblock-list>

The define command is one of the most powerful and useful features of metawall.
It allows you to define a symbolic name that will then represent an arbitrary
list of network blocks when used in rules.  In addition, if the list of network
blocks can be merged into larger equivalent blocks, this will be done, courtesy
of the NetAddr::IP compact function.  The name must consist only of
alphanumeric, dash and underscore characters, beginning with an alpha.  The
netblock list is a comma separated list of hostnames or IP addresses with
optional netmasks.  Netmasks are separated from the network address by a slash
and may be in either CIDR bit form (e.g. /24) or dotted-quad form (e.g.
/255.255.255.0).  The netblock list may contain more macros previously created
by define commands.  No spaces are allowed in the netblock list.  There are
some netblock macros built into the metawall script; these can be displayed
with the -n option on the command line.

=item protocol I<name> I<base-protocol> I<protocol-options>

The protocol command is similar to the define command, but instead of defining
macros for network blocks it defines them for protocols.  Metawall provides a
number of builtin protocols whose definitions can be displayed by using the -p
option on the command line.  The name must follow the same rules as defined
names.  The base protocol may be a real IP protocol such as icmp, tcp, or udp
or it may be another protocol already created by the protocol statement.
It may also be an IP protocol number from 1 to 255.  If the IP protocol in
question is icmp, tcp, or udp, you may specify additional options listed below.

=over 4

=item code I<integer>

This option is only valid with the ICMP protocol, and specifies the ICMP
code field.  Valid codes range from 0-255.  You may not specify a code unless
you also specify an ICMP type.

=item dport I<portrange>

This option is only valid with the TCP or UDP protocol.  It specifies the
allowed port range for the destination port field.  The port range may be a
single integer or a colon-separated range.  The number before or after the
colon may be omitted when the lower or upper end of the range is 0 or 65535
respectively.  This option is commonly used to distinguish between different
application layer protocols, since they often use well known destination port
numbers.

=item flags I<tcpflags>

This option is only valid with the TCP protocol.  It specifies what TCP
flags must be set or unset for the rule to match.  For example, you can
use 'flags SYN,!ACK' to match TCP packets with SYN set and ACK cleared.
Valid flags are ACK, FIN, PSH, RST, SYN, and URG.

=item sport I<portrange>

This option is only valid with the TCP or UDP protocol.  It specifies the
allowed port range for the source port field.  See the dport option for info
on the port range format.

=item type I<integer>

This option is only valid with the ICMP protocol, and specifies the ICMP
type field.  Valid types range from 0-255.

=back

=item deny/drop I<rule>

The deny and drop commands are synonyms; they perform the same function.
Any packet which matches the specified rule will be dropped, and processing
of the remainder of the chain will terminate.  See the RULES
section for information on rule specification.

=item reject I<rule>

The reject command is similar to the deny/drop command, but in addition to
dropping the packet it will generate an ICMP unreachable message back to the
packet source.  See the RULES section for information on rule specification.

=item permit/accept I<rule>

The permit and accept commands are synonyms; they perform the same function.
Any packets which matches the specified rule will be permitted through, and
processing of the remainder of the chain will terminate.  The permit command is
generally expected to allow a two-way traffic stream.  Stateful backends will
do this using the state table; on stateless backends a pair of rules will be
generated, one for the forward traffic and one for replies.  The C<oneway>
option can be used to override this behavior on stateless backends.  See the
RULES section for information on rule specification.

=item jump I<rule>

The jump command is used to transfer control to a different chain when the
rule is matched.  The rule associated with a jump command must include the
chain option, which specifies which chain to jump to.  See the RULES section
for information on rule specification.

=back

=head1 RULES

Most metawall commands produce packet filtering rules.  Those commands include
permit/accept, deny/drop, reject, and jump.  Every rule has a similar format
that looks like this:

I<command> I<protocol> I<source> [I<options>] I<destination> [I<options>]

Actually, the parser allows everything after the protocol argument to be
arbitrarily ordered, except that the source must come before the destination.
It is suggested that you keep source and destination options grouped after
the source and destination addresses for clarity, but this is not required.

The protocol argument may be any protocol that is built into metawall (use the
-p command line option for a list) or anything that has already been defined by
using a protocol command.  The source and destination arguments are formatted
exactly the same as the right hand side of the C<define> command.  In other
words, a comma separated list of networks or already defined macros.  The
keyword 'any' for the source or destination is equivalent to 0.0.0.0/0.

Options may be specified anywhere in the line after the protocol argument.
All options described in the protocol command in the COMMANDS section are
supported here as well, and they will override options associated with the
chosen protocol.  These option definitions will not be repeated here.  The
following options are also supported:

=over 4

=item chain I<name>

This option is only valid when used with the jump command.  In that case,
it specifies the name of the chain to jump to if the rule matches.

=item iint I<interface>

The C<iint> option specifies what interface the packet must be received on.
The rule will not match if the packet was not input on the specified
interface.

=item log

This option causes packets matching this rule to be logged via syslog.  There
is currently no way to modify the logging level, though this will probably
be added in the next release.

=item oint I<interface>

The C<oint> option specifies what interface the packet will be transmitted on.
The rule will not match if the packet will not be output on the specified
interface.

=item oneway

This option suppresses the generation of the reply rule when using a stateless
backend.  This can be particularly useful when trying to permit certain ICMP
traffic in one direction only, but it can be used with any protocol.

=back

=head1 EXAMPLES

This section provides a number of examples of metawall command syntax.  These
examples are B<not> recommendations of what rules you might want to use!  The
rules that are appropriate for any firewall must be determined according to the
security policy at that site.  These serve only to demonstrate the types of
things that can be done with metawall.

 # Define some network macros
 define BOGONS RFC1918,0.0.0.0/8,127.0.0.0/8,169.254.0.0/16
 define OURNET 192.0.2.0/24
 define DNS_SERVERS 192.0.2.5,192.0.2.6

 # We need special protocols
 protocol foobar tcp dport 2256
 protocol quake3 udp dport 27960:27975

 # Deny all traffic from bogus (spoofed) addresses
 deny ip BOGONS any

 # Prevent spoofing our addresses if eth1 is the outside
 deny ip OURNET iint eth1 any log

 # Allow some common outbound protocols
 permit ftp OURNET any
 permit ssh OURNET any
 permit http OURNET any
 permit https OURNET any

 # We also use the all-powerful foobar protocol
 permit foobar OURNET any

 # Allow external access for some services
 permit http any www.example.com
 permit dns any DNS_SERVERS
 permit quake3 any 192.0.2.50

 # Allow zone transfers to our secondaries
 permit dnsxfr ns2.mydyndns.org,ns3.mydyndns.org DNS_SERVERS

 # Allow email to/from mailservers
 permit smtp 192.0.2.20 any
 permit smtp any 192.0.2.20

 # See what outbound stuff we are dropping
 deny ip OURNET any log

 # Make sure everything else is dropped
 deny ip any any

=head1 HISTORY

=over 4

=item Version 0.12

Added support for TCP flags.
Added support for IP protocol numbers.
Changed what types of ICMP rules generate stateless reply rules.
Symbols may now contain '-' characters.
Fixed some buglets in symbol and token parsing.
Added a few more protocols.

=item Version 0.11 (unreleased)

Replaced -i install option with more flexible -c chain name option.

=item Version 0.10

Initial release with iptables support.

=back

=head1 AUTHOR

Steve Snodgrass <ssnodgra@pheran.com>

=head1 COPYRIGHT

Copyright (C)2002 Steven R. Snodgrass

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA 02111-1307 USA

=head1 AVAILABILITY

The metawall home page can be found at L<http://www.pheran.com/metawall/>.

=head1 ACKNOWLEDGEMENTS

Thanks to Luis E. Munoz for his excellent NetAddr::IP module, and to my
wonderful wife for allowing me to hide out in my den long enough to hack
this thing together.  :-)

=head1 SCRIPT CATEGORIES

Networking

=head1 README

Metawall is a perl script that allows you to write firewall rules in a simple
metalanguage.  These rules can then be used to generate packet filtering
commands for a variety of backend targets.
