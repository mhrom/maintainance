#eth0 --- Public interface  
#eth1 --- Local network

#The ip address got from ISP on eth0
PublicIP=176.104.244.142
#The local ip address on eth1
LocalIP=192.168.255.254

IPT=/sbin/iptables

#default policy rules
$IPT -P INPUT DROP
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -N LOGGING
#
# Flush (-F) all specific rules
#
$IPT -F INPUT 
$IPT -F FORWARD 
$IPT -F OUTPUT 
$IPT -F -t nat

#Allow unlimited traffic on loopback interface

$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

#Allow unlimited traffic in internal network

$IPT -A INPUT -i eth1 -j ACCEPT
$IPT -A OUTPUT -o eth1 -j ACCEPT
$IPT -A INPUT -i xenbr0 -j ACCEPT
$IPT -A OUTPUT -o xenbr0 -j ACCEPT

#Allow ssh connection from any hosts in Internet
$IPT -A INPUT -p tcp -s 0/0 -d $PublicIP --sport 1024:65535 --dport 22 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -s $PublicIP  -d 0/0 --sport 22 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

#Allow ssh connection from any hosts in Internet to tatuazhkiev on port 2222
$IPT -A INPUT -p tcp -s 0/0 -d $PublicIP --sport 1024:65535 --dport 2222 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -s $PublicIP  -d 0/0 --sport 2222 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

#Allow http traffic from Internal to External network

$IPT -A INPUT -p tcp -s 0/0 -d 0/0 --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp -s 0/0  -d 0/0 --sport 80 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

#Allow https traffic from inside to outside
$IPT -A INPUT -p tcp -s 0/0 -d 0/0 --sport 1024:65535 --dport 443 -j ACCEPT
$IPT -A INPUT -p tcp -s 0/0  -d 0/0 --sport 443 --dport 1024:65535 -j ACCEPT


#Allow dns traffic
$IPT -A OUTPUT -p udp -s $PublicIP -d 0/0 --sport 1024:65535 --dport 53 -j ACCEPT
$IPT -A INPUT -p udp -s 0/0 -d $PublicIP --sport 53 --dport 1024:65535 -j ACCEPT

#Allow smtp from inside to outside

$IPT -A OUTPUT -p tcp -s $PublicIP -d 0/0 --sport 1024:65535 --dport 587 -j ACCEPT
$IPT -A INPUT -p tcp -s 0/0 -d $PublicIP --sport 587 --dport 1024:65535 -j ACCEPT

$IPT -A OUTPUT -p tcp -s $PublicIP -d 0/0 --sport 1024:65535 --dport 25 -j ACCEPT
$IPT -A INPUT -p tcp -s 0/0 -d $PublicIP --sport 25 --dport 1024:65535 -j ACCEPT

#Allow icmp from inside to outside
$IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT


#Allow ftp traffic to server
#$IPT -A INPUT -p tcp -m multiport --dports 20,21 -m state --state  NEW,RELATED,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -p tcp -m multiport --sports 20,21 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

#Allow http traffic to web server

$IPT -A INPUT -p tcp -s 0/0 -d $PublicIP --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT 
$IPT -A OUTPUT -p tcp -s $PublicIP  -d 0/0 --sport 80 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT 

#Allow https traffic to web server
#$IPT -A INPUT -p tcp -s 0/0 -d $PublicIP --sport 1024:65535 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -p tcp -s $PublicIP  -d 0/0 --sport 443 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

#Allow access to openvz webadmin page
#$IPT -A INPUT -p tcp -s 0/0 -d $PublicIP --sport 1024:65535 --dport 3000 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -p tcp -s $PublicIP  -d 0/0 --sport 3000 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT


# Allow FTP connections @ port 21
#$IPT -A INPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT
# Allow Active FTP Connections
#$IPT -A INPUT -p tcp --sport 20 -m state --state NEW,RELATED -j ACCEPT
#$IPT -A OUTPUT -p tcp --dport 20 -m state --state NEW -j ACCEPT
# Allow Passive FTP Connections
#$IPT -A INPUT -p tcp --sport 1024: --dport 1024: -m state --state NEW,RELATED -j ACCEPT
#$IPT -A OUTPUT -p tcp --sport 1024: --dport 1024: -m state --state NEW,RELATED -j ACCEPT

#Forward packets that are part of existing and related connections from Internal to External network
$IPT -A FORWARD -i eth1 -o p4p1 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A FORWARD -i p4p1 -o eth1 -m state --state ESTABLISHED -j ACCEPT

#Internal network addresses nated to Internet direct

$IPT -A POSTROUTING -t nat -s 192.168.255.0/24 -j MASQUERADE

#prerouting nat modifying of traffic to nginx reverse proxy and tatuazhkiev
$IPT -A PREROUTING -t nat -d 176.104.244.142/32 -i p4p1 -p tcp -m tcp --dport 80 -j DNAT --to-destination 192.168.255.27
$IPT -A PREROUTING -t nat -d 176.104.244.142/32 -i p4p1 -p tcp -m tcp --dport 2222 -j DNAT --to-destination 192.168.255.19

#The drop packets are logging to file 

#$IPT -A INPUT -j LOGGING
#$IPT -A OUTPUT -j LOGGING
#$IPT -A FORWARD -j LOGGING
#$IPT -A POSTROUTING -j LOGGING
#$IPT -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
#$IPT -A LOGGING -j DROP
