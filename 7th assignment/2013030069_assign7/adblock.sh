#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Configure adblock of $domainNames file.
        # Write your code here...
	# this takes about 2 mins to complete..
        # read file contents:
	while read line
	do
		#check every line, since we have names as list..
#use of 'dig' command:	#dig +short $line | sed -n '2{p;q}' #sed -n prevents printing default input '2' causes it to execute 'p;q' and 'p' is for print and 'q' to quit:
		#but 'host' works better:
		host $line | awk '/has address/ { print $4 }'
	done < $domainNames > $IPAddresses
        true
            
    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        # Write your code here...
        # This might also take a while.. (seconds... up to 1 minutes)
        # read file contents:
	while read line
	do
		echo "No need to worry..Executing..."
		#iptables -A INPUT -s $line -j REJECT
		iptables -A OUTPUT -s $line -j REJECT
		#iptables -P OUTPUT ACCEPT
	done < $IPAddresses
	echo "Rules have been created."
	echo "All done!"
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        # Write your code here...
        # ...
	echo "Saving rules..."
	iptables-save > $adblockRules
	echo "Save complete!"
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        # Write your code here...
        # ...
	echo "Loading rules..."
	iptables-restore < $adblockRules
	echo "Loading complete!"
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        # Write your code here...
        # ...
        # ...
	echo "Deleting firewall rules..."
	iptables -F INPUT
	iptables -F OUTPUT
	iptables -F FORWARD
	echo "Rules are set to default (ACCEPT)."
	echo "Reset done!"
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        # Write your code here...
        # so easy...:
	iptables -S
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
	printf "Try option -h for help menu.\n"
        exit 1
    fi
}

adBlock $1
exit 0
