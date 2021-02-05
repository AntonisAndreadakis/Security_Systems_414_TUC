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
        
        input=$domainNames
        [ ! -f "$input" ] && { echo "$0: File $input not found."; exit 1; }

        IPT=/sbin/iptables
        
        egrep -v "^#|^$" x | while IFS= read -r domain
        do
        	# get the ip addr of the domain
        	dig +short $domain &>> IPAddresses.txt
		done <"${input}"

		sth="IPAddresses.txt"
		
		egrep -v "^#|^$" x | while IFS= read -r ip
		
		do
			sudo $IPT -A INPUT -s $ip -j REJECT
			sudo $IPT -A FORWARD -s $ip -j REJECT
			sudo $IPT -A OUTPUT -d $ip -j REJECT
		done <"${sth}"
        
        true
            
    elif [ "$1" = "-ips"  ]; then

    	input=$IPAddresses
        [ ! -f "$input" ] && { echo "$0: File $_input not found."; exit 1; }
        
        IPT=/sbin/iptables
        
        egrep -v "^#|^$" x | while IFS= read -r ip
		
		do
			sudo $IPT -A INPUT -s $ip -j REJECT
			sudo $IPT -A FORWARD -s $ip -j REJECT
			sudo $IPT -A OUTPUT -d $ip -j REJECT
		done <"${input}"
        true
        
    elif [ "$1" = "-save"  ]; then
        sudo iptables-save > adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        sudo iptables-restore < adblockRules
        true

        
    elif [ "$1" = "-reset"  ]; then
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -F
        sudo iptables -X
        true

        
    elif [ "$1" = "-list"  ]; then
        sudo iptables -L -n -v
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
        exit 1
    fi
}

adBlock $1
exit 0