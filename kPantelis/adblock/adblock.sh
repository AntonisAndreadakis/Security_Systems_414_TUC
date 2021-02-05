#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"
ip_table="/sbin/iptables"



# reset's adblock rules to their initial format..
function reset_rules(){

	#set to accept all types of conns..
	"$ip_table" -P INPUT ACCEPT
	"$ip_table" -P OUTPUT ACCEPT
	"$ip_table" -P FORWARD ACCEPT

	#delete old rules; quick way used..

	"$ip_table" -F 
	"$ip_table" -X
}




#Configures given domains by resolving their ip; appends in a file to use later..
function resolve_hosts(){

	#get input file, output file..
	input_file=$domainNames
	output_file=$IPAddresses
	local dns_server="8.8.8.8" #google's DNS is quicker than mine; might end up not using that later..
	

	#be sure the file is there..
	if [[ ! -f "$input_file" ]]; then
		echo "[Error]: File not found, exiting.."
		exit -1
	fi

	#parse, resolve, exclude errors; redirect output as well..

	while IFS= read -r domain || [[ -n "$domain" ]]; 
	do
		
		# could also use "dig -f <filename>" but this takes more time; forcing -tries, -timeout makes thing also quicker in the sake of some results..
		dig @${dns_server} ${domain} +short +tries=2 +time=1 | grep  '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' &>> "${output_file}"

			
	done<"$input_file"

	

	

}

#make some blocking rules using iptables and a file specified by $IPAddresses..
function make_rules(){

	input_file=$IPAddresses

	#force sudo case timelimit reached due to resolution; seems to solve the issue..
	while IFS= read -r ip || [[ -n "$ip" ]]; do

		# I use DROP instead of REJECT so the other end knows nothing about rejection/me..
        # I finally decided to use REJECT cause its mentioned in "Hints" so it might make testing easier
		sudo "$ip_table" -A FORWARD -s "$ip" -j REJECT
		sudo "$ip_table" -A INPUT -s "$ip" -j REJECT
        sudo "$ip_table" -A OUTPUT -d "$ip" -j REJECT
        
	done < ${input_file}

}

#Script's handler, dont wait for much though..

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "[Issue]: Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        #Configure adblock rules based on the domain names of $domainNames file.
		

		#resolve and lock on process; this ensures procs won't get stoped by a terminal suspension..      
        resolve_hosts & #block takes 55-120 secs for about 354 IPv4's, (-time=1, -tries=2) seems like a good tradeoff..
        
        #wait for me man..
        pid=$!
        wait $pid 

        #just prompt the guy..
		
		if [[ "$?" -eq "0" ]]; then
			echo "[Log]: DNS resolved.."
		else
			echo "[Log]: Issue arrised upon DNS resolution.."
		fi

		#lock on rule making, might take time..
		make_rules & #not more than 30 secs for 354 IPv4's; seems cool..

       	pid=$!
       	wait $pid 

       	if [[ "$?" -eq "0" ]]; then
			echo "[Log]: Rules set.."
		else
			echo "[Log]: Issue arrised upon rule setting...."
		fi

        true
            
    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
       	
       	make_rules &

       	pid=$!
       	wait $pid 

       	if [[ "$?" -eq "0" ]]; then
			echo "[Log]: Rules set.."
		else
			echo "[Log]: Issue arrised upon rule setting...."
		fi





        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
       
    	sudo iptables-save > adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
      	
      	sudo iptables-restore < adblockRules
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
    

        reset_rules

        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
  		"$ip_table" -L -n -v 


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
        printf "[Error]: Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0