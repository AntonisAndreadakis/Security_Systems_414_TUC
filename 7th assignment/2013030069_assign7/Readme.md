Andreadakis Antonios - 2013030059 - LAB41446117


## Description:

	Simple adblocking mechanism. Our purpose is to develop a programm, in order to prevent unwanted
	ads to pop up while we visit a website. We got familiar with iptables rules. Iptables command is
	used to maintain, set up and inspect the tables of IP packet filter rules in Linux kernel.
	Each table contains a number of built-in chains and may also contain user-defined chains. Each
	chain is a list of rules which can match a set of packets. Each rule specifies what to do with
	a packet that got matched. So, we implement a simple adblock mechanism that rejects packets
	coming from specific network advertising domains. A file named `domainNames.txt` was provided
	with those domains. All we needed to do was, extract info from that file and get the ip (or ips)
	for every domain and build some rules. More details described on section `Notes` below.


## Modes:

	`adblock.sh`:	executable for our purpose


## Running:

	sudo ./adblock.sh -[option]		->run executable with any available option (see -h for help)


## Notes:

	`running`:			->	Script must execute in root mode (using sudo).

	`options`:
	                -domains	->	Read the file `domainNames.txt` and for every line containing a domain name, I used `host` command and
	                                        got all ips for every domain name, in 1-2 minutes. Using `dig` command, we get results faster
	                                        (but not all ips). So I configure domains from `domainNames.txt` file and store ip at IPAddresses.txt file.

	                -ips		->	Configure adblock rules based on the IP addresses of IPAddresses.txt file. Read the file and for
	                  		      	every line I used `iptables -A OUTPUT -s $line -j REJECT` command.
						>	-A OUTPUT stands for append/add a rule
						>	The option -j (originally "jump") specifies what to do when the rule matches. You can jump to a
							different chain or you can ACCEPT (stop processing rules and send this packet) or you can REJECT
							(stop processing rules and ignore this packet).
	                        		So it's this last rule that does the actual blocking.

	                -save		->	Save rules to adblockRules.txt file. Using command `iptables-save > $adblockRules`
	                                        we store our rules into adblockRules file.

	                -load		->	Load rules from adblockRules file using `iptables-restore < $adblockRules` command.

	               	-reset		->	All current rules in iptables are cleared using:
								>	iptables -F INPUT
								>	iptables -F OUTPUT
								>	iptables -F FORWARD

	                -list		->	List current rules using `iptables -S` command.
	
	
