Code developed under HPY417 - Systems and Information Security, ECE TUC 2020-21 Winter Sem.


	Konstantinos Pantelis	 -   	LAB41446433/Assignment 7
	2015030070
	Undergrad. Student@ECE TUC
	kpantelis@isc.tuc.gr
	github.com/apfel-das/securious-tuc 
	


	** ASSIGNMENT 7 **



	** WHAT I'VE DONE **

	- Resolved Hostnames via Google's DNS [8.8.8.8] into IPv4's in a quick manner (59 - 121 secs for 353 IPs).
	- Learned to use threads in Bash (that's something definettly).
	- Understood how my slow - default DNS server slows resolving even in simple hosts (courses.ece.tuc.gr for instance..).
	- Wrote down some rules to prevent forward, input action on unwanted IPs via iptables. 
	- Rules work on redirection and blocking traffic, yet pop-ups/ads exist (I'll analyse more below..).
	- To format rules I tend to prefer DROP over REJECT in order not to notify the other end (based on this: https://serverfault.com/questions/157375/reject-vs-drop-when-using-iptables).

	** WHAT I'VE TRIED **

	- Downloading the whole HTML of domain, and blocking subdomains.
	- Worked in some occurences [sport24.gr, xhamster.com] but took more than "an era" to run.
	- So it doesn't seem like a good choice.


	** HOSTNAMES RESOLUTION [ OR "How a simple process can take ages if not treated properly" ] **

	- Should be taking some time, but not that much.
	- I used the "dig" command (could also work with host/dnslookup) which seemed to work fine for one or two domains.
	- For the file given a "dig" took 600-800 seconds via the deafult DNS to run. That's outrageously long even if hacking NASA with HTML :D.
	- Therefore I changed DNS (used Google's public DNS), invoked "-tries/-time" flags and backround run as well (&, wait).
	- I "grep" the result via pipping as well. Only valids ips get to be use (some hosts are down, I don't care about them).
	- The used combo (with some experiments on tries/timeout values) gave me 354 IPs in not more than 2 minutes [best: 55 secs, worst: 122 secs], which for me is an acceptable delay.




	** ABOUT ADS/ ADBLOCKING **

	- Some ads are "hidden" inside either HTML/CSS of the page or loaded by the scripting lang. running on the page (JS/PHP/Python/etc.), those won't get blocked.
	- If an add open as a redirect, this won't get loaded that's all it can be done..
	- Blocking pop-ups/notifications won't work, an alternative to it would be blocking hosts themselves, like commercial adblockers tend to do.
	- Video ads (like youtube.com ones) use hosts rather ips, therefore script is useless and ineffective on them.
	- Tried blocking "courses.ece.tuc.gr" as well [worked], that would be a nice trick if applied on machines inside the TUC facillities.


	** A TEST CASE [which actually worked]**

	- "www.sport24.gr" is one of my favorite places to read about Football stuff, yet they are full of ads.
	- "https://www.sport24.gr/matchcenter/live-euroleague-23-12.9090248.html" has text and some (probably Javascript) content layered on an "on-click" add of "Stixoiman".
	- The advertisement is powered by "adclick.g.doubleclick.net" host, who has 216.58.207.34 (for now, he's constantly changing though).
	- If I invoke my script (either via adding the domain, or by manually adding the IPv4 I resolved) the ad gets vanished into thin air and I get my "clean" page backround back.


	** SCRIPT adblock.sh **

	- Should run as sudo.
	- Resolves hostnames into ips (relatively quickly) and writes addresses in IPAddreses.txt.	
	- Formats rules based on either resolved ips (hostnames should be given) via file IPAddresses.txt or given ones( just provide a file/or rename custom into "IPAddresses.txt").
	- Rules can also be saved/loaded in/from a file.
	- Rules on iptables can also be printed/resetted.
	
	** CONCLUSION **

	- Script acts a wrapper for most "iptable" commands..
	- Resolving is pretty tough/time-consuming process I have to admit..
	- I would definettly use iptables if wishing to monitor a set/family of computers (as an admin) in a network and block sites they visit but that should be all.
	- If I had to, I would block hosts in order not to see ads, I also noticed that the adblocket I use tends to act against the CSS of the page itsself in some case (youtube in-page ads).

	** NOTES **
	

	- Usage of Google's DNS is hardcoded in line 33 [change as per your needs].
	- Echoing in files happens via "&>>" so it should be "all-bash-varsions" compatible.
	- "dig -f .." can also be used to avoid the manual while-loop in DNS resolution, but unknown why this had side effects on run-time/speed.

	** PS **

	- Merry X-MAS and a Happy -covid free- Year.
