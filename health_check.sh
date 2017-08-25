#!/bin/bash

# Uncomment to list a series of comma seperated ports to scan, otherwise this uses the default.
#nmap_port_overide='21,22,25,80,443,1022,2222,3306,8080,8081'

# DNS Server we use dig's overide to force this server instead of the server listed in /etc/resolve.conf
dns=8.8.8.8

#And the program, nothing below here should need to be edited.

version="1.0"

reset="\e[0m"
#light red
failureColor="\e[91m"
#Green
passColor="\e[32m"
#light yellow
skipColor="\e[93m"

pass="${reset}[ ${passColor}Success${reset} ]"
fail="${reset}[ ${failureColor}Failure${reset} ]"
skip="${reset}[ ${skipColor}Skipped${reset} ]"
info="${reset}[  ${skipColor}Info${reset}   ]"

#Addiational MX check for gmail using domains.
gmail_main="ASPMX.L.GOOGLE.COM"

ipaddr=0
dns_check=1

if [[ -z $1 ]]; then
echo ""
echo "Usage:  ./health_check.sh <domain>"
echo "        ./health_check.sh <ip address>"
echo ""
exit
fi

input=$1



echo ""
echo -e "--- ${passColor}Health Check${reset} ---"
echo -e "--- version $version  ---"
echo ""

echo "Checking: $input"

function check_if_ip {
	reverse=""
	is_ip=0
	if expr "$1" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
		is_ip=1
		reverse=`dig -x $1 +short | head -n 1`
		reverse="(Reverse DNS: $reverse)"
	else
		if [[ $2 -ne 1 ]]; then
			resolve_ip=`dig a $1 @$dns +short | head -n1`
			reverse_tmp=`dig -x $resolve_ip +short | head -n1`
			if [[ -z $reverse_tmp  ]]; then
				reverse_tmp="${failureColor}No Reverse DNS${reset}"
			fi
			reverse="(Resolves to: $resolve_ip / Reverse DNS: $reverse_tmp)"
		fi
	fi
}

function check_port {
	port_open=0
	nmap $1 -p $2 -Pn > .port_check.tmp
	port_report="${failureColor}Port $2 is closed or unable to be reached${reset}"
	grep "open" .port_check.tmp > /dev/null
	result=$?
	if [[ $result -eq 0 ]]; then
		port_open=1
		port_report="${passColor}Port $2 is listening${reset}"
	fi
}

function set_check {
	check="${skipColor}$1${reset}:"
}


check_if_ip $input 1

if [[ is_ip -eq 1 ]]; then
	dns_check=0
	ipaddr=1
fi





#Get Base domain ISO standard format dictates that:
#
#   "All ASCII ccTLD identifiers are two letters long, and all two-letter top-level domains are ccTLDs."
#
if [[ $ipaddr -eq 0 ]]; then
domain=`echo $input | awk '
        {
                gsub( "^.*://", "", $1 );      # ditch the http://  ftp:// etc
                n = split( $1, a, "." );
                if( length( a[n] ) == 2 )       # assuming all two character top level domains are country codes
                        printf( "%s.%s.%s\n", a[n-2], a[n-1], a[n] );
                else
                        printf( "%s.%s\n",  a[n-1], a[n] );
        }
'`
	echo "Domain Name: $domain"
fi
echo ""
############################  
############################  DNS Check
############################  
set_check "DNS Check"
if [[ $dns_check -eq 1 ]]; then
	nslookup $input >/dev/null
	result=$?
	if [[ $result -ne 0 ]]; then
		echo -e "${fail} ${check} $input does not resolve."
		dns_check=0
	else
		#What does it resolve to?		
		resolves=`dig $input +short @$dns| tee .dns_check.tmp`
		#Resolve to multiple IP addresses or domains?
		lines=`wc -l .dns_check.tmp | awk -F ' ' '{print $1}'`
		if [[ $lines -ne 1 ]]; then
			echo -e "${pass} ${check} $input resolves to multiple records... ${reset}"
			num=1
			for line in $(cat .dns_check.tmp)
			do
				echo -e "${info} [${num}] $line"
				((num++))
			done
		else 
			echo -e "${pass} ${check} $input resolves to ${skipColor} $resolves ${reset}" 
		fi
	fi
	
else
	echo -e "${skip} ${check::-1} ${reset}"
fi
echo ""

############################  
############################  SOA recent change check.
############################  Checks if the SOA on a DNS server is the same as what is on the domains name server, if they differ then chances are there was a recent DNS change or it's not
############################  Propogated.
set_check "DNS Propogation"
if [[ $dns_check -eq 1 ]]; then
	nameserver=`dig ns $domain +short | head -n 1 | sed -r 's/\\.$//'`
	#echo "Nameserver: $nameserver"
	cached=`dig soa $domain +short @$dns | awk -F ' ' '{print $3}'`
	current=`dig soa $domain +short @$nameserver | awk -F ' ' '{print $3}'`
	#echo "Cached: $cached"
	#echo "Nameserver: $current"
	if [[ $cached -eq $current ]]; then
		echo -e "${pass} $check DNS appears propogated (SOA: $cached) ${reset}"
	else
		echo -e "${fail} $check DNS SOA for $domain differs. ${reset}"
		echo -e "${info} $dns : $cached ${reset}"
		echo -e "${info} $nameserver : $current ${reset}"
	fi

else
	echo -e "${skip} ${check::-1}  ${reset}"
fi
echo ""

############################  
############################  MX Check
############################  
set_check "DNS MX Record" 
if [[ $dns_check -eq 1 ]]; then
	mx=`dig mx $domain @$dns +short | sort -n | awk -F ' ' '{print $NF}' | tee .mx_check.tmp`
	grep "." .mx_check.tmp > /dev/null
	result=$?
	grep -i "google.com" .mx_check.tmp > /dev/null
	google=$?
	if [[ $result -eq 0 ]]; then	
		lines=`wc -l .mx_check.tmp | awk -F ' ' '{print $1}'`

		if [[ $lines -ne 1 ]]; then
			echo -e "${pass} $check $domain MX record resolves to multiple records (listed in priority order)... ${reset}"
			num=1
			for line in $(cat .mx_check.tmp)
			do
				if [[ $google -eq 0 && $num -eq 1 ]]; then
					echo "$line" | grep -i $gmail_main > /dev/null
					if [[ $? -ne 0 ]]; then
						echo -e "${info} Domain appears to be using G Suite (Gmail) for email but does not have $gmail_main as first priority MX record"
					fi
				fi
				check_if_ip $line
				check_port $line 25
				echo -e "${info} [${num}] $line $reverse $port_report"
				((num++))
			done
		else
			check_if_ip $resolves
			check_port $resolves 25
			echo -e "${pass} $check $domain MX record resolves to ${skipColor} $resolves $reverse $port_report ${reset}"
			
		fi
	else
		echo -e "${fail} $check $domain MX record is not set. ${reset}"
	fi
else
        echo -e "${skip} ${check::-1} ${reset}"
fi
echo ""

############################  
############################  Ping Check
############################  
set_check "Ping"
if [[ $ipaddr -eq 1 || $dns_check -eq 1 ]]; then
	ping $input -c 2 2>&1 > .ping_check.tmp
	result=$?
	ping=0
	if [[ $result -eq 0 ]]; then
		echo -e "${pass} $check $input can be pinged";
		ping=1
	else
		echo -e "${fail} $check $input cannot be pinged";
	fi
else
	echo -e "${skip} ${check::-1} ${reset}"
fi
echo ""

############################
############################  Port Check
############################
set_check "Nmap Port Scan"
if [[ $ipaddr -eq 1 || $dns_check -eq 1 ]]; then
	if [[ -z $nmap_port_overide ]]; then
		nmap_noping_option="-p 21,22,25,80,443,1022,2222,3306,8080,8081 -Pn"
	else
		nmap_noping_option="-p $nmap_port_overide -Pn"
	fi
	if [[ $ping -eq 1 ]]; then
		nmap_option=""
	else
		nmap_option=$nmap_noping_option
		echo -e "${info} Port Check may take longer on unpingable servers.  ${failureColor}!!! Only checking specific ports !!! ${reset}"
	fi

	nmap $input ${nmap_option} > .port_check.tmp
	grep "Host is up" .port_check.tmp > /dev/null
	result=$?
	if [[ $result -eq 0 ]]; then
		echo -e "${pass} $check Server responds to port checks. ${reset}"
	else
		#One more try
		if [[ $ping -eq 1 ]]; then
			nmap $input ${nmap_noping_option} > .port_check.tmp
			grep "Host is up" .port_check.tmp > /dev/null
			result=$?
			if [[ $result -eq 0 ]]; then
				echo -e "${pass} $check Server responds to port checks. ${reset}"
			else
				echo -e "${fail} $check Server does not respond to port checks ${reset}"
			fi
		else
			echo -e "${fail} $check Server does not respond to port checks ${reset}"
		fi
	fi
else
	echo -e "${skip} ${check::-1} ${reset}"
fi

echo ""
