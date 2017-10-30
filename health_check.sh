#!/bin/bash

# Uncomment to list a series of comma seperated ports to scan, otherwise this uses the default.
#nmap_port_overide='21,22,25,80,443,1022,2222,3306,8080,8081'

# DNS Server we use dig's overide to force this server instead of the server listed in /etc/resolve.conf
dns=8.8.8.8
propcheck=(     '8.8.8.8', '165.87.13.129', '168.95.1.1', '64.6.64.6', '208.67.222.222')
propcheck_name=('Google',  'AT&T',          'HiNet (TW)', 'Verisign',  'OpenDNS')

#And the program, nothing below here should need to be edited.

version="1.1.3"

reset="\e[0m"
#light red
failureColor="\e[91m"
#Green
passColor="\e[32m"
#light yellow
skipColor="\e[93m"
linebuffer="---------------------------"

pass="${reset}[ ${passColor}Success${reset} ]"
fail="${reset}[ ${failureColor}Failure${reset} ]"
skip="${reset}[ ${skipColor}Skipped${reset} ]"
info="${reset}[  ${skipColor}Info${reset}   ]"

#Addiational MX check for gmail using domains.
gmail_main="ASPMX.L.GOOGLE.COM"
senderbase="score.senderscore.com"

### Check to see if this version of dig supports nocookie or not.
nocookie="+nocookie"
dig google.com @8.8.8.8 +nocookie &> /dev/null
result=$?
if [[ result -eq 1 ]]; then
	nocookie=""
fi

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
echo -e "--- ${passColor}Health Check${reset}  ---"
echo -e "--- version $version ---"
echo ""

function check_senderscore {
                        senderscorehost=`echo $1 | awk -F '.' '{print $4"."$3"."$2"."$1"."}'`
                        senderscorehost=${senderscorehost}${senderbase}
                        senderscore=`dig ${senderscorehost} +short | awk -F '.' '{print $4}'`
			if [[ "$senderscore" == "" ]]; then
                                senderscore="SenderScore: N/A"
                        else
				case $senderscore in
					100|9[0-9]|8[0-9])
						ss_color=$passColor
					;;
					7[0-9])
						ss_color=$skipColor
					;;
					*)
						ss_color=$failureColor
					;;
				esac
				senderscore="SenderScore: ${ss_color}${senderscore}${reset}"
                        fi
}

function check_if_ip {
	reverse=""
	is_ip=0
	if expr "$1" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
		is_ip=1
		reverse=`dig -x $1 +short $nocookie | head -n 1`
		reverse="(Reverse DNS: $reverse)"
		check_senderscore $1
		
	else
		if [[ $2 -ne 1 ]]; then
			resolve_ip=`dig a $1 @$dns +short $nocookie | head -n1`
			reverse_tmp=`dig -x $resolve_ip +short $nocookie | head -n1`
			check_senderscore $resolve_ip
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
	sed -n '/PORT.*STATE.*SERVICE/,/^$/p' .port_check.tmp | egrep "\bopen\b" &> /dev/null
	result=$?
	if [[ $result -eq 0 ]]; then
		port_open=1
		port_report="${passColor}Port $2 is listening${reset}"
	fi
}

function set_check {
	check="${skipColor}$1${reset}:"
}

function pass {
echo -e "${pass} $1 ${reset}"
}


function fail {
echo -e "${fail} $1 ${reset}"
}

function info {
echo -e "${info} $1 ${reset}"
}

function skip {
echo -e "${skip} ${check::-1}  ${reset}"
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
		fail "${check} ${input} does not resolve."
		dns_check=0
	else
		#What does it resolve to?		
		resolves=`dig $input +short $nocookie @$dns | tee .dns_check.tmp`
		#Resolve to multiple IP addresses or domains?
		lines=`wc -l .dns_check.tmp | awk -F ' ' '{print $1}'`
		
		if [[ $lines -eq 0 ]]; then
			fail "${check} $input does not resolve."
			dns_check=0
		else
			if [[ $lines -ne 1 ]]; then
				pass "$input resolves to multiple records..."
				num=1
				for line in $(cat .dns_check.tmp)
				do
					info "[${num}] $line"
					((num++))
				done
			else 
				pass "${check} $input resolves to ${skipColor} $resolves"
			fi
		fi
	fi
	
else
	skip
fi
echo ""

############################  
############################  SOA recent change check.
############################  Checks if the SOA on a DNS server is the same as what is on the domains name server, if they differ then chances are there was a recent DNS change or it's not
############################  Propogated.
set_check "DNS Propogation"
if [[ $dns_check -eq 1 ]]; then
	nameserver=`dig ns $domain +short $nocookie | head -n 1 | sed -r 's/\\.$//'`
	cached=`dig soa $domain +short $nocookie @$dns | awk -F ' ' '{print $3}'`
	current=`dig soa $domain +short $nocookie @$nameserver | awk -F ' ' '{print $3}'`
	if [[ $cached -eq $current ]]; then
		pass "$check DNS appears propogated (SOA: $cached)"
	else
		fail "$check DNS SOA for $domain differs."
		
		temp=`printf "%s %s %s\n" $dns ${linebuffer:${#dns}} $cached`
		info "$temp"
#		info  "$dns : $cached"
		temp=`printf "%s %s %s\n" $nameserver ${linebuffer:${#nameserver}} $current`
		info "$temp"
#		info  "$nameserver : $current"
	fi

else
		skip
fi
echo ""

############################  
############################  MX Check
############################  
set_check "DNS MX Record" 
if [[ $dns_check -eq 1 ]]; then
	mx=`dig mx $domain @$dns $nocookie +short | sort -n | awk -F ' ' '{print $NF}' | tee .mx_check.tmp`
	grep "." .mx_check.tmp > /dev/null
	result=$?
	grep -i "google.com" .mx_check.tmp > /dev/null
	google=$?
	if [[ $result -eq 0 ]]; then	
		lines=`wc -l .mx_check.tmp | awk -F ' ' '{print $1}'`

		if [[ $lines -ne 1 ]]; then
			pass "$check $domain MX record resolves to multiple records (listed in priority order)..."
			num=1
			for line in $(cat .mx_check.tmp)
			do
				if [[ $google -eq 0 && $num -eq 1 ]]; then
					echo "$line" | grep -i $gmail_main > /dev/null
					if [[ $? -ne 0 ]]; then
						info "Domain appears to be using G Suite (Gmail) for email but does not have $gmail_main as first priority MX record"
					fi
				fi
				check_if_ip $line
				check_port $line 25
				info "[${num}] $line $reverse $port_report $senderscore"
				((num++))
			done
		else
			check_if_ip $mx
			check_port $mx 25

			pass "$check $domain MX record resolves to ${skipColor} $mx $reverse $port_report $senderscore"
			
		fi
	else
		fail "$check $domain MX record is not set."
	fi
else
	skip
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
		pass "$check $input can be pinged"
		ping=1
	else
		fail "$check $input cannot be pinged"
	fi
else
	skip
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
		info "Port Check may take longer on unpingable servers.  ${failureColor}!!! Only checking specific ports !!!"
	fi

	nmap $input ${nmap_option} > .port_check.tmp
	sed -n '/PORT.*STATE.*SERVICE/,/^$/p' .port_check.tmp | egrep "\bopen\b" &> /dev/null
	result=$?
	if [[ $result -eq 0 ]]; then
		pass "$check Server responds to port checks."
	else
		#One more try
		if [[ $ping -eq 1 ]]; then
			nmap $input ${nmap_noping_option} > .port_check.tmp
			sed -n '/PORT.*STATE.*SERVICE/,/^$/p' .port_check.tmp | egrep "\bopen\b" &> /dev/null
			result=$?
			if [[ $result -eq 0 ]]; then
				pass "$check Server responds to port checks."
			else
				fail "$check Server does not respond to port checks."
			fi
		else
			fail "$check Server does not respond to port checks."
		fi
	fi
else
	skip
fi

echo ""
