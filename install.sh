#!/bin/bash
# smbexec installer v1.1.1
# Last updated 11/12/2012

##################################################
f_debian(){
	clear
	f_Banner
	f_install

	echo -e "\n\e[1;33m[*] Installing pre-reqs for Debian/Ubuntu...\e[0m\n"

	if [ ! -e /etc/lsb-release ] && [ ! -e /etc/issue ]; then echo -n -e "\e[1;31m[!] I can't confirm this is a Debian\Ubuntu machine. Installs may fail.\e[0m"; read; fi

	echo -e "\e[1;33m[*] Running 'updatedb'\e[0m\n"
	updatedb

	reqs="wget gcc mingw32-runtime mingw-w64 gcc-mingw32 mingw32-binutils xterm"
	for i in $reqs; do
		dpkg -s "$i" &> /tmp/checkinstall
		isinstalled=$(cat /tmp/checkinstall | grep -o "Status: install ok installed")
		if [ -z "$isinstalled" ]; then
			echo -e "\e[1;33m[-] $i is not installed, will attempt to install from repos\e[0m"

			if [ ! -z $(apt-get install -y "$i" | grep -o "E: Couldn") ]; then
				echo -e "\e[1;31m[-] $i could not be installed from the repository\e[0m"
			else
				dpkg -s "$i" &> /tmp/checkinstall
				isinstalled=$(cat /tmp/checkinstall | grep -o "Status: install ok installed")				
				if [ ! -z "$isinstalled" ]; then
					update=1
					echo -e "\t\e[1;32m[+] $i was successfully installed from the repository.\e[0m"

				else
					echo -e "\t\e[1;31m[!] Something went wrong, unable to install $i.\e[0m"
				fi
			fi
		else
			echo -e "\e[1;32m[+] I found $i installed on your system\e[0m"
		fi
        done

	#Creddump function to find/install
	f_creddump
	#ntds extract for AD hash dumping
	f_ntdsxtract
	#libesedb extract for AD hash dumping
	f_libesedb

	dpkg -s nmap &> /tmp/checkinstall #Adding this here or else uninstalled package spews errors to user screen
	if [ ! -e /usr/bin/nmap ] && [ ! -e /usr/local/bin/nmap ] && [ -z $(cat /tmp/checkinstall | grep -o "Status: install ok installed") ]; then
		f_nmapinstall
	else
		echo -e "\e[1;32m[+] I found nmap installed on your system\e[0m"
	fi

	if [[ -z $(locate -b "\msfconsole") ]]; then
		f_metasploitinstall
	else
		echo -e "\e[1;32m[+] I found metasploit installed on your system\e[0m"
	fi

	if [ "$update" == "1" ]; then
		echo -e "\e[1;33m[*] Running 'updatedb' again because we installed some new stuff\e[0m\n"
		updatedb
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	else
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	fi

rm -rf /tmp/smbexec/
}

##################################################
f_rhfedora(){
	clear
	f_Banner
	f_install

        echo -e "\n\e[1;33m[*] Installing pre-reqs for Red Hat/Fedora...\e[0m\n"

	if [ ! -e /etc/redhat-release ]; then echo -n -e "\e[1;31m[!] I can't confirm this is a Red Hat/Fedora machine. Installs may fail.\e[0m"; read; fi

	echo -e "\e[1;33m[*] Running 'updatedb'\e[0m\n"
	updatedb

	reqs="wget gcc gcc-c++ mingw32-gcc mingw32-binutils xterm"
        for i in $reqs; do
                if [ -z $(rpm -qa $i) 2>/dev/null ]; then
                        echo -e "\e[1;31m[-] $i is not installed, will attempt to install from repos\e[0m"
			yum install -y $i &>/dev/null

			if [ -z $(rpm -qa $i) ]; then
				echo -e "  \e[1;31m[-] $i could not be installed from the repository.\e[0m"
			else
				update=1
			    	echo -e "\t\e[1;32m[+] $i was successfully installed from the repository.\e[0m"
			fi
		else
		    	echo -e "\e[1;32m[+] I found $i installed on your system\e[0m"
		fi
        done

	#Creddump function to find/install
	f_creddump
	#ntds extract for AD hash dumping
	f_ntdsxtract
	#libesedb extract for AD hash dumping
	f_libesedb

	if [ ! -e /usr/bin/nmap ] && [ ! -e /usr/local/bin/nmap ] && [ -z $(rpm -qa nmap) ]; then
		echo -e "\e[1;31m[-] nmap is not installed, will attempt to install from nmap.org\e[0m"
		sleep 3
		f_nmapinstall
	else
		echo -e "\e[1;32m[+] I found nmap installed on your system\e[0m"
	fi

	if [[ -z $(locate -b "\msfconsole") ]]; then
		echo -e "\e\n[1;31m[-] Metasploit is not installed, will attempt to install from metasploit.com\e[0m"
		sleep 3
		f_metasploitinstall
	else
		echo -e "\e[1;32m[+] I found metasploit installed on your system\e[0m"
	fi

	if [ "$update" == "1" ]; then
		echo -e "\n\e[1;33m[*] Running 'updatedb' again because we installed some new stuff\e[0m\n"
		updatedb
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	else
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	fi

rm -rf /tmp/smbexec/
}

##################################################
f_microsoft(){
	clear
	f_Banner
	echo "Seriously!?!?! smbexec doesn't run on Windows!!!"
	echo -e "You need to learn you some Linux!\nHere's some links...\n"
	echo -e "- http://www.ubuntu.com\n- http://www.debian.org\n- http://fedoraproject.org\n- http://www.gentoo.org"
	echo -e "\nA whole world of awesomness awaits!\n\n"

	echo "                 .88888888:."
	echo "                88888888.88888."
	echo "             .8888888888888888."
	echo "              888888888888888888"
	echo "              88' _\`88'_  \`88888"
	echo "              88 88 88 88  88888"
	echo "              88_88_::_88_:88888"
	echo "              88:::,::,:::::8888"
	echo "              88\`:::::::::'\`8888"
	echo "             .88  \`::::'    8:88."
	echo "            8888            \`8:888." 
	echo "          .8888'             \`888888." 
	echo "         .8888:..  .::.  ...:'8888888:." 
	echo "        .8888.'     :'     \`'::\`88:88888" 
	echo "       .8888        '         \`.888:8888." 
	echo "      888:8         .           888:88888 "
	echo "    .888:88        .:           888:88888:" 
	echo "    8888888.       ::           88:888888" 
	echo "    \`.::.888.      ::          .88888888" 
	echo "   .::::::.888.    ::         :::\`8888'.:." 
	echo "  ::::::::::.888   '         .::::::::::::" 
	echo "  ::::::::::::.8    '      .:8::::::::::::." 
	echo " .::::::::::::::.        .:888::::::::::::: "
	echo " :::::::::::::::88:.__..:88888:::::::::::'" 
	echo "  \`'.:::::::::::88888888888.88:::::::::'" 
	echo "        \`':::_:' -- '' -'-' \`':_::::'\` "

	read

	f_mainmenu
}

##################################################
f_install(){

if [ ! -e /tmp/smbexec/ ]; then mkdir /tmp/smbexec/; fi

	while [[ $valid != 1 ]]; do
		read -e -p "Please provide the path you'd like to place the smbexec folder. [/opt] : " smbexecpath	
		if [ -z $smbexecpath ]; then 
			smbexecpath="/opt"
			valid=1
		elif [ -e $smbexecpath ]; then 
			valid=1
		else		
			echo "Not a valid file path."
		fi
	done
	
	# Remove the ending slash if it exists in path
	smbexecpath=$(echo $smbexecpath | sed 's/\/$//g')

	if [ $PWD/smbexec == $smbexecpath/smbexec ]; then 
		echo "Can't install into the folder.....from the folder.  Choose a different path."
		unset smbexecpath
		sleep 5
		f_install
	else
		# CD out of folder, mv folder to specified path and create symbolic link
		cd ..
		rm -rf $smbexecpath/smbexec > /dev/null
		mv $PWD/smbexec $smbexecpath/smbexec
		chmod 755 $smbexecpath/smbexec/smbexec.sh
		chmod 755 $smbexecpath/smbexec/progs/*
		ln -f -s $smbexecpath/smbexec/smbexec.sh /usr/bin/smbexec
	fi

	# Workaround to get rid of annoying samba error for patched smbclient
	if [ ! -e /usr/local/samba/lib/smb.conf ]; then
		mkdir -p /usr/local/samba/lib/
		cp $smbexecpath/smbexec/patches/smb.conf /usr/local/samba/lib/smb.conf
	fi
}

##################################################
f_ntdsxtract(){
NTDSXtractinstall=$(locate -l 1 -b "\dsusers.py")

if [ ! -z "$NTDSXtractinstall" ]; then
	echo -e "\e[1;32m[+] I found NTDSXtract on your system\e[0m"
else
	echo -e "\n\e[1;33m[*] Downloading NTDSXTRACT from ntdsxtract.com...\e[0m"
	sleep 2
	wget http://www.ntdsxtract.com/downloads/ntdsxtract/ntdsxtract_v1_0.zip -O /tmp/smbexec/ntdsxtract_v1_0.zip
	unzip /tmp/smbexec/ntdsxtract_v1_0.zip -d /tmp/smbexec/
	mv /tmp/smbexec/NTDSXtract\ 1.0 /opt/NTDSXtract
	if [ -e /opt/NTDSXtract/dsusers.py ]; then
		echo -e "\n\e[1;32m[+] NTDSXtract has been installed...\e[0m"
	else
		echo -e "\e[1;31m[!] NTDSXtract didn't install properly. You may need to do it manually\e[0m"
	fi
fi

}

##################################################
f_libesedb(){
esedbexportinstall=$(locate -l 1 -b "\esedbexport")

if [ ! -z "$esedbexportinstall" ]; then
	echo -e "\e[1;32m[+] I found esedbexport on your system\e[0m"
else
	echo -e "\n\e[1;33m[*] Downloading libesedb from googlecode.com...\e[0m"
	sleep 2
	wget http://libesedb.googlecode.com/files/libesedb-alpha-20120102.tar.gz -O /tmp/smbexec/libesedb-alpha-20120102.tar.gz
	tar -zxf /tmp/smbexec/libesedb-alpha-20120102.tar.gz -C /tmp/smbexec/
	currentpath=$PWD
	echo -e "\n\e[1;33m[*] Compiling esedbtools...\e[0m"
	sleep 2
	cd /tmp/smbexec/libesedb-20120102/
	./configure --enable-static-executables && make
	mv /tmp/smbexec/libesedb-20120102/esedbtools /opt/esedbtools
	cd "$currentpath"
	if [ -e /opt/esedbtools/esedbexport ] && [ -x /opt/esedbtools/esedbexport ]; then
		echo -e "\n\e[1;32m[+] esedbtools have been installed...\e[0m"
	else
		echo -e "\e[1;31m[!] esedbtools didn't install properly. You may need to do it manually\e[0m"
	fi
fi
}

##################################################
f_metasploitinstall(){
update=1
echo -e "\n\e[1;33m[*] Downloading Metasploit from metasploit.com, this will take a while to complete\e[0m"

if [ $(uname -m) == "x86_64" ]; then
	wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run -O /tmp/metasploit-latest-linux-x64-installer.run
	echo -e "\n\e[1;33m[*] The Metasploit installer will walk you through the rest of the process\e[0m"
	sleep 5
	chmod 755 /tmp/metasploit-latest-linux-x64-installer.run
	/tmp/metasploit-latest-linux-x64-installer.run
else
	wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-installer.run -O /tmp/metasploit-latest-linux-installer.run
	echo -e "\n\e[1;33m[*] The Metasploit installer will walk you through the rest of the process\e[0m"
	sleep 5
	chmod 755 /tmp/metasploit-latest-linux-installer.run
	/tmp/metasploit-latest-linux-installer.run
fi

if [ ! -e /usr/local/bin/msfconsole ]; then
	echo -e "\e[1;31m[!] Something went wrong, Metasploit did not install properly\e[0m"
else	

	msfprogs="msfconsole msfupdate msfencode msfpayload"
	for z in $msfprogs; do
		if [ ! -e /usr/bin/$z ]; then
			ln -f -s /usr/local/bin/$z /usr/bin/$z
		fi
	done
	echo -e "\n\e[1;32m[+] Metasploit has been installed...\e[0m"
fi

sleep 5
}

##################################################
f_nmapinstall(){
update=1
echo -e "\n\e[1;33m[*] Downloading nmap-6.0.1 from nmap.org, this may take a while to complete\e[0m"
wget http://nmap.org/dist/nmap-6.01.tgz -O /tmp/nmap-6.0.1.tgz
cd /tmp
tar xf nmap-6.0.1.tgz
cd nmap-6.01/
echo -e "\n\e[1;33m[*] Installing nmap-6.0.1 on your system\e[0m"
sleep 3
./configure
make && make install

if [ ! -e /usr/bin/nmap ] && [ ! -e /usr/local/bin/nmap ]; then
	echo -e "\e[1;31m[!] Something went wrong, nmap did not install properly\e[0m"
else
	echo -e "\n\e[1;32m[+] nmap has been installed...\e[0m"
fi

if [ ! -e /usr/bin/nmap ]; then
	ln -f -s /usr/local/bin/nmap /usr/bin/nmap
fi

sleep 5

}

##################################################
f_creddump(){
creddumpinstall=$(locate -l 1 -b "\cachedump.py")

if [ ! -z "$creddumpinstall" ]; then
	echo -e "\e[1;32m[+] I found creddump on your system\e[0m"
else
	update=1
	echo -e "\e[1;33m[-] Could not find creddump on your system, will attempt to download v0.3 from Google code\e[0m"
	wget http://creddump.googlecode.com/files/creddump-0.3.tar.bz2 -O /tmp/smbexec/creddump-0.3.tar.bz2
	tar -xjf /tmp/smbexec/creddump-0.3.tar.bz2 -C /tmp/smbexec/
	mkdir /opt/creddump
	cp -R /tmp/smbexec/creddump-0.3/* /opt/creddump/
	if [ -e /opt/creddump/pwdump.py ]; then
		echo -e "\n\e[1;32m[+] creddump has been installed...\e[0m"
	else
		echo -e "\e[1;31m[!] creddump didn't install properly. You may need to do it manually\e[0m"
	fi
fi

}

##################################################
f_compilesmbclient(){
echo -e "\n\e[1;33m[*] Extracting samba...\e[0m"
sleep 2
tar -zxf $path/sources/samba-3.6.9.tar.gz -C /tmp/smbexec/ > /dev/null 2>&1
cp $path/patches/samba-3.6.9-hashpass.patch /tmp/smbexec/samba-3.6.9/samba-3.6.9-hashpass.patch
cd /tmp/smbexec/samba-3.6.9
echo -e "\n\e[1;33m[*] Patching samba to accept hashes...\e[0m"
sleep 2
patch -p1 < samba-3.6.9-hashpass.patch > /dev/null 2>&1
echo -e "\n\e[1;33m[*] Compiling smbexeclient, this may take a while...\e[0m"
sleep 2
cd /tmp/smbexec/samba-3.6.9/source3/ && ./configure && make
mv /tmp/smbexec/samba-3.6.9/source3/bin/smbclient $path/progs/smbexeclient 
cd $path

if [ -e $path/progs/smbexeclient ]; then
	echo -e "\n\e[1;32m[+] smbexeclient has been compiled and moved to the progs folder...\e[0m"
	sleep 3
else
	echo -e "\e[1;31m[!] smbexeclient didn't install properly. Make sure you have prereqs installed...\e[0m"
	sleep 5
fi
}

##################################################
f_compilewinexe(){
echo -e "\n\e[1;33m[*] Extracting winexe...\e[0m"
sleep 2
tar -zxf $path/sources/winexe-1.00.tar.gz -C /tmp/smbexec/
cp $path/patches/winexe-1.0-hashpass.patch /tmp/smbexec/winexe-1.00/winexe-1.0-hashpass.patch
cd /tmp/smbexec/winexe-1.00
echo -e "\n\e[1;33m[*] Patching winexe to accept hashes...\e[0m"
sleep 2
patch -p1 < winexe-1.0-hashpass.patch > /dev/null 2>&1
echo -e "\n\e[1;33m[*] Compiling smbwinexe, this may take a while...\e[0m"
sleep 2
cd /tmp/smbexec/winexe-1.00/source4 && ./autogen.sh && ./configure && make
mv /tmp/smbexec/winexe-1.00/source4/bin/winexe $path/progs/smbwinexe
cd $path

if [ -e $path/progs/smbwinexe ]; then
	echo -e "\n\e[1;32m[+] smbwinexe has been compiled and moved to the progs folder...\e[0m"
	sleep 3
else
	echo -e "\e[1;31m[!] smbwinexe didn't install properly. Make sure you have prereqs installed...\e[0m"
	sleep 5
fi

}

##################################################
f_compilebinaries(){
path=$PWD
echo -e "\nThis script will compile your smbexec binaries\nPress any key to continue"
read
if [ ! -e /tmp/smbexec ]; then
 mkdir /tmp/smbexec/
fi
f_compilesmbclient
f_compilewinexe
f_mainmenu
}

##################################################

f_Banner(){
echo "************************************************************"
echo -e "		    \e[1;36msmbexec installer\e[0m       "
echo "	A rapid psexec style attack with samba tools              "
echo "      Original Concept and Script by Brav0Hax & Purehate    "
echo "              Codename - Diamond in the Rough	          "
echo -e "             Gonna pha-q up - \e[1;35mPurpleTeam\e[0m Smash!"
echo "************************************************************"
echo
}

##################################################
f_mainmenu(){
clear
f_Banner
	echo "Please choose your OS to install smbexec"
	echo "1.  Compile smbexec binaries"
	echo "2.  Debian/Ubuntu and derivatives"
	echo "3.  Red Hat or Fedora"
	echo "4.  Microsoft Windows"
	echo "5.  Exit"
	echo
	read -p "Choice: " mainchoice

	case $mainchoice in
	1) f_compilebinaries ;;
	2) f_debian ;;
	3) f_rhfedora ;;
	4) f_microsoft ;;
	*) clear;exit ;;
	esac

}
# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[!] This script must be run as root\e[0m" 1>&2
	exit 1
else
	f_mainmenu
fi
