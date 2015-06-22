#!/bin/bash
# smbexec installer
# Last updated 06/21/2015

##################################################
f_debian(){
	clear
	f_Banner
	f_install

	echo -e "\n\e[1;34m[*]\e[0m Installing pre-reqs for Debian/Ubuntu...\n"

	if [ ! -e /etc/lsb-release ] && [ ! -e /etc/issue ]; then echo -n -e "\e[1;31m[!]\e[0m I can't confirm this is a Debian\Ubuntu machine. Installs may fail."; read; fi

	echo -e "\e[1;34m[*]\e[0m Running 'updatedb' if it fails then install 'locate' from repos and try again\n"
	updatedb

	#Install the correct mingw
	mingw64=$(apt-cache search gcc-mingw-w64)

	if [ -z "$mingw64" ]; then
		echo -e "\e[1;34m[*]\e[0m Installing mingw requirements..."
		apt-get install -y mingw32-runtime gcc-mingw32 mingw32-binutils &> /tmp/smbexec-inst/checkinstall #Old systems, hopefully this is never used
	else
		echo -e "\e[1;34m[*]\e[0m Installing mingw requirements..."
		apt-get install -y binutils-mingw-w64 gcc-mingw-w64 mingw-w64 mingw-w64-dev &> /tmp/smbexec-inst/checkinstall
	fi

	reqs="bundler gcc libxml2-dev libxslt1-dev make nmap passing-the-hash python-crypto python-pyasn1 wget"
	for i in $reqs; do
		dpkg -s "$i" &> /tmp/smbexec-inst/checkinstall
		isinstalled=$(cat /tmp/smbexec-inst/checkinstall | grep -o "Status: install ok installed")
		if [ -z "$isinstalled" ]; then
			echo -e "\e[1;33m[-]\e[0m $i is not installed, will attempt to install from repos"

			if [ ! -z $(apt-get install -y "$i" | grep -o "E: Couldn") ]; then
				echo -e "\e[1;31m[-]\e[0m $i could not be installed from the repository"
			else
				dpkg -s "$i" &> /tmp/smbexec-inst/checkinstall
				isinstalled=$(cat /tmp/smbexec-inst/checkinstall | grep -o "Status: install ok installed")
				if [ ! -z "$isinstalled" ]; then
					update=1
					echo -e "\t\e[1;32m[+]\e[0m $i was successfully installed from the repository."
				else
					echo -e "\t\e[1;31m[!]\e[0m Something went wrong, unable to install $i."
				fi
			fi
		else
			echo -e "\e[1;32m[+]\e[0m I found $i installed on your system"
		fi
        done

	#Ruby Gem install
	f_gembundler
	#ntds extract for AD hash dumping
	f_ntdsxtract
	#libesedb extract for AD hash dumping
	f_libesedb
	#impacket for wmiexec.py
	f_impacket
	
	if [[ -z $(locate -b "\msfconsole") ]]; then
		f_metasploitinstall
	else
		echo -e "\e[1;32m[+]\e[0m I found metasploit installed on your system"
	fi

	if [ "$update" == "1" ]; then
		echo -e "\e[1;34m[*]\e[0m Running 'updatedb' again because we installed some new stuff\n"
		updatedb
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	else
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	fi

rm -rf /tmp/smbexec-inst/
}

##################################################
f_rhfedora(){
	clear
	f_Banner
	f_install

        echo -e "\n\e[1;34m[*]\e[0m Installing pre-reqs for Red Hat/Fedora...\n"

	if [ ! -e /etc/redhat-release ]; then echo -n -e "\e[1;31m[!]\e[0m I can't confirm this is a Red Hat/Fedora machine. Installs may fail."; read; fi

	echo -e "\e[1;34m[*]\e[0m Running 'updatedb', if it fails install 'locate' from repos and try again\n"
	updatedb
	
	reqs="gcc libxml libxslt make mingw32-binutils-generic mingw32-gcc nmap python-crypto python-pyasn1 rubygem-bundler wget"
        for i in $reqs; do
                if [ -z $(rpm -qa $i) 2>/dev/null ]; then
                        echo -e "\e[1;31m[-]\e[0m $i is not installed, will attempt to install from repos"
			yum install -y $i &>/dev/null

			if [ -z $(rpm -qa $i) ]; then
				echo -e "  \e[1;31m[-]\e[0m $i could not be installed from the repository."
			else
				update=1
			    	echo -e "\t\e[1;32m[+]\e[0m $i was successfully installed from the repository."
			fi
		else
		    	echo -e "\e[1;32m[+]\e[0m I found $i installed on your system"
		fi
        done
	
	#Ruby Gem install
	f_gembundler
	#ntds extract for AD hash dumping
	f_ntdsxtract
	#libesedb extract for AD hash dumping
	f_libesedb
	#impacket for wmiexec.py
	f_impacket

	if [[ -z $(locate -b "\msfconsole") ]]; then
		echo -e "\n\e[1;31m[-]\e[0m Metasploit is not installed, will attempt to install from metasploit.com"
		sleep 3
		f_metasploitinstall
	else
		echo -e "\e[1;32m[+]\e[0m I found metasploit installed on your system"
	fi

	if [ "$update" == "1" ]; then
		echo -e "\n\e[1;34m[*]\e[0m Running 'updatedb' again because we installed some new stuff\n"
		updatedb
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	else
		echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
	fi

rm -rf /tmp/smbexec-inst/
}

##################################################
f_install(){

if [ ! -e /tmp/smbexec-inst/ ]; then mkdir /tmp/smbexec-inst/; fi

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

	if [ $PWD == $smbexecpath/smbexec ]; then
		echo -e "\e[1;34m[*]\e[0m OK...keeping the folder where it is..."
		sleep 3
		chmod 755 $smbexecpath/smbexec/smbexec.rb
		chmod 755 $smbexecpath/smbexec/progs/*
		ln -f -s $smbexecpath/smbexec/smbexec.rb /usr/bin/smbexec
	else
		# CD out of folder, mv folder to specified path and create symbolic link
		cd ..
		rm -rf $smbexecpath/smbexec > /dev/null
		mv $PWD/smbexec $smbexecpath/smbexec
		chmod 755 $smbexecpath/smbexec/smbexec.rb
		chmod 755 $smbexecpath/smbexec/progs/*
		ln -f -s $smbexecpath/smbexec/smbexec.rb /usr/bin/smbexec
	fi

	# Workaround to get rid of annoying samba error for patched smbclient
	if [ ! -e /usr/local/samba/lib/smb.conf ]; then
		mkdir -p /usr/local/samba/lib/
		cp $smbexecpath/smbexec/patches/smb.conf /usr/local/samba/lib/smb.conf
	fi
}

##################################################
f_gembundler(){
	currentpath=$PWD
	echo -e "\e[1;34m[*]\e[0m Installing required ruby gems..."
	cd $smbexecpath/smbexec
	bundle install &> /tmp/smbexec-inst/geminstall
	geminstall=$(cat /tmp/smbexec-inst/geminstall|grep -o 'command not found')
		if [ -z "$geminstall" ]; then
			echo -e "\t\e[1;32m[+]\e[0m Gems were successfully installed."
		else
			echo -e "\t\e[1;31m[!]\e[0m Something went wrong, unable to install the gems."
			echo -e "\t\e[1;31m[!]\e[0m If you are using rvm run this command from the smbexec dir when installer completes:"
			echo -e "\t\e[1;31m[!]\e[0m rvmsudo bundle install"
		fi
	cd ${currentpath}
	currentpath=' '
}
##################################################
f_ntdsxtract(){
NTDSXtractinstall=$(locate -l 1 -b "\dsusers.py")

if [ ! -z "$NTDSXtractinstall" ]; then
	echo -e "\e[1;32m[+]\e[0m I found NTDSXtract on your system"
else
	echo -e "\n\e[1;34m[*]\e[0m Downloading NTDSXTRACT from github..."
	sleep 2
	wget https://github.com/csababarta/ntdsxtract/archive/master.zip -O /tmp/smbexec-inst/ntdsxtract.zip
	unzip /tmp/smbexec-inst/ntdsxtract.zip -d /tmp/smbexec-inst/
	mv /tmp/smbexec-inst/ntdsxtract-master /opt/NTDSXtract
	if [ -e /opt/NTDSXtract/dsusers.py ]; then
		echo -e "\n\e[1;32m[+]\e[0m NTDSXtract has been installed..."
	else
		echo -e "\e[1;31m[!]\e[0m NTDSXtract didn't install properly. You may need to do it manually"
	fi
fi

}

##################################################
f_libesedb(){
esedbexportinstall=$(locate -l 1 -b "\esedbexport")

if [ ! -z "$esedbexportinstall" ]; then
	echo -e "\e[1;32m[+]\e[0m I found esedbexport on your system"
else
	update=1
	echo -e "\n\e[1;34m[*]\e[0m Downloading libesedb from authors google docs drive..."
	sleep 2
	wget --no-check-certificate https://googledrive.com/host/0B3fBvzttpiiSN082cmxsbHB0anc/libesedb-alpha-20120102.tar.gz -O /tmp/smbexec-inst/libesedb-alpha-20120102.tar.gz
	tar -zxf /tmp/smbexec-inst/libesedb-alpha-20120102.tar.gz -C /tmp/smbexec-inst/
	currentpath=$PWD
	echo -e "\n\e[1;34m[*]\e[0m Compiling esedbtools..."
	sleep 2
	cd /tmp/smbexec-inst/libesedb-20120102/
	./configure --enable-static-executables=yes && make
	mv /tmp/smbexec-inst/libesedb-20120102/esedbtools /opt/esedbtools
	cd "$currentpath"
	if [ -e /opt/esedbtools/esedbexport ] && [ -x /opt/esedbtools/esedbexport ]; then
		echo -e "\n\e[1;32m[+]\e[0m esedbtools have been installed..."
	else
		echo -e "\e[1;31m[!]\e[0m esedbtools didn't install properly. You may need to do it manually"
	fi
	currentpath=' '
fi
}

##################################################
f_impacket(){
impacketinstall=$(which wmiexec.py)

if [ ! -z "$impacketinstall" ]; then
	echo -e "\e[1;32m[+]\e[0m I found Impacket on your system"
else
	echo -e "\n\e[1;34m[*]\e[0m Downloading Impacket from github..."
	sleep 2
	wget https://github.com/CoreSecurity/impacket/archive/impacket_0_9_13.zip -O /tmp/smbexec-inst/impacket.zip
	unzip /tmp/smbexec-inst/impacket.zip -d /tmp/smbexec-inst/
	mv /tmp/smbexec-inst/impacket-impacket_0_9_13 /opt/impacket
	currentpath=$PWD
	cd /opt/impacket/
	python setup.py install
	cd ${currentpath}
	impacketinstall=$(which wmiexec.py)
	if [ ! -z "$impacketinstall" ]; then
		echo -e "\n\e[1;32m[+]\e[0m Impacket has been installed..."
	else
		echo -e "\e[1;31m[!]\e[0m Impacket didn't install properly. You may need to do it manually"
	fi
	currentpath=' '
fi
}

##################################################
f_metasploitinstall(){
update=1
echo -e "\n\e[1;34m[*]\e[0m Downloading Metasploit from metasploit.com, this will take a while to complete"

if [ $(uname -m) == "x86_64" ]; then
	wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run -O /tmp/smbexec-inst/metasploit-latest-linux-x64-installer.run
	echo -e "\n\e[1;34m[*]\e[0m The Metasploit installer will walk you through the rest of the process"
	sleep 5
	chmod 755 /tmp/smbexec-inst/metasploit-latest-linux-x64-installer.run
	/tmp/smbexec-inst/metasploit-latest-linux-x64-installer.run
else
	wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-installer.run -O /tmp/smbexec-inst/metasploit-latest-linux-installer.run
	echo -e "\n\e[1;34m[*]\e[0m The Metasploit installer will walk you through the rest of the process"
	sleep 5
	chmod 755 /tmp/smbexec-inst/metasploit-latest-linux-installer.run
	/tmp/smbexec-inst/metasploit-latest-linux-installer.run
fi

if [ ! -e /usr/local/bin/msfconsole ]; then
	echo -e "\e[1;31m[!]\e[0m Something went wrong, Metasploit did not install properly"
else

	msfprogs="msfconsole msfupdate msfencode msfpayload"
	for z in $msfprogs; do
		if [ ! -e /usr/bin/$z ]; then
			ln -f -s /usr/local/bin/$z /usr/bin/$z
		fi
	done
	echo -e "\n\e[1;32m[+]\e[0m Metasploit has been installed...don't forget to get your activation key from Rapid7"
fi

sleep 5
}

##################################################

f_Banner(){
echo "************************************************************"
echo -e "		    \e[1;36msmbexec installer\e[0m       "
echo "	A rapid psexec style attack with samba tools              "
echo "************************************************************"
echo
}

##################################################
f_mainmenu(){

clear
f_Banner
	echo "Please choose your OS to install smbexec"
	echo "1.  Debian/Ubuntu and derivatives"
	echo "2.  Red Hat or Fedora"
	echo "3.  Exit"
	echo
	read -p "Choice: " mainchoice

	case $mainchoice in
	1) f_debian ;;
	2) f_rhfedora ;;
	3) clear;exit ;;
	*) f_mainmenu ;;
	esac

}
# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[!]\e[0m This script must be run as root" 1>&2
	exit 1
else
	f_mainmenu
fi
