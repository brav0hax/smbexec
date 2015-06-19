#!/bin/bash
# smbexec installer
# Last updated 09/08/2013

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

	reqs="autoconf cmake comerr-dev g++ gcc libtalloc-dev libtevent-dev libpopt-dev libbsd-dev zlib1g-dev libc6-dev make nmap python-dev bundler wget xterm"
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

	#Required gems via bundle install
	echo -e "\e[1;34m[*]\e[0m Installing required ruby gems..."
	bundle install &> /tmp/smbexec-inst/geminstall
	geminstall=$(cat /tmp/smbexec-inst/geminstall|grep -o 'command not found')
		if [ -z "$geminstall" ]; then
			echo -e "\t\e[1;32m[+]\e[0m Gems were successfully installed."
		else
			echo -e "\t\e[1;31m[!]\e[0m Something went wrong, unable to install the gems."
			echo -e "\t\e[1;31m[!]\e[0m If you are using rvm run this command from the smbexec dir when installer completes:"
			echo -e "\t\e[1;31m[!]\e[0m rvmsudo bundle install"
		fi
	#ntds extract for AD hash dumping
	f_ntdsxtract
	#libesedb extract for AD hash dumping
	f_libesedb

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

	reqs="autoconf cmake gcc gcc-c++ mingw32-binutils mingw32-gcc python-devel wget xterm"
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

	#ntds extract for AD hash dumping
	f_ntdsxtract
	#libesedb extract for AD hash dumping
	f_libesedb

	if [ ! -e /usr/bin/nmap ] && [ ! -e /usr/local/bin/nmap ] && [ -z $(rpm -qa nmap) ]; then
		echo -e "\e[1;31m[-]\e[0m nmap is not installed, will attempt to install from nmap.org"
		sleep 3
		f_nmapinstall
	else
		echo -e "\e[1;32m[+]\e[0m I found nmap installed on your system"
	fi

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
f_ntdsxtract(){
NTDSXtractinstall=$(locate -l 1 -b "\dsusers.py")

if [ ! -z "$NTDSXtractinstall" ]; then
	echo -e "\e[1;32m[+]\e[0m I found NTDSXtract on your system"
else
	echo -e "\n\e[1;34m[*]\e[0m Downloading NTDSXTRACT from ntdsxtract.com..."
	sleep 2
	wget http://www.ntdsxtract.com/downloads/ntdsxtract/ntdsxtract_v1_0.zip -O /tmp/smbexec-inst/ntdsxtract_v1_0.zip
	unzip /tmp/smbexec-inst/ntdsxtract_v1_0.zip -d /tmp/smbexec-inst/
	mv /tmp/smbexec-inst/NTDSXtract\ 1.0 /opt/NTDSXtract
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
	./configure --enable-static-executables && make
	mv /tmp/smbexec-inst/libesedb-20120102/esedbtools /opt/esedbtools
	cd "$currentpath"
	if [ -e /opt/esedbtools/esedbexport ] && [ -x /opt/esedbtools/esedbexport ]; then
		echo -e "\n\e[1;32m[+]\e[0m esedbtools have been installed..."
	else
		echo -e "\e[1;31m[!]\e[0m esedbtools didn't install properly. You may need to do it manually"
	fi
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
f_compilesmbclient(){

if [ ! -d /tmp/smbexec-inst ]; then mkdir /tmp/smbexec-inst;fi

if [ -e $path/progs/smbexeclient ]; then
	echo -e "\n\e[1;32m[+]\e[0m Looks like smbexeclient is already compiled, moving to smbwinexe compilation..."
	sleep 3
else
	echo -e "\n\e[1;34m[*]\e[0m Extracting samba..."
	sleep 2
	tar -xf $path/sources/samba.tar.gz -C /tmp/smbexec-inst/ > /dev/null 2>&1
	echo -e "\n\e[1;34m[*]\e[0m Compiling smbexeclient, this may take a while..."
	sleep 2
	cd /tmp/smbexec-inst/samba/source3 && ./configure.developer && make bin/smbclient
	cp /tmp/smbexec-inst/samba/source3/bin/smbclient $path/progs/smbexeclient
	make clean &> /dev/null
	cd $path

	if [ -e $path/progs/smbexeclient ]; then
		echo -e "\n\e[1;32m[+]\e[0m smbexeclient has been compiled and moved to the progs folder..."
		sleep 3
	else
		echo -e "\e[1;31m[!]\e[0m smbexeclient didn't install properly. Make sure you have prereqs installed..."
		sleep 5
	fi
fi
}

##################################################
f_compilewinexe(){

if [ ! -d /tmp/smbexec-inst ]; then mkdir /tmp/smbexec-inst;fi

if [ -e $path/progs/smbwinexe ]; then
	echo -e "\n\e[1;32m[+]\e[0m Looks like smbwinexe is already compiled, finishing up..."
	sleep 3
else
	echo -e "\n\e[1;34m[*]\e[0m Extracting winexe..."
	sleep 2
	tar -zxf $path/sources/winexe.tar.gz -C /tmp/smbexec-inst/
	echo -e "\n\e[1;34m[*]\e[0m Checking for samba source..."
		if [ ! -d /tmp/smbexec-inst/samba ]; then tar -zxf $path/sources/samba.tar.gz -C /tmp/smbexec-inst/ > /dev/null 2>&1; fi
	echo -e "\n\e[1;34m[*]\e[0m Compiling smbwinexe, this may take a while..."
	sleep 2
	cd /tmp/smbexec-inst/winexe/source && ./waf -j8 configure --samba-dir=../../samba  && ./waf -j8
	cp /tmp/smbexec-inst/winexe/source/build/winexe-static $path/progs/smbwinexe
	cd $path

	if [ -e $path/progs/smbwinexe ]; then
		echo -e "\n\e[1;32m[+]\e[0m smbwinexe has been compiled and moved to the progs folder..."
		sleep 3
	else
		echo -e "\e[1;31m[!]\e[0m smbwinexe didn't install properly. Make sure you have prereqs installed..."
		sleep 5
	fi
fi
}

##################################################
f_compilebinaries(){
path=$PWD
echo -e "\nThis script will compile your smbexec binaries\nPress any key to continue"
read
if [ ! -e /tmp/smbexec-inst ]; then
 mkdir /tmp/smbexec-inst/
fi
f_compilesmbclient
f_compilewinexe
updatedb
rm -rf /tmp/smbexec-inst/
f_mainmenu
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
	echo "3.  Microsoft Windows"
	echo "4.  Compile smbexec binaries"
	echo "5.  Exit"
	echo
	read -p "Choice: " mainchoice

	case $mainchoice in
	1) f_debian ;;
	2) f_rhfedora ;;
	3) f_microsoft ;;
	4) f_compilebinaries ;;
	*) clear;exit ;;
	esac

}
# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[!]\e[0m This script must be run as root" 1>&2
	exit 1
else
	f_mainmenu
fi
