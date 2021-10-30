#!/bin/bash
clear
echo "Created by Nathan Pan, Career and Technology Center, Frederick, MD, USA"
echo "Last Modified on Tuesday, August 24th, 2021, 2:01pm"
echo "CyberPatriot Ubuntu Script"

####################################LOG FILE####################################

touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log

####################################PASSWORD FILE####################################

touch ~/Desktop/Password.txt
echo -e "The script contains a secure password that will be used for all accounts. Would you like to make a custom password instead? yes or no"
read pwyn
if [ $pwyn == yes ]
then
	echo "Password:"
	read pw
	echo "$pw" > ~/Desktop/Password.txt
	echo "Password has been set as '$pw'."
else
	echo "H=Fmcqz3M]}&rfC$F>b)" > ~/Desktop/Password.txt
	echo "Password has been set as 'H=Fmcqz3M]}&rfC$F>b)'."
fi
chmod 777 ~/Desktop/Password.txt
echo "Password file is on desktop. Copy password from the file."

####################################CHECK IF ROOT####################################

if [ "$(id -u)" != "0" ]; then
    echo "Script is not being run as root."
	echo "run as: 'sudo ./ubuntu.sh'."
    exit    
fi
echo "Script is being run as root."

####################################BACKUPS####################################

mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups

echo "Backups folder created on the Desktop."

####################################USERS####################################

cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/

echo "/etc/group and /etc/passwd files backed up."

echo "Type all user account names except the one you are using, with a space in between."
read -a users

usersLength=${#users[@]}	

for (( i=0;i<$usersLength;i++))
do
	clear
	echo ${users[${i}]}
	echo "Delete ${users[${i}]}? yes or no"
	read yn1
	if [ $yn1 == yes ]
	then
		userdel -r ${users[${i}]}
		echo "${users[${i}]} has been deleted."
		
	else	
		echo "Make ${users[${i}]} administrator? yes or no"
		read yn2								
		if [ $yn2 == yes ]
		then
			gpasswd -a ${users[${i}]} sudo
			gpasswd -a ${users[${i}]} adm
			gpasswd -a ${users[${i}]} lpadmin
			gpasswd -a ${users[${i}]} sambashare
			echo "${users[${i}]} has been made an administrator."
		else
			gpasswd -d ${users[${i}]} sudo
			gpasswd -d ${users[${i}]} adm
			gpasswd -d ${users[${i}]} lpadmin
			gpasswd -d ${users[${i}]} sambashare
			gpasswd -d ${users[${i}]} root
			echo "${users[${i}]} has been made a standard user."
		fi
		
		if [ $pwyn == yes ]
		then
			echo -e "$pw\n$pw" | passwd ${users[${i}]}
			echo "${users[${i}]} has been given the password '$pw'."
		else
			echo -e "H=Fmcqz3M]}&rfC$F>b)\nH=Fmcqz3M]}&rfC$F>b)" | passwd ${users[${i}]}
			echo "${users[${i}]} has been given the password 'H=Fmcqz3M]}&rfC$F>b)'."
		fi
		passwd -x30 -n3 -w7 ${users[${i}]}
		#usermod -L ${users[${i}]} #is this needed? and does it unlock? what about the current user?
		echo "${users[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days." # ${users[${i}]}'s account has been locked."		
	fi
done
clear

echo "Type user account names of users you want to add, with a space in between"
read -a usersNew

usersNewLength=${#usersNew[@]}	

for (( i=0;i<$usersNewLength;i++))
do
	clear
	echo ${usersNew[${i}]}
	if [ $pwyn == yes ]
	then
		echo -e "$pw\n$pw" | adduser ${usersNew[${i}]}
		echo "${usersNew[${i}]} has been given the password '$pw'."
	else
		echo -e "H=Fmcqz3M]}&rfC$F>b)\nH=Fmcqz3M]}&rfC$F>b)" | adduser ${usersNew[${i}]}
		echo "${usersNew[${i}]} has been given the password 'H=Fmcqz3M]}&rfC$F>b)'."
	fi
	echo "A user account for ${usersNew[${i}]} has been created."
	clear
	echo "Make ${usersNew[${i}]} administrator? yes or no"
	read ynNew								
	if [ $ynNew == yes ]
	then
		gpasswd -a ${usersNew[${i}]} sudo
		gpasswd -a ${usersNew[${i}]} adm
		gpasswd -a ${usersNew[${i}]} lpadmin
		gpasswd -a ${usersNew[${i}]} sambashare
		echo "${usersNew[${i}]} has been made an administrator."
		
	else
		echo "${usersNew[${i}]} has been made a standard user."
		
	fi
	
	passwd -x30 -n3 -w7 ${usersNew[${i}]}
	#usermod -L ${usersNew[${i}]} #again, is this needed?
	echo "${usersNew[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days." # ${users[${i}]}'s account has been locked."	
done

clear
echo "In Script.log, check for any user folders that do not belong to any users in /home/."
echo "***************User folders in /home***************" >> ~/Desktop/Script.log
ls -a /home/ >> ~/Desktop/Script.log

clear
echo "In Script.log, check for any files for users that should not be administrators in /etc/sudoers.d."
echo "***************Files in /etc/sudoers.d***************" >> ~/Desktop/Script.log
ls -a /etc/sudoers.d >> ~/Desktop/Script.log

clear
echo "Remove all instances of '!authenticate' and 'NOPASSWD' from /etc/sudoers. Close window when finished."
cp /etc/sudoers ~/Desktop/backups/
gedit /etc/sudoers
echo "Press enter to continue."
read enter

clear
unalias -a
echo "All aliases have been removed."

clear
usermod -L root
echo "Root account has been locked. Use 'usermod -U root' to unlock it."

clear
if [[ $(grep root /etc/passwd | wc -l) -gt 1 ]]
then
	grep root /etc/passwd | wc -l
	echo -e "UID 0 is not correctly set to root. Please fix.\nPress enter to continue..."
	read waiting
fi
echo "UID 0 is correctly set to root."

clear
sed -i '1c\
root:x:0:0:root:/root:/sbin/nologin' /etc/passwd
echo "Root has been set to nologin"

####################################FILE PERMISSIONS####################################

clear
chmod 640 .bash_history
echo "Bash history file permissions set."

clear
chmod 600 /etc/shadow
echo "File permissions on shadow have been set."

clear
chmod 644 /etc/passwd
echo "File permissions on passwd have been set."

####################################FIREWALL/NETWORK SECURITY####################################

clear
apt-get -y -qq install ufw
ufw enable
ufw logging on #try 'ufw logging high' or 'ufw logging low' as well
ufw deny 1337
ufw deny 2049
ufw deny 111
ufw default deny
echo "Firewall enabled. Port 1337, 2049, and 111 blocked. Default set to deny."

clear
apt-get -y -qq install iptables
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
echo "IPtables has been installed and telnet, NFS, X-Windows, printer, and Sun rcp/NFS have been blocked. If any of these are needed, use google to find how to unlock."
iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
echo "SSH spammers and portscans have been blocked. Blocks removed after 1 day, and scan attempts are logged."
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A OUTPUT -p icmp -o eth0 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT
iptables -A INPUT -p icmp -i eth0 -j DROP
echo "NULL packets and pings are dropped."
iptables-save
/sbin/iptables-save
echo "IPtables rules saved."

clear
chmod 777 /etc/hosts
cp /etc/hosts ~/Desktop/backups/
echo > /etc/hosts
echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
chmod 644 /etc/hosts
echo "HOSTS file has been set to defaults."

chmod 777 /etc/host.conf
cp /etc/host.conf ~/Desktop/backups/
echo > /etc/host.conf
echo -e "# The \"order\" line is only used by old versions of the C library.\norder hosts,bind\nmulti on" >> /etc/host.conf
chmod 644 /etc/host.conf
echo "host.conf has been set to defaults."

####################################LOCAL POLICY CONFIGURATIONS####################################

clear
chmod 777 /etc/lightdm/lightdm.conf
cp /etc/lightdm/lightdm.conf ~/Desktop/backups/
echo > /etc/lightdm/lightdm.conf
echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
chmod 644 /etc/lightdm/lightdm.conf
echo "LightDM has been secured."

clear
cp /etc/default/irqbalance ~/Desktop/backups/
echo > /etc/default/irqbalance
echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
echo "IRQ Balance has been disabled."

clear
cp /etc/sysctl.conf ~/Desktop/backups/
echo > /etc/sysctl.conf
echo -e "# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
net.ipv6.conf.default.max_addresses = 1\n\n########## Other ##########\nfs.suid_dumpable = 0\nkernel.exec-shield = 2\nkernel.randomize_va_space = 2\nkernel.sysrq = 0\nnet.ipv4.tcp_rfc1337 = 1\n" >> /etc/sysctl.conf
sysctl -p >> /dev/null
echo "Sysctl has been configured."

clear
cp /proc/sys/kernel/sysrq ~/Desktop/backups/
echo 0 > /proc/sys/kernel/sysrq
echo "SysRq key has been disabled"

clear
cp /proc/sys/net/ipv4/tcp_rfc1337 ~/Desktop/backups/
echo 1 > /proc/sys/net/ipv4/tcp_rfc1337
echo "Kernel drops RST packets for sockets in the time-wait state."

clear
cp /proc/sys/kernel/core_uses_pid ~/Desktop/backups/
echo 1 > /proc/sys/kernel/core_uses_pid
echo "Kernel core_uses_pid set to 1."

clear
cp /proc/sys/net/ipv4/conf/default/log_martians ~/Desktop/backups/
echo 1 > /proc/sys/net/ipv4/conf/default/log_martians
echo "Default log_martians set to 1."

clear
cp /proc/sys/net/ipv4/tcp_timestamps ~/Desktop/backups/
echo 0 > /proc/sys/net/ipv4/tcp_timestamps
echo "tcp_timestamps set to 0."

clear
cp /etc/resolv.conf ~/Desktop/backups/
echo -e "nameserver 8.8.8.8\nsearch localdomain" >> /etc/resolv.conf
echo "resolv.conf has been configured."

clear
cp /etc/init/control-alt-delete.conf ~/Desktop/backups/
sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf
systemctl mask ctrl-alt-del.target #ubuntu 16 only?
systemctl daemon-reload #ubuntu 16 only?
echo "Reboot using Ctrl-Alt-Delete has been disabled."

#THIS DOES NOT WORK, NEED TO FIGURE OUT HOW TO DO THIS THROUGH /etc/fstab
#clear
#cp /proc/mounts ~/Desktop/backups/
#echo "tmpfs /dev/shm tmpfs ro,nosuid,nodev,noexec 0 0" >> /proc/mounts
#echo "/proc/mounts has been modified to secure /dev/shm."

####################################SERVICES####################################

echo "Answer all questions with 'yes' or 'no'"
echo "Does this machine need Samba?"
read sambaYN
echo "Does this machine need FTP?"
read ftpYN
echo "Does this machine need SSH?"
read sshYN
echo "Does this machine need Telnet?"
read telnetYN
echo "Does this machine need Mail?"
read mailYN
echo "Does this machine need Printing?"
read printYN
echo "Does this machine need MySQL?"
read dbYN
echo "Will this machine be a Web Server?"
read httpYN
echo "Does this machine need DNS?"
read dnsYN
echo "Does this machine need remote desktop capabilities?"
read rdpYN
echo "Does this machine allow media files?"
read mediaFilesYN

echo "Disable IPv6?"
read ipv6YN
if [ $ipv6YN == yes ]
then
	echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -p >> /dev/null
	echo "IPv6 has been disabled."
fi



clear
if [ $sambaYN == no ]
then
	ufw deny netbios-ns
	ufw deny netbios-dgm
	ufw deny netbios-ssn
	ufw deny microsoft-ds
	apt-get -y -qq purge samba
	apt-get -y -qq purge samba-common
	apt-get -y -qq purge samba-common-bin
	apt-get -y -qq purge samba4
	
	clear
	echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
elif [ $sambaYN == yes ]
then
	ufw allow netbios-ns
	ufw allow netbios-dgm
	ufw allow netbios-ssn
	ufw allow microsoft-ds
	apt-get -y -qq install samba
	apt-get -y -qq install system-config-samba
	cp /etc/samba/smb.conf ~/Desktop/backups/
	if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
	then
		sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
	fi
	sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf
	
	echo Type all user account names, with a space in between
	read -a usersSMB
	usersSMBLength=${#usersSMB[@]}	
	for (( i=0;i<$usersSMBLength;i++))
	do
		echo -e 'H=Fmcqz3M]}&rfC%F>b)\nH=Fmcqz3M]}&rfC%F>b)' | smbpasswd -a ${usersSMB[${i}]}
		echo "${usersSMB[${i}]} has been given the password 'H=Fmcqz3M]}&rfC%F>b)' for Samba."
	done
	echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been allowed. Samba config file has been configured."
	
	clear
else
	echo Response not recognized.
fi
echo "Samba is complete."



clear
if [ $ftpYN == no ]
then
	ufw deny ftp 
	ufw deny sftp 
	ufw deny saft 
	ufw deny ftps-data 
	ufw deny ftps
	apt-get -y -qq purge proftpd*
	apt-get -y -qq purge pure-ftpd*
	apt-get -y -qq purge vsftpd
	echo "vsFTPd has been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
	
elif [ $ftpYN == yes ]
then
	ufw allow ftp 
	ufw allow sftp 
	ufw allow saft 
	ufw allow ftps-data 
	ufw allow ftps
	cp /etc/vsftpd/vsftpd.conf ~/Desktop/backups/
	cp /etc/vsftpd.conf ~/Desktop/backups/
	gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
	service vsftpd restart
	echo "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd service has been restarted."
	
else
	echo Response not recognized.
fi
echo "FTP is complete."



clear
if [ $sshYN == no ]
then
	ufw deny ssh
	apt-get purge -y -qq openssh-server
	echo "SSH port has been denied on the firewall. Open-SSH has been removed."
	
elif [ $sshYN == yes ]
then
	apt-get -y -qq install openssh-server
	apt-get -y -qq install libpam-google-authenticator
	ufw allow ssh
	cp /etc/ssh/sshd_config ~/Desktop/backups/	
	echo Type all user account names, with a space in between
	read usersSSH
	echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 3784\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's ~/.rhosts and ~/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
	service ssh restart
	mkdir ~/.ssh
	chmod 700 ~/.ssh
	ssh-keygen -t rsa
	echo "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
	
else
	echo Response not recognized.
fi
echo "SSH is complete."



clear
if [ $telnetYN == no ]
then
	ufw deny telnet 
	ufw deny rtelnet 
	ufw deny telnets
	apt-get -y -qq purge telnet
	apt-get -y -qq purge telnetd
	apt-get -y -qq purge inetutils-telnetd
	apt-get -y -qq purge telnetd-ssl
	echo "Telnet port has been denied on the firewall and Telnet has been removed."
	
elif [ $telnetYN == yes ]
then
	ufw allow telnet 
	ufw allow rtelnet 
	ufw allow telnets
	echo "Telnet port has been allowed on the firewall."
	
else
	echo Response not recognized.
fi
echo "Telnet is complete."



clear
if [ $mailYN == no ]
then
	ufw deny smtp 
	ufw deny pop2 
	ufw deny pop3
	ufw deny imap2 
	ufw deny imaps 
	ufw deny pop3s
	apt-get -y -qq purge sendmail
	apt-get -y -qq purge dovecot*
	echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
	
elif [ $mailYN == yes ]
then
	ufw allow smtp 
	ufw allow pop2 
	ufw allow pop3
	ufw allow imap2 
	ufw allow imaps 
	ufw allow pop3s
	echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been allowed on the firewall."
	
else
	echo Response not recognized.
fi
echo "Mail is complete."



clear
if [ $printYN == no ]
then
	ufw deny ipp 
	ufw deny printer 
	ufw deny cups
	echo "ipp, printer, and cups ports have been denied on the firewall."
	
elif [ $printYN == yes ]
then
	ufw allow ipp 
	ufw allow printer 
	ufw allow cups
	echo "ipp, printer, and cups ports have been allowed on the firewall."
	
else
	echo Response not recognized.
fi
echo "Printing is complete."



clear
if [ $dbYN == no ]
then
	ufw deny ms-sql-s 
	ufw deny ms-sql-m 
	ufw deny mysql
	ufw deny mysql-proxy
	ufw deny postgresql*
	apt-get -y -qq purge mysql
	apt-get -y -qq purge mysql-client-core-5.5
	apt-get -y -qq purge mysql-client-core-5.6
	apt-get -y -qq purge mysql-common-5.5
	apt-get -y -qq purge mysql-common-5.6
	apt-get -y -qq purge mysql-server
	apt-get -y -qq purge mysql-server-5.5
	apt-get -y -qq purge mysql-server-5.6
	apt-get -y -qq purge mysql-client-5.5
	apt-get -y -qq purge mysql-client-5.6
	apt-get -y -qq purge mysql-server-core-5.6
	apt-get -y -qq purge postgresql
	echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL and postgresql have been removed."
	
elif [ $dbYN == yes ]
then
	ufw allow ms-sql-s 
	ufw allow ms-sql-m 
	ufw allow mysql 
	ufw allow mysql-proxy
	apt-get -y -qq install mysql-server-5.6
	cp /etc/my.cnf ~/Desktop/backups/
	cp /etc/mysql/my.cnf ~/Desktop/backups/
	cp /usr/etc/my.cnf ~/Desktop/backups/
	cp ~/.my.cnf ~/Desktop/backups/
	if grep -q "bind-address" "/etc/mysql/my.cnf"
	then
		sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
	fi
	gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit ~/.my.cnf
	service mysql restart
	echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL service has been restarted."
	
else
	echo Response not recognized.
fi
echo "MySQL is complete."



clear
if [ $httpYN == no ]
then
	ufw deny http
	ufw deny https
	apt-get -y -qq purge apache2
	rm -r /var/www/*
	echo "http and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
	
elif [ $httpYN == yes ]
then
	apt-get install -y -qq apache2
	ufw allow http 
	ufw allow https
	cp /etc/apache2/apache2.conf ~/Desktop/backups/
	if [ -e /etc/apache2/apache2.conf ]
	then
  	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
	fi
	chown -R root:root /etc/apache2

	echo "http and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
	
else
	echo Response not recognized.
fi
echo "Web Server is complete."



clear
if [ $dnsYN == no ]
then
	ufw deny domain
	apt-get -y -qq purge bind9
	echo "domain port has been denied on the firewall. DNS name binding has been removed."
	
elif [ $dnsYN == yes ]
then
	ufw allow domain
	echo "domain port has been allowed on the firewall."
	
else
	echo Response not recognized.
fi
echo "DNS is complete."



clear
if [ $rdpYN == no ]
then
	ufw deny 3389
	ufw deny 512
	ufw deny 513
	ufw deny 514
	apt-get -y -qq purge rsh*
	apt-get -y -qq purge xrdp
	apt-get -y -qq purge vnc*
	apt-get -y -qq purge remmina
	apt-get -y -qq purge freerdp*
	apt-get -y -qq purge rstatd
	echo "Remote desktop ports have been denied on the firewall. Remote desktop applications have been removed."

elif [ $rdpYN == yes ]
then
	echo "Nothing here yet."

else
	echo Response not recognized.
fi
echo "Remote desktop is complete."

####################################PROHIBITED FILE SEARCH####################################

clear
if [ $mediaFilesYN == no ]
then
	echo "***************Audio files***************" >> ~/Desktop/Script.log
	find / -name "*.midi" -type f >> ~/Desktop/Script.log
	find / -name "*.mid" -type f >> ~/Desktop/Script.log
	find / -name "*.mod" -type f >> ~/Desktop/Script.log
	find / -name "*.mp3" -type f >> ~/Desktop/Script.log
	find / -name "*.mp2" -type f >> ~/Desktop/Script.log
	find / -name "*.mpa" -type f >> ~/Desktop/Script.log
	find / -name "*.m4a" -type f >> ~/Desktop/Script.log
	find / -name "*.abs" -type f >> ~/Desktop/Script.log
	find / -name "*.mpega" -type f >> ~/Desktop/Script.log
	find / -name "*.au" -type f >> ~/Desktop/Script.log
	find / -name "*.snd" -type f >> ~/Desktop/Script.log
	find / -name "*.wav" -type f >> ~/Desktop/Script.log
	find / -name "*.aiff" -type f >> ~/Desktop/Script.log
	find / -name "*.aif" -type f >> ~/Desktop/Script.log
	find / -name "*.sid" -type f >> ~/Desktop/Script.log
	find / -name "*.flac" -type f >> ~/Desktop/Script.log
	find / -name "*.ogg" -type f >> ~/Desktop/Script.log
	find / -name "*.aac" -type f >> ~/Desktop/Script.log
	clear
	echo "All audio files has been listed in Script.log."

	echo "***************Video files***************" >> ~/Desktop/Script.log
	find / -name "*.mpeg" -type f >> ~/Desktop/Script.log
	find / -name "*.mpg" -type f >> ~/Desktop/Script.log
	find / -name "*.mpe" -type f >> ~/Desktop/Script.log
	find / -name "*.dl" -type f >> ~/Desktop/Script.log
	find / -name "*.movie" -type f >> ~/Desktop/Script.log
	find / -name "*.movi" -type f >> ~/Desktop/Script.log
	find / -name "*.mv" -type f >> ~/Desktop/Script.log
	find / -name "*.iff" -type f >> ~/Desktop/Script.log
	find / -name "*.anim5" -type f >> ~/Desktop/Script.log
	find / -name "*.anim3" -type f >> ~/Desktop/Script.log
	find / -name "*.anim7" -type f >> ~/Desktop/Script.log
	find / -name "*.avi" -type f >> ~/Desktop/Script.log
	find / -name "*.vfw" -type f >> ~/Desktop/Script.log
	find / -name "*.avx" -type f >> ~/Desktop/Script.log
	find / -name "*.fli" -type f >> ~/Desktop/Script.log
	find / -name "*.flc" -type f >> ~/Desktop/Script.log
	find / -name "*.mov" -type f >> ~/Desktop/Script.log
	find / -name "*.qt" -type f >> ~/Desktop/Script.log
	find / -name "*.spl" -type f >> ~/Desktop/Script.log
	find / -name "*.swf" -type f >> ~/Desktop/Script.log
	find / -name "*.dcr" -type f >> ~/Desktop/Script.log
	find / -name "*.dir" -type f >> ~/Desktop/Script.log
	find / -name "*.dxr" -type f >> ~/Desktop/Script.log
	find / -name "*.rpm" -type f >> ~/Desktop/Script.log
	find / -name "*.rm" -type f >> ~/Desktop/Script.log
	find / -name "*.smi" -type f >> ~/Desktop/Script.log
	find / -name "*.ra" -type f >> ~/Desktop/Script.log
	find / -name "*.ram" -type f >> ~/Desktop/Script.log
	find / -name "*.rv" -type f >> ~/Desktop/Script.log
	find / -name "*.wmv" -type f >> ~/Desktop/Script.log
	find / -name "*.asf" -type f >> ~/Desktop/Script.log
	find / -name "*.asx" -type f >> ~/Desktop/Script.log
	find / -name "*.wma" -type f >> ~/Desktop/Script.log
	find / -name "*.wax" -type f >> ~/Desktop/Script.log
	find / -name "*.wmv" -type f >> ~/Desktop/Script.log
	find / -name "*.wmx" -type f >> ~/Desktop/Script.log
	find / -name "*.3gp" -type f >> ~/Desktop/Script.log
	find / -name "*.mov" -type f >> ~/Desktop/Script.log
	find / -name "*.mp4" -type f >> ~/Desktop/Script.log
	find / -name "*.avi" -type f >> ~/Desktop/Script.log
	find / -name "*.swf" -type f >> ~/Desktop/Script.log
	find / -name "*.flv" -type f >> ~/Desktop/Script.log
	find / -name "*.m4v" -type f >> ~/Desktop/Script.log
	clear
	echo "All video files have been listed in Script.log."
	
	echo "***************Image files***************" >> ~/Desktop/Script.log
	find / -name "*.tiff" -type f >> ~/Desktop/Script.log
	find / -name "*.tif" -type f >> ~/Desktop/Script.log
	find / -name "*.rs" -type f >> ~/Desktop/Script.log
	find / -name "*.im1" -type f >> ~/Desktop/Script.log
	find / -name "*.gif" -type f >> ~/Desktop/Script.log
	find / -name "*.jpeg" -type f >> ~/Desktop/Script.log
	find / -name "*.jpg" -type f >> ~/Desktop/Script.log
	find / -name "*.jpe" -type f >> ~/Desktop/Script.log
	find / -name "*.png" -type f >> ~/Desktop/Script.log
	find / -name "*.rgb" -type f >> ~/Desktop/Script.log
	find / -name "*.xwd" -type f >> ~/Desktop/Script.log
	find / -name "*.xpm" -type f >> ~/Desktop/Script.log
	find / -name "*.ppm" -type f >> ~/Desktop/Script.log
	find / -name "*.pbm" -type f >> ~/Desktop/Script.log
	find / -name "*.pgm" -type f >> ~/Desktop/Script.log
	find / -name "*.pcx" -type f >> ~/Desktop/Script.log
	find / -name "*.ico" -type f >> ~/Desktop/Script.log
	find / -name "*.svg" -type f >> ~/Desktop/Script.log
	find / -name "*.svgz" -type f >> ~/Desktop/Script.log
	find / -name "*.bmp" -type f >> ~/Desktop/Script.log
	find / -name "*.img" -type f >> ~/Desktop/Script.log
	clear
	echo "All image files have been listed in Script.log."
	
	echo "***************Other files***************" >> ~/Desktop/Script.log
	find / -name "*.txt" -type f >> ~/Desktop/Script.log
	find / -name "*.exe" -type f >> ~/Desktop/Script.log
	find / -name "*.msi" -type f >> ~/Desktop/Script.log
	find / -name "*.bat" -type f >> ~/Desktop/Script.log
	find / -name "*.sh" -type f >> ~/Desktop/Script.log
	clear
	echo "All other file types have been listed in Script.log."
	
else
	echo Response not recognized.
fi
echo "Media files are complete."

clear
cp /etc/rc.local ~/Desktop/backups/
echo > /etc/rc.local
echo 'exit 0' >> /etc/rc.local
echo "Any startup scripts have been removed."

clear
find /bin/ -name "*.sh" -type f -delete
echo "Scripts in bin have been removed."

clear
echo "***************Files w/permissions between 700 and 777***************" >> ~/Desktop/Script.log
find / -type f -perm 777 >> ~/Desktop/Script.log
find / -type f -perm 776 >> ~/Desktop/Script.log
find / -type f -perm 775 >> ~/Desktop/Script.log
find / -type f -perm 774 >> ~/Desktop/Script.log
find / -type f -perm 773 >> ~/Desktop/Script.log
find / -type f -perm 772 >> ~/Desktop/Script.log
find / -type f -perm 771 >> ~/Desktop/Script.log
find / -type f -perm 770 >> ~/Desktop/Script.log
find / -type f -perm 767 >> ~/Desktop/Script.log
find / -type f -perm 766 >> ~/Desktop/Script.log
find / -type f -perm 765 >> ~/Desktop/Script.log
find / -type f -perm 764 >> ~/Desktop/Script.log
find / -type f -perm 763 >> ~/Desktop/Script.log
find / -type f -perm 762 >> ~/Desktop/Script.log
find / -type f -perm 761 >> ~/Desktop/Script.log
find / -type f -perm 760 >> ~/Desktop/Script.log
find / -type f -perm 757 >> ~/Desktop/Script.log
find / -type f -perm 756 >> ~/Desktop/Script.log
find / -type f -perm 755 >> ~/Desktop/Script.log
find / -type f -perm 754 >> ~/Desktop/Script.log
find / -type f -perm 753 >> ~/Desktop/Script.log
find / -type f -perm 752 >> ~/Desktop/Script.log
find / -type f -perm 751 >> ~/Desktop/Script.log
find / -type f -perm 750 >> ~/Desktop/Script.log
find / -type f -perm 747 >> ~/Desktop/Script.log
find / -type f -perm 746 >> ~/Desktop/Script.log
find / -type f -perm 745 >> ~/Desktop/Script.log
find / -type f -perm 744 >> ~/Desktop/Script.log
find / -type f -perm 743 >> ~/Desktop/Script.log
find / -type f -perm 742 >> ~/Desktop/Script.log
find / -type f -perm 741 >> ~/Desktop/Script.log
find / -type f -perm 740 >> ~/Desktop/Script.log
find / -type f -perm 737 >> ~/Desktop/Script.log
find / -type f -perm 736 >> ~/Desktop/Script.log
find / -type f -perm 735 >> ~/Desktop/Script.log
find / -type f -perm 734 >> ~/Desktop/Script.log
find / -type f -perm 733 >> ~/Desktop/Script.log
find / -type f -perm 732 >> ~/Desktop/Script.log
find / -type f -perm 731 >> ~/Desktop/Script.log
find / -type f -perm 730 >> ~/Desktop/Script.log
find / -type f -perm 727 >> ~/Desktop/Script.log
find / -type f -perm 726 >> ~/Desktop/Script.log
find / -type f -perm 725 >> ~/Desktop/Script.log
find / -type f -perm 724 >> ~/Desktop/Script.log
find / -type f -perm 723 >> ~/Desktop/Script.log
find / -type f -perm 722 >> ~/Desktop/Script.log
find / -type f -perm 721 >> ~/Desktop/Script.log
find / -type f -perm 720 >> ~/Desktop/Script.log
find / -type f -perm 717 >> ~/Desktop/Script.log
find / -type f -perm 716 >> ~/Desktop/Script.log
find / -type f -perm 715 >> ~/Desktop/Script.log
find / -type f -perm 714 >> ~/Desktop/Script.log
find / -type f -perm 713 >> ~/Desktop/Script.log
find / -type f -perm 712 >> ~/Desktop/Script.log
find / -type f -perm 711 >> ~/Desktop/Script.log
find / -type f -perm 710 >> ~/Desktop/Script.log
find / -type f -perm 707 >> ~/Desktop/Script.log
find / -type f -perm 706 >> ~/Desktop/Script.log
find / -type f -perm 705 >> ~/Desktop/Script.log
find / -type f -perm 704 >> ~/Desktop/Script.log
find / -type f -perm 703 >> ~/Desktop/Script.log
find / -type f -perm 702 >> ~/Desktop/Script.log
find / -type f -perm 701 >> ~/Desktop/Script.log
find / -type f -perm 700 >> ~/Desktop/Script.log
echo "All files with file permissions between 700 and 777 have been listed in Script.log."

clear
echo "***************PHP files***************" >> ~/Desktop/Script.log
echo "***('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)***" >> ~/Desktop/Script.log
find / -name "*.php" -type f >> ~/Desktop/Script.log
echo "All PHP files have been listed in Script.log. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

####################################UNWANTED SOFTWARE/SERVICES REMOVAL####################################

clear
apt-get -y -qq purge netcat
apt-get -y -qq purge netcat-openbsd 
apt-get -y -qq purge netcat-traditional 
apt-get -y -qq purge ncat 
apt-get -y -qq purge pnetcat 
apt-get -y -qq purge socat
apt-get -y -qq purge sock
apt-get -y -qq purge socket
apt-get -y -qq purge sbd
rm /usr/bin/nc

clear
echo "Netcat and all other instances have been removed."

apt-get -y -qq purge john 
apt-get -y -qq purge john-data 

clear
echo "John the Ripper has been removed."

apt-get -y -qq purge hydra 
apt-get -y -qq purge hydra-gtk 

clear
echo "Hydra has been removed."

apt-get -y -qq purge aircrack-ng 

clear
echo "Aircrack-NG has been removed."

apt-get -y -qq purge fcrackzip 

clear
echo "FCrackZIP has been removed."

apt-get -y -qq purge lcrack 

clear
echo "LCrack has been removed."

apt-get -y -qq purge ophcrack 
apt-get -y -qq purge ophcrack-cli 

clear
echo "OphCrack has been removed."

apt-get -y -qq purge pdfcrack 

clear
echo "PDFCrack has been removed."

apt-get -y -qq purge pyrit 

clear
echo "Pyrit has been removed."

apt-get -y -qq purge rarcrack 

clear
echo "RARCrack has been removed."

apt-get -y -qq purge sipcrack 

clear
echo "SipCrack has been removed."

apt-get -y -qq purge irpas 

clear
echo "IRPAS has been removed."

clear
echo 'Are there any hacking tools shown? Check in Script.log (not counting libcrack2:amd64 or cracklib-runtime)'
echo "***************Hacking tools***************" >> ~/Desktop/Script.log
echo "***(not counting libcrack2:amd64 or cracklib-runtime)***" >> ~/Desktop/Script.log
dpkg -l | egrep "crack|hack" >> ~/Desktop/Script.log

apt-get -y -qq purge logkeys 

clear 
echo "LogKeys has been removed."

apt-get -y -qq purge zeitgeist-core 
apt-get -y -qq purge zeitgeist-datahub 
apt-get -y -qq purge python-zeitgeist 
apt-get -y -qq purge rhythmbox-plugin-zeitgeist 
apt-get -y -qq purge zeitgeist 

clear
echo "Zeitgeist has been removed."

apt-get -y -qq purge nfs-kernel-server 
apt-get -y -qq purge nfs-common 
apt-get -y -qq purge portmap 
apt-get -y -qq purge rpcbind 
apt-get -y -qq purge autofs 

clear
echo "NFS has been removed."

apt-get -y -qq purge nginx 
apt-get -y -qq purge nginx-common 

clear
echo "NGINX has been removed."

apt-get -y -qq purge inetd 
apt-get -y -qq purge openbsd-inetd 
apt-get -y -qq purge xinetd 
apt-get -y -qq purge inetutils-ftp 
apt-get -y -qq purge inetutils-ftpd 
apt-get -y -qq purge inetutils-inetd 
apt-get -y -qq purge inetutils-ping 
apt-get -y -qq purge inetutils-syslogd 
apt-get -y -qq purge inetutils-talk 
apt-get -y -qq purge inetutils-talkd 
apt-get -y -qq purge inetutils-telnet 
apt-get -y -qq purge inetutils-telnetd 
apt-get -y -qq purge inetutils-tools 
apt-get -y -qq purge inetutils-traceroute 

clear
echo "Inetd (super-server) and all inet utilities have been removed."


apt-get -y -qq purge vnc4server 
apt-get -y -qq purge vncsnapshot 
apt-get -y -qq purge vtgrab 

clear
echo "VNC has been removed."

apt-get -y -qq purge snmp 
apt-get -y -qq purge snmpd 

clear
echo "SNMP has been removed."

apt-get -y -qq purge zenmap 
apt-get -y -qq purge nmap 

clear
echo "Zenmap and nmap have been removed."

apt-get -y -qq purge wireshark 
apt-get -y -qq purge wireshark-common 
apt-get -y -qq purge wireshark-gtk 
apt-get -y -qq purge wireshark-qt 

clear
echo "Wireshark has been removed."

apt-get -y -qq purge crack 
apt-get -y -qq purge crack-common 

clear
echo "Crack has been removed."

apt-get -y -qq purge medusa 

clear
echo "Medusa has been removed."

apt-get -y -qq purge nikto 

clear
echo "Nikto has been removed."

apt-get -y -qq purge cyphesis* 

clear
echo "WorldForge has been removed."

apt-get -y -qq purge minetest 

clear
echo "Minetest has been removed."

apt-get -y -qq purge freeciv* 

clear
echo "Freeciv has been removed."

apt-get -y -qq purge aisleriot 

clear
echo "Aisleriot has been removed."

apt-get -y -qq purge wesnoth* 

clear
echo "Wesnoth has been removed."

apt-get -y -qq purge talk talkd 

clear
echo "talk has been removed."

apt-get -y -qq purge kdump-tools kexec-tools 

clear
echo "kdump-tools and kexec-tools have been removed."

apt-get -y -qq purge wordpress 

clear
echo "WordPress has been removed."

apt-get -y -qq purge vpnc* 

clear
echo "Cisco VPN client has been removed."

apt-get -y -qq purge nis yp-tools 

clear
echo "NIS server and client have been removed."

apt-get -y -qq purge tftpd atftpd tftpd-hpa 

clear
echo "tftpd server has been removed."

apt-get -y -qq purge ettercap* 

clear
echo "Ettercap has been removed."

apt-get -y -qq purge manaplus 

clear
echo "ManaPlus has been removed."

apt-get -y -qq purge gameconqueror 

clear
echo "Game Conqueror has been removed."

apt-get -y -qq purge yersinia 

clear
echo "Yersinia has been removed."

apt-get -y -qq purge deluge

clear
echo "Deluge has been removed."

apt-get -y -qq purge ircd-irc2

clear
echo "IRC daemon has been removed."

apt-get -y -qq purge linuxdcpp

clear
echo "LinuxDC++ has been removed."

apt-get -y -qq purge rfdump

clear
echo "RFdump has been removed."


####################################INSTALLATIONS####################################

clear
echo "Installing applications..."
apt-get -y -qq -f install
apt-get -y -qq install firefox 
apt-get -y -qq install hardinfo 
apt-get -y -qq install chkrootkit 
apt-get -y -qq install portsentry 
apt-get -y -qq install lynis 
apt-get -y -qq install gufw 
apt-get -y -qq install sysv-rc-conf 
apt-get -y -qq install rkhunter 
apt-get -y -qq install apparmor* 
apt-get -y -qq install --reinstall coreutils 
apt-get -y -qq install clamav
echo "Firefox, hardinfo, chkrootkit, portsentry, lynis, gufw, sysv-rc-conf, rkhunter, AppArmor, and clamav have been installed. Coreutils has been reinstalled."

####################################PASSWORD POLICY####################################

clear
cp /etc/login.defs ~/Desktop/backups/
sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
sed -i '162s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
echo "Password policies have been set with /etc/login.defs."

clear
apt-get -y -qq install libpam-cracklib 
cp /etc/pam.d/common-auth ~/Desktop/backups/
cp /etc/pam.d/common-password ~/Desktop/backups/
echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so nullok_secure\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=3 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth
echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of modules that define the services to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512 remember=5 minlen=16\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config\npassword requisite pam_cracklib.so try_first_pass retry=3 difok=4 minlen=16 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 maxrepeat=2 reject_username gecoscheck enforce_for_root" > /etc/pam.d/common-password
echo "Password policies have been set with /etc/pam.d."

####################################CRONTAB####################################

clear
crontab -l > ~/Desktop/backups/crontab-old
crontab -r
echo "Crontab has been backed up. All startup tasks have been removed from crontab."

clear
cd /etc/
/bin/rm -f cron.deny at.deny
echo root > cron.allow
echo root > at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
cd ..
echo "Only root allowed in cron."

####################################FIREFOX####################################

clear
apt-get -y -qq install git 
cd
git clone https://github.com/pyllyukko/user.js -q
cd user.js
cp user.js ~/.mozilla/firefox/XXXXXXXX.your_profile_name/user.js #EDIT BEFOREHAND - change to whatever the respective directory is
make systemwide_user.js
cp systemwide_user.js /etc/firefox/syspref.js #on older versions of Ubuntu, it may be /etc/firefox/firefox.js
apt-get -y -qq purge git 
echo "Firefox has been hardened."

####################################AUDIT POLICY####################################

clear
apt-get -y -qq install auditd audispd-plugins 
auditctl -e 1
auditctl -a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
auditctl -a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd
sed -i 's/^active.*/active = yes/g' /etc/audisp/plugins.d/syslog.conf
service auditd start
echo "Audit service has been installed and started."
#anything else? idk

####################################DISABLE AUTOMATIC MOUNTING####################################

clear
service autofs stop #this section needs to be checked
echo "install usb-storage /bin/true" >> /etc/modprobe.conf
gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /desktop/gnome/volume_manager/automount_drives false
gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /desktop/gnome/volume_manager/automount_media false
echo "Automatic mounting has been disabled."

####################################ENCRYPT FILESYSTEM####################################

#I THINK THIS WOULD ENCRYPT ROOT FILESYSTEM? DON'T KNOW WHETHER THIS WILL BREAK THE IMAGE OR NOT
#clear
#apt-get -y -qq install ecryptfs-utils cryptsetup
#sudo ecryptfs-migrate-home -u $USER
#echo "Filesystem has been encrypted."

####################################UPDATES####################################

clear
chmod 777 /etc/apt/apt.conf.d/10periodic
cp /etc/apt/apt.conf.d/10periodic ~/Desktop/backups/
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic
echo "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

clear
if [[ $(lsb_release -r) == "Release:	14.04" ]] || [[ $(lsb_release -r) == "Release:	14.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse\ndeb-src http://security.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	12.04" ]] || [[ $(lsb_release -r) == "Release:	12.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse\ndeb-src http://security.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	16.04" ]] || [[ $(lsb_release -r) == "Release:	16.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse\ndeb-src http://security.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	18.04" ]] || [[ $(lsb_release -r) == "Release:	18.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse\ndeb-src http://security.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
else
	echo “Error, cannot detect OS version”
fi
echo "Apt Repositories have been added."

clear
apt-get -y -qq update 
apt-get -y -qq upgrade 
apt-get -y -qq dist-upgrade 
echo "Ubuntu OS has checked for updates and has been upgraded."

clear
apt-get -y -qq update && apt-get -y -qq install linux-image-generic 
apt-get -y -qq update && apt-get -y -qq install linux-headers-generic 
echo "Kernel updates checked for and upgraded."

clear
apt-get -y -qq autoremove 
apt-get -y -qq autoclean 
apt-get -y -qq clean 
echo "All unused packages have been removed."

clear
echo "Check to verify that all update settings are correct."
update-manager

clear
apt-get -y -qq update
apt-get -y -qq upgrade openssl libssl-dev 
apt-cache policy openssl libssl-dev
echo "OpenSSL heart bleed bug has been fixed."

clear
env i='() { :;}; echo Your system is Bash vulnerable. See checklist for how to secure.' bash -c "echo Bash vulnerability test"
echo "Shellshock Bash vulnerability is secured."

####################################LOGS####################################

clear
mkdir -p ~/Desktop/logs
chmod 777 ~/Desktop/logs
echo "Logs folder has been created on the Desktop."

clear
touch ~/Desktop/logs/allusers.txt
uidMin=$(grep "^UID_MIN" /etc/login.defs)
uidMax=$(grep "^UID_MAX" /etc/login.defs)
echo -e "User Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo -e "\nSystem Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo "All users have been logged."
cp /etc/services ~/Desktop/logs/allports.log
echo "All ports log has been created."
dpkg -l > ~/Desktop/logs/packages.log
echo "All packages log has been created."
apt-mark showmanual > ~/Desktop/logs/manuallyinstalled.log
echo "All manually installed packages log has been created."
service --status-all > ~/Desktop/logs/allservices.txt
echo "All running services log has been created."
ps ax > ~/Desktop/logs/processes.log
echo "All running processes log has been created."
ss -l > ~/Desktop/logs/socketconnections.log
echo "All socket connections log has been created."
sudo netstat -tlnp > ~/Desktop/logs/listeningports.log
echo "All listening ports log has been created."
cp /var/log/auth.log ~/Desktop/logs/auth.log
echo "Auth log has been created."
cp /var/log/syslog ~/Desktop/logs/syslog.log
echo "System log has been created."

chmod 777 -R Desktop/backups
chmod 777 -R Desktop/logs

####################################ANTIVIRUS/SYSTEM SCANS####################################

clear
touch ~/Desktop/antivirus_commands.txt
echo -e "USE SUDO\n\nchkrootkit -q\n----------\nlynis -c -quiet\n----------\nrkhunter --update\nrkhunter --propupd\nrkhunter -c --enable all --disable none\n----------\nclamscan -r --bell -i /" > ~/Desktop/antivirus_commands.txt
chmod 777 ~/Desktop/antivirus_commands.txt

echo "Script is complete. Run antivirus/system scan commands using sudo from antivirus_commands.txt on the desktop (you may want to wait for freshclam to finish updating before running clamscan). Check in ~/Desktop/Script.log for some other things to look at. Refer to the checklist for other things to do."