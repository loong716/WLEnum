GetSysInfo() {
	echo -e "[*] System Info\n"
	Hostname="`hostname`"
	Release="`uname -r`"
	Arch="`uname -m`"
	
	if [ "$Hostname" ]; then
		echo "Hostname: $Hostname"
	fi
	
	if [ "$Release" ]; then
		echo "Release: $Release"
	fi
	
	if [ "$Arch" ]; then
		echo "Arch: $Arch"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}


GetUserInfo() {
	echo -e "[*] User Info\n"
	CurrentUser="$USER"
	CurrentUserID="$UID"
	HomePath="$HOME"
	EnvPath="$PATH"
	Group="`groups`"
	
	if [ "$CurrentUser" ]; then
		echo "CurrentUser: $CurrentUser"
	fi
	
	if [ "$CurrentUserID" ]; then
		echo "CurrentUserID: $CurrentUserID"
	fi
	
	if [ "$HomePath" ]; then
		echo "HomePath: $HomePath"
	fi
	
	if [ "$EnvPath" ]; then
		echo "EnvPath: $EnvPath"
	fi
	
	if [ "$Group" ]; then
		echo "Group: $Group"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

CheckPermission() {
	echo -e "[*] Check Sensitive Files Permission"
	pass="`ls -l /etc/passwd`"
	shadow="`ls -l /etc/shadow`"
	group="`ls -l /etc/group`"
	sudoer="`ls -l /etc/sudoers`"
	
	echo "$pass"
	echo "$shadow"
	echo "$group"
	echo "$sudoer"
	
	echo -e "\n------------------------------------------------------\n"
}


GetIPInfo() {
	echo -e "[*] IP Config\n"
	IPConfig="`ifconfig`"
	
	if [ "$IPConfig" ]; then
		echo "$IPConfig"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetRoute() {
	echo -e "[*] Route\n"
	Route="`route`"
	
	if [ "$Route" ]; then
		echo "$Route"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetArpInfo() {
	echo -e "[*] ARP\n"
	ARPInfo="`arp`"
	
	if [ "$ARPInfo" ]; then
		echo "$ARPInfo"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetPortInfo() {
	echo -e "[*] Port Info\n"
	PortInfo="`netstat -atu`"
	
	if [ "$PortInfo" ]; then
		echo "$PortInfo"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetProcessInfo() {
	echo -e "[*] Process Info\n"
	ProcessInfo="`ps -A`"
	
	if [ "$ProcessInfo" ]; then
		echo "$ProcessInfo"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetSchduleTask() {
	echo -e "[*] Schedule Tasks\n"
	SchduleTask="`cat /etc/crontab`"
	
	if [ "$SchduleTask" ]; then
		echo "$SchduleTask"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetBashHistory() {
	echo -e "[*] The last 30 commands executed by the current user\n"
	BashHistory="`tail -n 30 $HOME/.bash_history`"
	
	if [ "$BashHistory" ]; then
		echo "$BashHistory"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetPasswd() {
	echo -e "[*] /etc/passwd\n"
	Passwd="`cat /etc/passwd`"
	
	if [ "$Passwd" ]; then
		echo "$Passwd"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetLoggingUser() {
	echo -e "[*] Logging in User\n"
	LoggingUser="`w`"
	
	if [ "$LoggingUser" ]; then
		echo "$LoggingUser"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetLoginHistory() {
	echo -e "[*] Login History\n"
	LoginHistory="`last`"
	
	if [ "$LoginHistory" ]; then
		echo "$LoginHistory"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetMountInfo() {
	echo -e "[*] Mounted Partitions\n"
	MountInfo="`mount | column -t`"
	
	if [ "$MountInfo" ]; then
		echo "$MountInfo"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetSUIDFile() {
	echo -e "[*] SUID Files\n"
	SUIDFile="`find / -perm -u=s -type f 2>/dev/null`"
	
	if [ "$SUIDFile" ]; then
		echo "$SUIDFile"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}


GetInterestingFile() {
	echo -e "[*] Interesting files modified in the last 24 hours\n"
	InterestingFile="`find / -regex '.*\.\(txt\|log\|conf\|ini\|xml\)$' -mtime 0`"
	
	if [ "$InterestingFile" ]; then
		echo "$InterestingFile"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

:<<!
GetAllFile() {
	echo -e "[*] All Interesting files\n"
	AllFile="`find / -regex '.*\.\(txt\|log\|conf\|ini\|xml\)$'`"
	
	if [ "$AllFile" ]; then
		echo "$AllgFile"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}
!

GetHiddenFile() {
	echo -e "[*] Hidden Files in home path\n"
	HiddenFile="`find / -name ".*" -type f -path "/home/*" -exec ls -al {} \; 2>/dev/null`"
	
	if [ "$HiddenFile" ]; then
		echo "$HiddenFile"
	fi
	
	echo -e "\n------------------------------------------------------\n"
}

GetAll() {

	GetSysInfo
	GetUserInfo
	CheckPermission
	GetLoggingUser
	GetLoginHistory
	GetPasswd
	GetIPInfo
	GetRoute
	GetArpInfo
	GetPortInfo
	GetProcessInfo
	GetSchduleTask
	GetBashHistory
	GetMountInfo
	GetSUIDFile
	GetInterestingFile
	GetHiddenFile
	#GetAllFile
}

GetAll


