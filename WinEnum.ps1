Function VMDetect
{
	"[*] Virtual Machine Detect"
	$CPU = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors
	$Memory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory
	$SerialNumber = (Get-WmiObject Win32_BIOS).SerialNumber
	$Manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
	$Model = (Get-WmiObject Win32_ComputerSystem).Model
	if(($Manufacturer -Match "VM") -or ($Manufacturer -Match "Virtual") -or ($Manufacturer -Match "VM") -or ($Manufacturer -Match "Hyper") -or ($Manufacturer -Match "Box"))
	{
		"[*] Seems to be a virtual machine`n"
	}
	else
	{
		"[*] Seems not to be a virtual machine`n"
	}
	"NumberOfLogicalProcessors: $CPU"
	"TotalPhysicalMemory: {0:f2}GB" -f ($Memory/1GB)
	"BIOS SerialNumber: $SerialNumber"
	"Manufacturer: $Manufacturer"
	"Model: $Model`n"
}


Function AVDetect
{
	param($Computername)
	"[*] Anti-Virus SoftWare Detect"
	if($Computername -Match "Server")
	{
		"[*] This function does not support server system.`n"
	}
	else{
		""
		$AV = Get-WmiObject -namespace root\SecurityCenter2 -class Antivirusproduct
		if ($AV)
		{
			$AV | Foreach-Object{
				"Name: {0}" -f $_.displayName
				"PathToSignedProductExe: {0}" -f $_.pathToSignedProductExe
				AVStatusDetect($_.productState)
			}
		}
		else
		{
			"[*] It seems that there is no anti-virus software, please check the results of other commands for further confirmation.`n"
		}
	}
}

Function AVStatusDetect
{
	param($productState)
	$state = '{0:X6}' -f $productState
	$scanner = $state[2,3] -join ''
	$updated = $state[4,5] -join ''
	if($scanner -ge '10')
	{
		"Status: Enabled"
	}
	elseif($scanner -eq '00' -or $scanner -eq '01')
	{
		"Status: Disabled"
	}
	else{ "Status: Unknown"}
	
	if($updated -eq '00')
	{
		"Updated: Yes`n"
	}
	elseif($update -eq '01')
	{
		"Updated: No`n"
	}
	else{ "Updated: Unknown`n"}
	
	
}


Function GetUserInfo
{
	#$names = (Get-WmiObject -Class Win32_UserAccount).Name
	#$Domains = (Get-WmiObject -Class Win32_UserAccount).Domain
	$Domains = Get-WmiObject -Class Win32_UserAccount | Select-Object Domain
	$CurrentUser = whoami
	"[*] User Info"
	"[*] Current User: $CurrentUser`n"
	$names = Get-WmiObject -Class Win32_UserAccount | Foreach-Object { $_.Name }
	
	foreach($name in $names)
	{
		$i = 0
		$userinfo = net user $name
		"{0}\{1}" -f ($Domains[$i].Domain, $name)
		"-----------------------"
		$userinfo[1,18,8,22,23]
		"`n"
		$i += 1
	}
}


Function GetSysInfo
{
	$PSComputerName = (Get-WmiObject Win32_OperatingSystem).PSComputerName
	$Caption = (Get-WmiObject Win32_OperatingSystem).Caption
	$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
	$MUILanguages = (Get-WmiObject Win32_OperatingSystem).MUILanguages
	$Version = (Get-WmiObject Win32_OperatingSystem).Version
	$Domain = (Get-WmiObject Win32_ComputerSystem).Domain
	
	
	AVDetect($Caption)
	"------------------------------------------------------------------------------`n"
	#$ip = Get-NetIPConfiguration 
	"[*] System Info`n"
	
	"PSComputerName: $PSComputerName"
	"Caption: $Caption"
	"OSArchitecture: $OSArchitecture"
	"MUILanguages: $MUILanguages"
	"Version: $Version"
	"Domain: $Domain`n"
	
	"------------------------------------------------------------------------------`n"
	
	GetInstalledPrograms($OSArchitecture)
	
}


Function GetPatchInfo
{
	"[*] Patch Info"
	$patch = Get-WmiObject Win32_QuickFixEngineering | Format-Table HotFixID
	if($patch)
	{
		$patch
	}
}


# https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E5%9F%BA%E7%A1%80-%E8%8E%B7%E5%BE%97%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%B7%B2%E5%AE%89%E8%A3%85%E7%9A%84%E7%A8%8B%E5%BA%8F%E5%88%97%E8%A1%A8/
Function GetInstalledPrograms
{
	Param($Sysbits)
	$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
	$RedirectPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
	
	"[*] Installed Programs"
	if ($Sysbits -Match "64")
	{
		"[*] x64`n"
		GetRegValue($Path)
		GetRegValue($RedirectPath)
	}
	else
	{
		"[*] x86`n"
		GetRegValue($Path)
	}
	""
}

Function GetServiceInfo
{
	"[*] Service Info"
	$ServiceInfo = Get-WmiObject Win32_Service | Sort-Object State | Format-Table Caption,State,StartMode
	if($ServiceInfo)
	{
		$ServiceInfo
	}
}

Function GetRegValue
{
	param($RegPath)
	$RegKeys = dir $RegPath -Name
	foreach($RegKey in $RegKeys)
	{
		(Get-ItemProperty -Path $RegPath$RegKey).DisplayName
	}
	
}

<#filter Get-ProcessOwner
{
	$id = $_.ProcessId
	$info = (Get-WmiObject -Class Win32_Process -Filter "Handle=$id").GetOwner()
	if($info.ReturnValue -eq 2)
	{
		$owner = ''
	}
	else
	{
		$owner = "{0}\{1}" -f ($info.Domain,$info.User)
	}
	$_ | Add-Member -MemberType NoteProperty -Name Owner -Value $owner -PassThru
}#>

Function GetProcessInfo
{
	"[*] Process Info"
	
	#Get-WmiObject -Class Win32_Process | Get-ProcessOwner | Format-Table -Property @{ e='Name'; width = 40 },@{ e='Handle'; width = 10 },@{ e='Owner'; width = 40 }
	Get-WmiObject -Class Win32_Process | Format-Table -Property @{ e='Name'; width = 40 },@{ e='Handle'; width = 10 }
}


function GetNetshareInfo
{
	"[*] Netshare Info"
	$netshare = Get-WmiObject -Class Win32_Share | Format-Table Name,Path,Status,Description -Autosize
	if($netshare)
	{
		$netshare
	}
}

Function GetUsersFile
{
	"[*] User's File`n"
	$UsersFile = Get-ChildItem -Path "C:\Users" -Recurse -Include @("*.txt","*.pdf","*.doc*","*.xls*","*.ppt*") -ErrorAction SilentlyContinue | Select-Object FullName
	if($UsersFile)
	{
		$UsersFile
		""
	}
}

Function GetNetConfig
{
	"[*] IPConfig"
	ipconfig /all
	""
	"-----------------------------------------------------------------------`n"
	"[*] Net Route"
	Get-WmiObject -Class Win32_IP4RouteTable | Format-Table Destination,Mask,NextHop,Metric1
	"-----------------------------------------------------------------------`n"
	"[*] Arp"
	arp -a
	""
	"-----------------------------------------------------------------------`n"
	"[*] DNS Cache"
	ipconfig /displaydns
	"-----------------------------------------------------------------------`n"
	"[*] Port Info"
	netstat -ano
	""
}


<#
Function GetAllFiles
{
	$Drives = [Environment]::GetLogicalDrives()
	foreach($Drive in $Drives)
	{
		Get-ChildItem -Path $Drive -Recurse -Include @("*.txt","*.pdf","*.doc*","*.xls*","*.ppt*") -ErrorAction SilentlyContinue | Select-Object FullName
	}
}
#>

# https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1
Function GetFWRules
{
	"[*] Windows FireWall Rules`n"
	$fw = New-Object -ComObject HNetCfg.FwPolicy2
	$fwRules = $fw.Rules
	$fwaction = @{1="Allow";0="Block"}
	$FwProtocols = @{1="ICMPv4";2="IGMP";6="TCP";17="UDP";41="IPV6";43="IPv6Route"; 44="IPv6Frag"; 47="GRE"; 58="ICMPv6";59="IPv6NoNxt";60="IPv60pts";112="VRRP"; 113="PGM";115="L2TP"}
	$fwdirection = @{1="Inbound"; 2="Outbound"}
	
	$fwRules | Foreach-Object{
		"Name: {0}" -f $_.Name
		"ApplicationName: {0}" -f $_.ApplicationName
		"Action: {0}" -f $fwaction.Get_Item($_.Action)
		"Direction: {0}" -f $fwdirection.Get_Item($_.Direction)
		"Protocol: {0}" -f $fwProtocols.Get_Item($_.Protocol)
		"LocalAddresses: {0}" -f $_.LocalAddresses
		"LocalPorts: {0}" -f $_.LocalPorts
		"RemoteAddresses: {0}" -f $_.RemoteAddresses
		"RemotePort: {0}" -f $_.RemotePorts
		""
	}
}


Function Main
{
	"------------------------------------------------------------------------------`n"
	VMDetect
	"------------------------------------------------------------------------------`n"
	GetSysInfo
	"------------------------------------------------------------------------------`n"
	GetUserInfo
	"------------------------------------------------------------------------------`n"
	GetPatchInfo
	"------------------------------------------------------------------------------`n"
	GetServiceInfo
	"------------------------------------------------------------------------------`n"
	GetProcessInfo
	"------------------------------------------------------------------------------`n"
	GetNetshareInfo
	"------------------------------------------------------------------------------`n"
	GetNetConfig
	"------------------------------------------------------------------------------`n"
	GetUsersFile
	"------------------------------------------------------------------------------`n"
	GetFWRules
	"------------------------------------------------------------------------------`n"
	#GetAllFiles
	#"------------------------------------------------------------------------------`n"
}

Main
