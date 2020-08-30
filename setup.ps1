'RUNNING: setup.ps1'
'Installs Chocolatey, Boxstarter, and runs next script to build fresh Windows 10 machine.'
''
# by AquaeAtrae 8/30/2020


# USAGE using Powershell (Admin): 
#   START https://boxstarter.org/package/url?https://raw.githubusercontent.com/AquaeAtrae/Win10Ent-devbox-2/master/setup.ps1
#
# USAGE:
#   PowerShell.exe -ExecutionPolicy Bypass -File .\setup.ps1
#
# USAGE: 
#   PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/AquaeAtrae/Win10Ent-devbox-2/master/setup.ps1'))"
#

# PREREQUISITES:
# Windows 10 Enterprise (2004 or newer)
# Use a Domain account (not online)
#
# Existing partitions labelled "Data" (D:) and "Files" (F:)
# Existing user data F:\Users\<username>

$UserName = $env:username
$UserDomain = $env:UserDomain
$LocalCredential = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name


#######################
# Chocolatey, Boxstarter, and prerequisites

$ChocoInstalled = $false; if (Get-Command choco.exe -ErrorAction SilentlyContinue) { $ChocoInstalled = $true }
$BoxyInstalled = $false; if (Get-Command BoxStarter.bat -ErrorAction SilentlyContinue) { $BoxyInstalled = $true }

if (-not($ChocoInstalled -or $BoxyInstalled)) {
	'Chocolatey or BoxStarter not yet installed.'

	# $Env:ChocolateyInstall = "%PROGRAMDATA%\Chocolatey"
	[System.Environment]::SetEnvironmentVariable("ChocolateyInstall", $null, 'User')

	# $chocoInstall = New-TemporaryFile 

	'Install chocolatey package manager from chocolatey.org .' 
	'chocolatey default install path is C:\ProgramData\chocolatey\lib .'
	'Check version with `choco.exe --version`.' 

	Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

	& "$Env:ProgramData\chocolatey\choco.exe" upgrade chocolatey --yes --force
	'Chocolatey installed and upgraded.'

	'Installing Boxstarter.'
	& "$Env:ProgramData\chocolatey\choco.exe" install Boxstarter --yes --force 

	'DONE: Boxstarter installed.' 

	'NOTE: Must open a new PowerShell terminal to load choco environment variables...'
	refreshenv

	[console]::beep(500,300) # pitch, ms
	read-host "Press ENTER to continue or Ctrl-C to stop..."

}
else
{
	'Chocolatey and Boxstarter already installed...'
}

#######################
# Boxstarter options
$Boxstarter.RebootOk=$true
$Boxstarter.NoPassword=$false # Is this a machine with no logon password?
$Boxstarter.AutoLogin=$true

# Get the base URI path from the ScriptToCall value
$bstrappackage = "-bootstrapPackage"
$helperUri = $Boxstarter['ScriptToCall']
$strpos = $helperUri.IndexOf($bstrappackage)
$helperUri = $helperUri.Substring($strpos + $bstrappackage.Length)
$helperUri = $helperUri.TrimStart("'", " ")
$helperUri = $helperUri.TrimEnd("'", " ")
$helperUri = $helperUri.Substring(0, $helperUri.LastIndexOf("/"))
$helperUri += "/scripts"
Write-Host "helper script base URI is $helperUri"

function ExecuteScript {
  Param ([string]$script)
  Write-Host "executing $helperUri/$script ..."
	Invoke-Expression ((new-object net.webclient).DownloadString("$helperUri/$script"))
}


Disable-UAC
Disable-MicrosoftUpdate


#######################
# Timezone, Hostname & Domain

if ($TzHostDomainDone) {

	$TimeZone = Read-Host "Time zone ($(Get-Timezone).Id)"
	if ([string]::IsNullOrEmpty($TimeZone)) {
		$TimeZone = $(Get-Timezone).Id  # no change
	}
	else {
		Write-BoxstarterMessage "Setting time zone to $TimeZone"
		# & C:\Windows\system32\tzutil /s "$TimeZone"
		Set-TimeZone -Id $TimeZone
	}

	$ComputerName = Read-Host "Computer name ($env:ComputerName)"
	if ([string]::IsNullOrEmpty($ComputerName)) {
		$ComputerName = $env:ComputerName  # no change
	}
	else {
		# Rename computer (boxstarter will reboot and resume script)
		Write-BoxstarterMessage "Setting computer host name to $ComputerName"
		Rename-Computer -NewName $ComputerName -LocalCredential $LocalCredential -Restart
	}

	$DomainName = Read-Host "Domain ($((Get-WmiObject Win32_ComputerSystem).Domain))"
	if ([string]::IsNullOrEmpty($DomainName)) {
		$DomainName = $((Get-WmiObject Win32_ComputerSystem).Domain)
	}
	else {
		# Join domain
		#   better method? https://powershell.one/wmi/root/cimv2/win32_computersystem-JoinDomainOrWorkgroup
		Function Join-Domain { 
			param( 
							[string]$Domain=$(read-host "Please specify the domain to join"), 
							[System.Management.Automation.PSCredential]$Credential = $(Get-Credential) 
							) 
			$CS = Get-WmiObject Win32_ComputerSystem
			$CS.JoinDomainOrWorkgroup($Domain,$Credential.GetNetworkCredential().Password,$Credential.UserName,$null,3) 
		} 

		Write-BoxstarterMessage "Setting Domain to $DomainName"
		'Requires Domain Admin credentials'
		Join-Domain $DomainName
	}

	$TzHostDomainDone = $true

	'DONE: TimeZone, Computer Name, Domain.'
	[console]::beep(500,300) # pitch, ms

}

#######################
# RDP Remote Access, PS Remoting, Ansible, Jump Desktop, OpenVPN with configs, Firewall rules

# Enable-PSRemoting -Force  # allow remote powershell

Enable-RemoteDesktop   # boxy: enables feature    and firewall rule??

# netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# TO DO: only enable most narrow rules with specified source IP addresses

'DONE: Remote access enabled.'
[console]::beep(500,300) # pitch, ms

'Enabling Windows 10 Features...'
$features = @{
  enable = @(
		'Microsoft-Hyper-V-All',  # requires Windows 10 Professional or Enterprise
		'Microsoft-Hyper-V',
		'Microsoft-Hyper-V-Tools-All',
		'Microsoft-Hyper-V-Management-PowerShell',
		'Microsoft-Hyper-V-Hypervisor',
		'Microsoft-Hyper-V-Services',
		'Microsoft-Hyper-V-Management-Clients',
		'HypervisorPlatform',    # requires Windows 10 Professional or Enterprise
		
    'Microsoft-Windows-Subsystem-Linux',
    'Containers',
		'Containers-DisposableClientVM',  # sandbox
		'Windows-Defender-ApplicationGuard', # IE/Edge view untrusted websites from within VM sandbox
		'TelnetClient ',
		'TFTP',
		
		'SearchEngine-Client-Package',
		'MSRDC-Infrastructure',
		'WorkFolders-Client',
		# 'Microsoft-Windows-NetFx4-US-OC-Package',
		
		'ServicesForNFS-ClientOnly',
		'ClientForNFS-Infrastructure',
		'NFS-Administration'
  )
  disable = @(
    # 'Internet-Explorer-Optional-amd64'
		# 'IIS-WebServerRole',
		# 'MediaPlayback',
		# 'WindowsMediaPlayer',
		
		# 'MSMQ-Container',  # Message queueing
		# 'MSMQ-Server',
		# 'HostGuardian',  # Guarded fabric and shielded VMs (cloud security), but blocks hibernation
		
		# 'NetFx3',
		# 'Microsoft-Windows-NetFx3-OC-Package'
  )
}
$winVer = [int](Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ReleaseID')
if ($winVer -ge 2004) {
  $features.enable += @('VirtualMachinePlatform')
}

if ($features.disable) {
  Disable-WindowsOptionalFeature -FeatureName $features.disable -Online -NoRestart
}
if ($features.disable) {
	Enable-WindowsOptionalFeature -FeatureName $features.enable -Online -All -NoRestart
}

'DONE: Windows 10 Features enabled.'
'NEXT: WSL2 Kernel Update?'
[console]::beep(500,300) # pitch, ms
read-host "Press ENTER to continue or Ctrl-C to stop..."

'Installing software.'

choco install windows-adk-all   # WinPE builder

choco install sysinternals
choco install linkshellextension

#######################
# Chrome, Firefox Developer, Safari, Click-Once extensions

cinst google-chrome-x64

#######################
# NextCloud, Google Drive, KeePass, Authy, Putty, winscp, OpenVPN, SSH Key Agent, notepad++, 7zip

cinst googledrive 
cinst google-drive-file-stream

cinst keepassxc
cinst authy-desktop

cinst openvpn

choco install winscp 
choco install putty.install 
choco install zoom 
choco install logmein.client

cinst notepadplusplus

choco install sharex

choco install 7zip

choco install autohotkey


'DONE: Software installed.'
[console]::beep(500,300) # pitch, ms
read-host "Press ENTER to continue or Ctrl-C to stop..."


Enable-UAC
Enable-MicrosoftUpdate

Install-WindowsUpdate -acceptEula