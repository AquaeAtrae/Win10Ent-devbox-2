'RUNNING: setup.ps1'
'Installs Chocolatey, Boxstarter, and runs next script to build fresh Windows 10 machine.'
''
# Uninterupted Operating System
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

# RESOURCES:
# Microsoft boxstarter sample scripts   https://github.com/microsoft/windows-dev-box-setup-scripts
# Recommended dev tools https://www.hanselman.com/blog/ScottHanselmans2014UltimateDeveloperAndPowerUsersToolListForWindows.aspx
# Sample boxstarter and good comments with extensive clean up of Windows https://gist.github.com/NickCraver/7ebf9efbfd0c3eab72e9


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
	#read-host "Press ENTER to continue or Ctrl-C to stop..."

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

# SOURCE: https://github.com/microsoft/windows-dev-box-setup-scripts
# Get the base URI path from the ScriptToCall value
$bstrappackage = "-bootstrapPackage"
$helperUri = $Boxstarter['ScriptToCall']
$strpos = $helperUri.IndexOf($bstrappackage)
$helperUri = $helperUri.Substring($strpos + $bstrappackage.Length)
$helperUri = $helperUri.TrimStart("'", " ")
$helperUri = $helperUri.TrimEnd("'", " ")
$helperUri = $helperUri.Substring(0, $helperUri.LastIndexOf("/"))
$helperUri += "/scripts"
write-host "helper script base URI is $helperUri"

function executeScript {
    Param ([string]$script)
    write-host "executing $helperUri/$script ..."
	iex ((new-object net.webclient).DownloadString("$helperUri/$script"))
}


Disable-UAC
Disable-MicrosoftUpdate


#######################
# Timezone, Hostname & Domain

refreshenv
$TzHostDomainDone = [System.Environment]::GetEnvironmentVariable("TzHostDomainDone", [System.EnvironmentVariableTarget]::Machine)
'Timezone/Host/Domain already done: $TzHostDomainDone'

if (-not $TzHostDomainDone) {

  $WSLUserName = $UserName.ToLower() -replace "[: ]", ""  # lowercase username stripped of invalid characters

	# TO DO: alternatively, just force password change after first login?
  [System.Management.Automation.PSCredential]$WSLCredential = $(Get-Credential -UserName $UserName -Message "Set WSL Linux username and initial password")

  $OrigTimezone = $(Get-Timezone).Id
	$TimeZone = Read-Host "Time zone ($OrigTimezone)"
	if ([string]::IsNullOrEmpty($TimeZone)) {
		$TimeZone = $OrigTimezone  # no change
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

  $OrigDomain = $((Get-WmiObject Win32_ComputerSystem).Domain)
	$DomainName = Read-Host "Domain ($OrigDomain)"
	if ([string]::IsNullOrEmpty($DomainName)) {
		$DomainName = $OrigDomain
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

	[System.Environment]::SetEnvironmentVariable('TzHostDomainDone', $true, [System.EnvironmentVariableTarget]::Machine)

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

Enable-WindowsOptionalFeature -FeatureName $features.enable -Online -All -NoRestart

# Enable long file names (beyond 260 chars)
# [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem]
#"LongPathsEnabled"=dword:00000001

'DONE: Windows 10 Features enabled'
''
#######################
# WSL2

'NEXT: WSL2 Kernel Update?'
'  Start-Process msiexec.exe -Wait -ArgumentList ''/I https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi /passive'' '
[console]::beep(500,300) # pitch, ms
# read-host "Press ENTER to continue or Ctrl-C to stop..."


# Start-Process msiexec.exe -Wait -ArgumentList '/I https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi /quiet /qn /norestart'
Start-Process msiexec.exe -Wait -ArgumentList '/I https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi /passive'

$winVer = [int](Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ReleaseID')
if ($winVer -ge 2004) {
  RefreshEnv
  wsl --set-default-version 2
}

if (!(Get-Command "ubuntu2004.exe" -ErrorAction SilentlyContinue)) {
  $item = "wslubuntu2004"
  $file = "$env:TEMP\$item.appx"
  Write-Host "Downloading $item"
  curl.exe -sL https://aka.ms/$item -o $file
	# TO DO: move appx installation to custom location
	# https://kontext.tech/column/tools/308/how-to-install-windows-subsystem-for-linux-on-a-non-c-drive
	
  Add-AppxPackage $file
  Remove-Item $file

  RefreshEnv

  Ubuntu2004 install --root
  Ubuntu2004 config --default-user root
  Ubuntu2004 run "curl -sL '$helperUri/WSL.sh' | bash"
	# Ubuntu2004 run "curl -sL '$helperUri/WSL.sh' | sed -En ""s/USERNAME/$UserName/g"" | bash"
  
	Ubuntu2004 run "useradd -m -s '/usr/bin/bash' -G sudo ${UserName}"
	
	'Setting WSL password'
	[console]::beep(500,300) # pitch, ms
  #Ubuntu2004 run passwd $UserName
	
	Ubuntu2004 run "printf ""%s:%s\n"" """ + $WSLCredential.GetNetworkCredential().UserName + """ """ + $WSLCredential.GetNetworkCredential().Password + """ | chpasswd"
	
  Ubuntu2004 config --default-user $UserName
	
	choco install lxrunoffline

	# icacls D:\wsl /grant "USERNAME:(OI)(CI)(F)"
	# lxrunoffline move -n Ubuntu-20.04 -d D:\wsl\installed\Ubuntu-20.04  # relocate WSL root storage... but will it overwrite existing?!
	lxrunoffline get-dir -n Ubuntu-20.04
	
	# mklink /D C:\project_directory \\wsl$\ubuntu-18.03\home\user\project_directory
}

choco install vcxsrv
# choco install xming

'DONE: WSL2 installed.'
[console]::beep(500,300) # pitch, ms
#read-host "Press ENTER to continue or Ctrl-C to stop..."

#######################
# Installing software

'Installing software...'

choco install webpi

# .NET
choco install dotnet4.5
choco install dotnet4.6
choco install dotnet4.6.1
choco install dotnet4.6.2
choco install dotnet4.7
choco install dotnet4.7.1
choco install dotnetcore-sdk
choco install netfx-4.5.1-devpack
choco install netfx-4.5.2-devpack
choco install netfx-4.6.1-devpack
choco install netfx-4.7-devpack
choco install netfx-4.7.1-devpack
choco install dotnetfx  # 4.8
choco install netfx-4.8-devpack

choco install manictime  # requires dotnet 4.5

# %USERPROFILE%\.docker\daemon.json   # "data-root": "",
choco install docker-desktop
# enable resources | WSL integration?
# choco install jq

choco install  docker-compose
choco install docker-kitematic

# choco install virtualbox
# choco install virtualbox-guest-additions-guest.install

choco install windows-adk-all   # WinPE builder

choco install powershell-core
choco install microsoft-windows-terminal
# https://aka.ms/terminal-documentation

choco install notepadplusplus

choco install chocolateygui
choco install boxstarter.hyperv
choco install autoit.install
choco install nircmd
# choco install sudo
choco install gsudo

choco install sql-server-express -ia '/INSTALLSQLDATADIR=""F:\Data\MSSQL15.SQLEXPRESS""'
# TO DO: modify nupkg (zip) adding $silentArgs for custom /INSTALLSQLDATADIR
# https://chocolatey.org/api/v2/package/sql-server-express/2019.20200409
choco install ssms

# choco install vscode
choco install vscodium
choco pin add -n=vscodium
choco install arduino
choco install firacode
choco install mkcert
choco install bugshooting
# Windows Steps Recorder is built-in

# choco install intellijidea-community  # jetbrains java IDE
# choco install phpstorm
# choco install webstorm
# choco install kubernetes-cli

choco install winmerge	
# choco install sublimetext2
# atom
	
# choco install nxlog

choco install everything  # search files and folders
choco install sysinternals
choco install handle  # shows which process has files open
choco install powertoys
choco install autoruns
choco install linkshellextension
choco install rufus
choco install nirlauncher

choco install crystaldiskinfo
choco install crystaldiskmark
choco install hwinfo.install
choco install gpu-z
choco install cpu-z
choco install hwmonitor
choco install windowsrepair

choco install gpg4win
choco install treesizefree


#######################
# NextCloud, Google Drive, KeePass, Authy, Putty, winscp, OpenVPN, SSH Key Agent, notepad++, 7zip

cinst googledrive 
cinst google-drive-file-stream
choco install google-backup-and-sync
# choco install dropbox
choco install nextcloud-client
# choco install syncthing
# choco install rsync

cinst keepassxc
choco install keepass-keepasshttp
cinst authy-desktop
# choco install lastpass
choco install openvpn
choco install nordvpn
choco install veracrypt

cinst openvpn

choco install winscp 
choco install curl
choco install wget
choco install putty
choco install winscp
# choco install utorrent
choco install jq  # cli json processor
choco install postman  # API testing tool
choco install teracopy
choco install grepwin
# choco install logrotate

# choco install wireshark
# choco install winpcap
# choco install nmap
# choco install advanced-ip-scanner
# choco install zap  # OWASP Zap proxy tester

choco install zoom 
# choco install logmein.client
# choco install teamviewer-qs

choco install sharex

choco install 7zip

choco install autohotkey  # FAILS?
# choco install autohotkey.install

choco install git -params '"/GitAndUnixToolsOnPath /WindowsTerminal /NoShellIntegration /SChannel"'

# choco install javaruntime-preventasktoolbar
choco adoptopenjdk11 `
  adoptopenjdk8 `

choco install dotnetcore-sdk `
  hub `
  rapidee `
  slack `
  keybase `
  gh `
  hub `
  7zip `
  googlechrome `
  firefox `
  nodejs `
  putty `
  maven `
#	jetbrainstoolbox `
#  bitnami-xampp `
#  apache-httpd `


choco install microsoft-edge


# choco install office365proplus
# choco install libreoffice-fresh
# choco install openoffice
# choco install crystalreports2008runtime
# choco install evernote
# choco install adobe-creative-cloud

# choco install qgis
# choco install googleearthpro

# choco install inkscape
# choco install gimp
# choco install drawio  # diagrams
# choco install audacity
# choco install audacity-lame  # mp3 encoder
# choco install shotcut  # video editor
# choco install openshot  # video editor
# choco install avidemux
# choco install carnac  # shows keystrokes for demos
# choco install blender
# choco install handbrake.install
# choco install meshroom  # photoscanning

# choco install discord.install
# choco install steam
# choco install origin
# choco install uplay

choco install dellcommandupdate
choco install dell-update
choco install geforce-experience
# choco install msiafterburner
choco install samsung-magician
# choco install logitech-options
# choco install ccleaner
# choco install ccenhancer
# choco install bulk-crap-uninstaller

RefreshEnv



'DONE: Software installed.'
[console]::beep(500,300) # pitch, ms
#read-host "Press ENTER to continue or Ctrl-C to stop..."

# 	[System.Environment]::SetEnvironmentVariable('TzHostDomainDone', $null, [System.EnvironmentVariableTarget]::Machine)  # clear variable

choco install choco-package-list-backup
# https://www.alexdresko.com/2014/12/22/automatically-generating-a-chocolatey-install-script/

choco install choco-upgrade-all-at  # Task Scheduler to update all choco packages

Enable-UAC
Enable-MicrosoftUpdate

Install-WindowsUpdate -acceptEula  # Installs any current updates