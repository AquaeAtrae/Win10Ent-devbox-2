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
bcdedit /timeout 5  # Set the default boot option time-out (seconds)

#######################
# Timezone, Hostname & Domain

refreshenv
$TzHostDomainDone = [System.Environment]::GetEnvironmentVariable("TzHostDomainDone", [System.EnvironmentVariableTarget]::Machine)
'Timezone/Host/Domain already done: $TzHostDomainDone'

if (-not $TzHostDomainDone) {

  $WSLUserName = $UserName.ToLower() -replace "[: ]", ""  # lowercase username stripped of invalid characters
	# -replace " [$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+","_"

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
	# Install-ChocolateyEnvironmentVariable "TzHostDomainDone" "$true" -VariableType Machine

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

function Assign-DriveLetter {
    param(
       [Parameter(Position=0,Mandatory)]
       [string]$DesiredDriveLetter,

       [Parameter(Position=1)]
       [string]$DriveID,

       [Parameter(Position=2)]
       [string]$DriveSerial,

       [Parameter(Position=3)]
       [string]$DriveLabel
       )

    if (!$DriveID) {  if (!$DriveSerial) {  if (!$DriveLabel) {
        $Drive = gwmi Win32_Volume | where {$_.Label -like $DriveLabel} | select -First 1
    } else {
        $Drive = gwmi Win32_Volume | where {$_.SerialNumber -like $DriveSerial} | select -First 1
    } else {
        $Drive = gwmi Win32_Volume | where {$_.DeviceID -like $DriveID} | select -First 1
    } else {
        'ERROR: Must identify the drive to assign letter via DriveID, DriveSerial, or DriveLabel'
    }

    if ($DesiredDriveLetter + ":" -ne $Drive.DriveLetter) {
        $takenDriveLetters = (Get-PSDrive).Name -like '?'
        if ($DesiredDriveLetter -in $takenDriveLetters) {
            # Reassign existing drive to first unused drive letter to release the drive letter
            $firstUnusedDriveLetter = [char[]] (0x44..0x5a) | where { $_ -notin $takenDriveLetters } | select -first 1  # ASCII letters D through Z
            
            Write-Host "Moving existing drive from $DesiredDriveLetter`: to $firstUnusedDriveLetter`:"
            $ExistingDrive = gwmi Win32_Volume | where {$_.DriveLetter -like $DesiredDriveLetter + ":"}

            if (!$ExistingDrive) {'Boxstarter reboot required'; Invoke-Reboot}  # boxstarter reboot
            $ExistingDrive.AddMountPoint($firstUnusedDriveLetter + ":\")
            $ExistingDrive.DriveLetter = $firstUnusedDriveLetter + ":"
            $ExistingDrive.Put()
            $ExistingDrive.Mount()
        }

        if ((Get-PSDrive).Name -like $DesiredDriveLette) {'Boxstarter reboot required'; Invoke-Reboot}  # boxstarter reboot

        Write-Host "Assigning drive to $DesiredDriveLetter`:"
        $Drive.AddMountPoint($DesiredDriveLetter + ":\")
        $Drive.DriveLetter = $DesiredDriveLetter + ":"
        $Drive.Put()
        $Drive.Mount()
    }
}

'Setting drive letter assignments'
Assign-DriveLetter -DesiredDriveLetter "D" -DriveLabel "Data"
Assign-DriveLetter -DesiredDriveLetter "F" -DriveLabel "Files"

'Relocate User Folders'
$home = "F:\Users\AquaeAtrae"
Move-LibraryDirectory "Downloads" "$home\Downloads"
Move-LibraryDirectory "Personal" "$home\Documents"
Move-LibraryDirectory "Desktop" "$home\Desktop"
Move-LibraryDirectory "My Video" "$home\Videos"
Move-LibraryDirectory "My Pictures" "$home\Pictures"
Move-LibraryDirectory "Favorites" "$home\Favorites"
Move-LibraryDirectory "My Music" "$home\Music"
# Move-LibraryDirectory "{56784854-C6CB-462B-8169-88E350ACB882}" "$home\Contacts"
# Move-LibraryDirectory "{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}" "$home\Searches"
# Move-LibraryDirectory "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}" "$home\Links"
# Move-LibraryDirectory "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}" "$home\Saved Games"

'Power Settings'
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -change -monitor-timeout-ac 20
powercfg -change -monitor-timeout-dc 20
powercfg -change -disk-timeout-ac 20
powercfg -change -disk-timeout-dc 20
powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -attributes SUB_SLEEP 9d7815a6-7ee4-497e-8888-515a05f02364 -ATTRIB_HIDE;  powercfg -h on     # not compatible with HostGuardian
# Set-StartScreenOptions -EnableBootToDesktop -EnableDesktopBackgroundOnStart -EnableShowStartOnActiveScreen -EnableListDesktopAppsFirst
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtension
Set-TaskbarOptions -Size Small -Dock Bottom -Combine Full -Lock
Set-TaskbarOptions -Size Small -Dock Bottom -Combine Full -AlwaysShowIconsOn


$winVer = [int](Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ReleaseID')
if ($winVer -ge 2004) {
  $features.enable += @('VirtualMachinePlatform')
}

Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Tools-All -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Management-PowerShell -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Hypervisor -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Services -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Management-Clients -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName HypervisorPlatform -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Windows-Subsystem-Linux -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Containers -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName Windows-Defender-ApplicationGuard -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName TelnetClient -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName TFTP -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName SearchEngine-Client-Package -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName MSRDC-Infrastructure -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName WorkFolders-Client -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName ServicesForNFS-ClientOnly -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName ClientForNFS-Infrastructure -Online -All -NoRestart
Enable-WindowsOptionalFeature -FeatureName NFS-Administration -Online -All -NoRestart
Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName IIS-WebServerRole -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName MediaPlayback -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName WindowsMediaPlayer -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName MSMQ-Container -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName MSMQ-Server -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName HostGuardian -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName NetFx3 -Online -NoRestart
Disable-WindowsOptionalFeature -FeatureName Microsoft-Windows-NetFx3-OC-Package -Online -NoRestart
Enable-WindowsOptionalFeature -FeatureName Microsoft-Windows-NetFx4-US-OC-Package -Online -All -NoRestart


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
Start-Process msiexec.exe -Wait -ArgumentList '/I https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi /passive'  # REPEATS ON REBOOT UNNECESSARILY

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
	
	# mklink /D C:\project_directory \\wsl$\ubuntu-18.03\home\USER\project_directory
	
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
	
}

choco install vcxsrv
# choco install xming

'DONE: WSL2 installed.'
[console]::beep(500,300) # pitch, ms
#read-host "Press ENTER to continue or Ctrl-C to stop..."


#######################
# Profile

# OLT Photoshop Macros.atn
# G Hub macros
# Lightroom Catalogs


#######################
# Installing software

'Installing software...'

# choco install webpi

# .NET
choco install dotnet4.5
choco install dotnet4.6
choco install dotnet4.6.1
choco install dotnet4.6.2
choco install dotnet4.7
choco install dotnet4.7.1
choco install dotnet4.7.2
choco install dotnetfx  # 4.8
choco install dotnetcore-sdk
choco install netfx-4.5.1-devpack
choco install netfx-4.5.2-devpack
choco install netfx-4.6.1-devpack
choco install netfx-4.7-devpack
#choco install netfx-4.7.1-devpack  # FAILS
choco install netfx-4.7.2-devpack
choco install netfx-4.8-devpack

choco install manictime  # requires dotnet 4.5

# %USERPROFILE%\.docker\daemon.json   # "data-root": "",
choco install docker-desktop
# enable resources | WSL integration?
# choco install jq

choco install docker-compose
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
choco install cloneapp	# backup and recover app configs and registries
# cloneapp-ua 

choco install autoit.install
# choco install sudo
choco install gsudo

choco install sql-server-express -ia '/INSTALLSQLDATADIR=""F:\Data\MSSQL15.SQLEXPRESS""'
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
choco install nirlauncher  # includes Win32/Unwaders adware?!
choco install nircmd

choco install crystaldiskinfo
choco install crystaldiskmark
choco install hwinfo.install
choco install gpu-z
choco install cpu-z
choco install hwmonitor

choco install windowsrepair  # tweaking.com

choco install gpg4win
choco install treesizefree


#######################
# NextCloud, Google Drive, KeePass, Authy, Putty, winscp, OpenVPN, SSH Key Agent, notepad++, 7zip

choco install googledrive 
choco install google-drive-file-stream
choco install google-backup-and-sync
# choco install dropbox
choco install nextcloud-client
# choco install syncthing
# choco install rsync

choco install keepassxc
choco install keepass-keepasshttp
choco install authy-desktop
# choco install lastpass
choco install openvpn
# choco install nordvpn  # FAILS
choco install veracrypt

choco install openvpn

choco install winscp 
choco install curl
choco install wget
choco install putty
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
Install-Module -Name 7Zip4Powershell
Import-Module -Name 7Zip4Powershell -Global

choco install autohotkey
# choco install autohotkey.install

choco install git -params '"/GitAndUnixToolsOnPath /WindowsTerminal /NoShellIntegration /SChannel"'

# choco install javaruntime-preventasktoolbar
choco adoptopenjdk11 `
  adoptopenjdk8 `

choco install hub `
  rapidee `
  slack `
  keybase `  # requires dotnet4.7
  gh `
  hub `
  googlechrome `
  firefox `  # FAILS
  nodejs `
  maven `
#  jetbrainstoolbox `
#  bitnami-xampp `
#  apache-httpd `


choco install microsoft-edge


choco install microsoft-office-deployment --params="'/64bit /Product:ProPlus2019Volume /Exclude:OneDrive,Outlook,Lync,Groove'"  # Office Volume license requires MLK key
# choco install office365proplus
# choco install libreoffice-fresh
# choco install openoffice
# choco install crystalreports2008runtime
# choco install evernote
# choco install adobe-creative-cloud  # FAILS error code 72

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
choco install nvidia-display-driver
# choco install geforce-experience  # FAILS
# choco install msiafterburner
choco install samsung-magician
# choco install logitech-options
# choco install ccleaner
# choco install ccenhancer
# choco install bulk-crap-uninstaller

RefreshEnv

$chrome = convert-path (ls "$env:localappdata\" -recurse -include "chrome.exe")[0].pspath
If ($chrome -ne "")	{	Install-ChocolateyPinnedTaskBarItem $chrome }



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