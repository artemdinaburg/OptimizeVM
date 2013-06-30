@echo off

rem Based on the script provided in the VMware View Optimization Guide:
rem http://www.vmware.com/files/pdf/VMware-View-OptimizationGuideWindows7-EN.pdf
rem
rem This script is not provied by, nor endorsed by, nor affiliated with VMware, Inc.
rem
rem THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
rem IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
rem FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
rem AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
rem LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
rem OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
rem THE SOFTWARE.
rem
rem Licensed under the MIT license
rem 

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Please re-run this with Administrative privileges!
    exit
)

echo Starting VM Optimization at:  > OptimizeVM.log
date /t >> OptimizeVM.log
time /t >> OptimizeVM.log

echo Disabling Windows Features...

echo 	Windows Gadget Platform
dism /NoRestart /online /Disable-Feature /FeatureName:WindowsGadgetPlatform >>OptimizeVM.log 2>&1

echo 	Windows Media Player
dism /NoRestart /online /Disable-Feature /FeatureName:WindowsMediaPlayer >>OptimizeVM.log 2>&1

echo 	Windows Media Playback
dism /NoRestart /online /Disable-Feature /FeatureName:MediaPlayback >>OptimizeVM.log 2>&1

echo 	Windows Media Center
dism /NoRestart /online /Disable-Feature /FeatureName:MediaCenter >>OptimizeVM.log 2>&1

echo 	Optical Media Disc
dism /NoRestart /online /Disable-Feature /FeatureName:OpticalMediaDisc >>OptimizeVM.log 2>&1

echo 	.NET famework
dism /NoRestart /online /Disable-Feature /FeatureName:NetFx3 >>OptimizeVM.log 2>&1

echo 	Tablet PC Components
dism /NoRestart /online /Disable-Feature /FeatureName:TabletPCOC >>OptimizeVM.log 2>&1

echo 	Printing Features
dism /NoRestart /online /Disable-Feature /FeatureName:Printing-Foundation-Features >>OptimizeVM.log 2>&1
dism /NoRestart /online /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client >>OptimizeVM.log 2>&1

echo 	Fax Services
dism /NoRestart /online /Disable-Feature /FeatureName:FaxServicesClientPackage >>OptimizeVM.log 2>&1

echo 	MSRDC
dism /NoRestart /online /Disable-Feature /FeatureName:MSRDC-Infrastructure >>OptimizeVM.log 2>&1

echo 	XPS Support
dism /NoRestart /online /Disable-Feature /FeatureName:Printing-XPSServices-Features >>OptimizeVM.log 2>&1

echo 	Windows Search
dism /NoRestart /online /Disable-Feature /FeatureName:SearchEngine-Client-Package >>OptimizeVM.log 2>&1

echo Disabling Last Access for NTFS
fsutil behavior set DisableLastAccess 1 >>OptimizeVM.log 2>&1

echo Setting Visual Effects for Best Performance
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0x2 /f >>OptimizeVM.log 2>&1

echo Disabling IPv6
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xFFFFFFFF /f >>OptimizeVM.log 2>&1

reg load "hku\temp" "%USERPROFILE%\..\Default User\NTUSER.DAT" >>OptimizeVM.log 2>&1

echo Setting Wallpaper to None
reg ADD "hku\temp\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /d " " /f >>OptimizeVM.log 2>&1

echo Disabling Windows RSS feeds
reg ADD "hku\temp\Software\Microsoft\Feeds" /v SyncStatus /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1

echo Disabling Action Center
reg ADD "hku\temp\Software\Microsoft\WIndows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 0x1 /f >>OptimizeVM.log 2>&1
reg unload "hku\temp" >>OptimizeVM.log 2>&1

echo Disabling IE First Run Customization
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v DisableFirstRunCustomize /t REG_DWORD /d 0x1 /f >>OptimizeVM.log 2>&1

echo Disabling SuperFetch
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0x3 /f >>OptimizeVM.log 2>&1

echo Disabling Windows Update
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0x1 /f >>OptimizeVM.log 2>&1

echo Disabling SystemRestore
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 0x1 /f >>OptimizeVM.log 2>&1

echo Disabling Network Location Wizard
reg ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f >>OptimizeVM.log 2>&1

echo Set Disk Timeout to 190
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Disk" /v TimeOutValue /t REG_DWORD /d 190 /f >>OptimizeVM.log 2>&1

echo Limiting Event Log Size
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application" /v MaxSize /t REG_DWORD /d 0x100000 /f >>OptimizeVM.log 2>&1
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application" /v Retention /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\System" /v MaxSize /t REG_DWORD /d 0x100000 /f >>OptimizeVM.log 2>&1
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\System" /v Retention /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Security" /v MaxSize /t REG_DWORD /d 0x100000 /f >>OptimizeVM.log 2>&1
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Security" /v Retention /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1

echo Disabling Crash Dumps
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1

echo Enabling RDP
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1

echo Disabling UAC
reg ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\system" /v EnableLUA /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1

echo Removing Windows SideShow
reg ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Sideshow" /v Disabled /t REG_DWORD /d 0x1 /f >>OptimizeVM.log 2>&1

echo Disabling Services...

echo 	BitLocker
Powershell Set-Service 'BDESVC' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	BitLocker Backup Engine
Powershell Set-Service 'wbengine' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Diagnostic Policy Service
Powershell Set-Service 'DPS' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Desktop Window Manager
Powershell Set-Service 'UxSms' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Disk Defragmenter
Powershell Set-Service 'Defragsvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Home Group Listener
Powershell Set-Service 'HomeGroupListener' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Home Group Provider
Powershell Set-Service 'HomeGroupProvider' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	IP Helper Service
Powershell Set-Service 'iphlpsvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	iSCSI Initiator
Powershell Set-Service 'MSiSCSI' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Volume Shadow Copy Provider
Powershell Set-Service 'swprv' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Offline Files Service
Powershell Set-Service 'CscService' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Secure Socket Tunneling Protocol
Powershell Set-Service 'SstpSvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Windows Security Center
Powershell Set-Service 'wscsvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	SSDP Service Discovery
Powershell Set-Service 'SSDPSRV' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Superfetch
Powershell Set-Service 'SysMain' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Tablet Input Service
Powershell Set-Service 'TabletInputService' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Themes
Powershell Set-Service 'Themes' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	UPNP
Powershell Set-Service 'upnphost' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Volume Shadow Service
Powershell Set-Service 'VSS' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Windows Backup Service
Powershell Set-Service 'SDRSVC' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Windows Defender
Powershell Set-Service 'WinDefend' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Windows Error Reporting
Powershell Set-Service 'WerSvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Windows Firewall
Powershell Set-Service 'MpsSvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

rem this should not exist since the component is removed ealier
rem echo 	Windows Media Center Receiver
rem Powershell Set-Service 'ehRecvr' -startuptype "disabled" >>OptimizeVM.log 2>&1

rem this should not exist since the component is removed ealier
rem echo 	Windows Media Center Scheduler
rem Powershell Set-Service 'ehSched' -startuptype "disabled" >>OptimizeVM.log 2>&1

rem this should not exist since the component is removed ealier
rem echo 	Windows Search Service
rem Powershell Set-Service 'WSearch' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Windows Update Service
Powershell Set-Service 'wuauserv' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	WLAN AutoConfiguration Service
Powershell Set-Service 'Wlansvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Windows Mobile Broadband Service
Powershell Set-Service 'WwanSvc' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo 	Interactive Services Detection
Powershell Set-Service 'UI0Detect' -startuptype "disabled" >>OptimizeVM.log 2>&1

echo Disabling Graphical Boot Screen
bcdedit /set BOOTUX disabled >>OptimizeVM.log 2>&1

echo Deleting all Volume Shadow Copies
vssadmin delete shadows /All /Quiet >>OptimizeVM.log 2>&1

echo Disabling System Restore on C:
Powershell disable-computerrestore -drive c:\ >>OptimizeVM.log 2>&1

echo Disabling Firewall
netsh advfirewall set allprofiles state off >>OptimizeVM.log 2>&1

echo Disabling Hibernation
powercfg -H OFF >>OptimizeVM.log 2>&1

echo Stopping Superfetch
net stop "sysmain" >>OptimizeVM.log 2>&1

echo Removing Scheduled Tasks

echo 	Disk Defragmenting
schtasks /change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable >>OptimizeVM.log 2>&1

echo 	System Restore
schtasks /change /TN "\Microsoft\Windows\SystemRestore\SR" /Disable >>OptimizeVM.log 2>&1

echo 	Registry Backup
schtasks /change /TN "\Microsoft\Windows\Registry\RegIdleBackup" /Disable >>OptimizeVM.log 2>&1

rem Should be removed via components removal
rem echo 	Security Essentials Idle Scanning
rem schtasks /change /TN "\Microsoft\Windows Defender\MPIdleTask" /Disable >>OptimizeVM.log 2>&1

echo 	Security Essentials Scheduled Scan
schtasks /change /TN "\Microsoft\Windows Defender\MP Scheduled Scan" /Disable >>OptimizeVM.log 2>&1

echo 	Windows System Assesment
schtasks /change /TN "\Microsoft\Windows\Maintenance\WinSAT" /Disable >>OptimizeVM.log 2>&1

echo Changing Explorer Preferences
reg load "hku\temp" "%USERPROFILE%\..\Default User\NTUSER.DAT" >>OptimizeVM.log 2>&1

echo 	Show Hidden Files
reg ADD "hku\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 0x1 /f >>OptimizeVM.log 2>&1

echo 	Show File Extension
reg ADD "hku\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1

echo 	Show Drives With No Media
reg ADD "hku\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideDrivesWithNoMedia /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1

echo 	Disable Simple Sharing
reg ADD "hku\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SharingWizardOn /t REG_DWORD /d 0x0 /f >>OptimizeVM.log 2>&1
reg unload "hku\temp" >>OptimizeVM.log 2>&1

