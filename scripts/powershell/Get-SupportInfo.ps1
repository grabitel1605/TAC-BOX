<#
.Synopsis
    This is a script to gather information for Help Desk support calls

.Description
    This is a basic script designed to gather user and computer information for helpdesk support calls.
    Information gathered includes:
    DNS Name a& IP Address
    DNS Server
    Name of OPerating System
    Amount of Memory in target computer
    Amount of free space on disk
    Last Reboot of the System

.Example
    Get-Support
    PS C:\scripts> .Get-SupportInfo.ps1

    cmdlet get-helpdesksupportdata.ps1 at command pipeline position 1
    SupplyValues for the following parameters:
    ComputerName: $ComputerName
    Username: username

    In this example, the script is simply run and the parameters are input as they are mandatory.

.Example
    Get-SupportInfo.ps1 -ComputerNamer Laptop-01 -Username  admin

    This example has mandatory parameters input when calling script.

.Example
    Get-SupportInfo.ps1 -ComputerName Laptop-01 -Username admin | out-file C:\UserInfo.txt
#>

###################################################################
#Script Name	:Get-SupportInfo.ps1                                                                                      
#Author       	:                                                
#Email         	:                                           
###################################################################

##Parameters for ComputerName & UserName
param(
[Parameter(Mandatory=$true)][string]$ComputerName
)

#Variables
    $credential = Get-Credential
    $CimSession = New-CimSession -ComputerName -Credential $credential
    $Analyst = $credential.UserName

#OS Description
    $OS=(Get-CimInstance Win32_OperatingSystem -ComputerName $computername).Caption
    $OS

#Disk Freespace on OS Drive
    $drive = Get-CimInstance -class win32_logicaldisk | Where-Object DeviceID -eq 'C:'
    $Freespace =(($drive.Freespace)/1gb)
    $drive
    $Freespace

#Amount of System Memory
    $MemoryInGB = ((((Get-CimInstance Win32_PhysicalMemory -ComputerName $computername).Capacity|measure -Sum).Sum)/1gb)
     $MemoryInGB

#Last Reboot of System
    $LastReboot = (Get-CIMInstance -Class Win32_OperatingSystem -ComputerName $computername).LastBootUpTime
     $LastReboot

#IP Address & DNS Name
    $DNS = Resolve-DnsName -Name $computername | Where-Object Type -eq "A"
    $DNSName = $DNS.Name
    $DNSIP = $DNS.IPaddress
    $DNS
    $DNSName
    $DNSIP

#DNS Server of Target
    $CimSession = New-CimSession -ComputerName $computername -Credential (Get-Credential)
    (Get-DnsClientServerAddress -CimSession $CimSession -InterfaceAlias "ethernet" -AddressFamily IPv4).ServerAddresses

#Write Output to Screen
#Clear-Host
Write-Output "Help Desk Support Information for $computername"
Write-Output "-----------------------------------------------"
Write-Output "Support Analyst: $Analyst";""
Write-Output "ComputerNamer: $computername";""
Write-Output "Last System Reboot of $computername : $LastReboot ";""
Write-Output "DNS Name of $computername :$DNSName";""
Write-Output "IP Address of $DNSName : DNSIP";""
Write-Output "DNS Server(s) for $computername : $DNSServer";""
Write-Output "Total System RAM in $somputername : $MemoryInGB GB";""
Write-Output "Freespace on C: $Freespace GB";""
Write-Output "Version of Operating System: $OS"