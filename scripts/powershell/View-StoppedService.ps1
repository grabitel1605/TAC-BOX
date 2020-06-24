#Basic script to view stopped services on a system
$credential = Get-Credential
$ComputerName = Read-host 'Enter name of host'

$StoppedService = get-service -ComputerName $ComputerName | Where-Object -Property Status -eq 'Stopped'  

Write-Output $StoppedService
