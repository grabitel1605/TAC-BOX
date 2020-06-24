$ComputerName = Read-Host "Enter Computer Name"
Get-CimInstance -Class Win32_OperatingSystem -ComputerName $ComputerName | 
    Select-Object -Property CSName,LastBootUpTime 