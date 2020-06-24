$ComputerName = Read-Host "Enter Computer Name"
Get-CimInstance -ComputerName $ComputerName -ClassName Win32_OperatingSystem |
    Select-Object CSName LastBootUpTime