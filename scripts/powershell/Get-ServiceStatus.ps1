#Get-ServiceStatus.ps1 - Script displays the status of services running on a specified machine.

#Creates a mandatory paramater for ComputerName and for Service Status

Param(
    [Parameter(Mandatory=$true)]
    [string[]]                      #Additional[] after string denotes this parameter accepts multiple inputs
    $ComputerName                   #Note this is the same name as the variable used in your code below
)

#Creates a variable for Get-Service Objects
#As it can hold multiple objects, referred to as an array
$Services = Get-Service -ComputerName $Computername     #

#Use foreach construct to perform actions on each object in $Services
foreach($Service in $Services){

    #Create variable containing status and displayname using member enumeration
    $ServiceStatus = $Service.Status         # decimal notating the variable allows access to properties for each object

    $ServiceDisplayName = $Service.DisplayName

    #Use if-else construct for decision making

    if($ServiceStatus -eq 'Running'){
        Write-Output "Service OK - Status of $ServiceDisplayname is $ServiceStatus"
    }
    Else{
        Write-Output "Check Service - Status of $ServiceDisplayname is $ServiceStatus"
    }
}