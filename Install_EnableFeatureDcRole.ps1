# Install the packages required
2
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
3
Install-Module Az.Storage -Force
4
5
# Storage account name and Container name

$StorageAccountName = "releasenotesmariapps "

$ContainerName = "customscriptextensions"

# Give the connection string.

$ConnectionString = "DefaultEndpointsProtocol=https;AccountName=releasenotesmariapps;AccountKey=Tab1n8KfHCRsApcj2FEI4u5aDViIx5Q9lDOYxRtk2CUicpQvgmWxGUs9QxCtM99mJj80AXkdEVul5R9CgAG24A==;EndpointSuffix=core.windows.net"

$Ctx = New-AzStorageContext -ConnectionString $ConnectionString

#Download File

$FileName1 = "bulk_users1.csv"

#Destination Path

$localTargetDirectory = "C:\Users\"


#Download Blob to the Destination Path

#installing ADDS

$PlainPassword = "KV2waysPzQNmZ3Z"
$SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force

Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools  
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-SafeModeAdministratorPassword $SecurePassword `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName "mappsazure.com" `
-DomainNetbiosName "MAPPSAZURE" `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true

#Create USERS & OU'S

Get-AzStorageBlobContent -Blob $FileName1 -Container $ContainerName -Destination $localTargetDirectory -Context $ctx

### Creating Organisational Unit ###
New-ADOrganizationalUnit -Name "Mariapps-RDP" -Path "DC=mappsazure,DC=com" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Mariapps-MIGR" -Path "DC=mappsazure,DC=com" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Mariapps-ADMIN" -Path "DC=mappsazure,DC=com" -ProtectedFromAccidentalDeletion $False
New-ADOrganizationalUnit -Name "Service-Accounts" -Path "DC=mappsazure,DC=com" -ProtectedFromAccidentalDeletion $False
NEW-ADGroup –name "Mariapps-RDP" –groupscope Global –path "OU=Mariapps-RDP,DC=MAPPSAZURE,DC=com"
NEW-ADGroup –name "Mariapps-ADMIN" –groupscope Global –path "OU=Mariapps-ADMIN,DC=MAPPSAZURE,DC=com"
NEW-ADGroup –name "Mariapps-MIGR" –groupscope Global –path "OU=Mariapps-MIGR,DC=MAPPSAZURE,DC=com"

### Creating Security Groups ###
NEW-ADGroup –name "Group-Svc" –groupscope Global –path "OU=Service-Accounts,DC=mappsazure,DC=com"
NEW-ADGroup –name "Group-MSSQL-Svc" –groupscope Global –path "OU=Service-Accounts,DC=mappsazure,DC=com"
NEW-ADGroup –name "Group-Utils-Svc" –groupscope Global –path "OU=Service-Accounts,DC=mappsazure,DC=com"

### Creating Service Accounts ###
$PlainPassword = "kK0eDw+hDHY7BRwYhQQaXg=="
$SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
Import-module ActiveDirectory
New-ADUser -Name "Web App Pool & DB User" -GivenName "Web App Pool" -Surname "& DB User" -SamAccountName "iis-db-admin" -UserPrincipalName "iis-db-admin@mappsazure.com" -Path "OU=Service-Accounts,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true
New-ADUser -Name "TFS Admin" -GivenName "TFS " -Surname "Admin" -SamAccountName "tfsadmin" -UserPrincipalName "tfsadmin@mappsazure.com" -Path "OU=Service-Accounts,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true
New-ADUser -Name "Schedule Task" -GivenName "Schedule" -Surname "Task" -SamAccountName "schedule-svc" -UserPrincipalName "schedule-svc@mappsazure.com" -Path "OU=Service-Accounts,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true
New-ADUser -Name "MSSQL-SVC" -GivenName "MSSQL" -Surname "-SVC" -SamAccountName "mssql-svc" -UserPrincipalName "mssql-svc@mappsazure.com" -Path "OU=Service-Accounts,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true
New-ADUser -Name "SQL AGENT-SVC" -GivenName "SQL AGENT" -Surname "-SVC" -SamAccountName "sqlagent-svc" -UserPrincipalName "sqlagent-svc@mappsazure.com" -Path "OU=Service-Accounts,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true
New-ADUser -Name "SQL REPORTING-SVC" -GivenName "SQL REPORTING" -Surname "-SVC" -SamAccountName "ssrs-svc" -UserPrincipalName "ssrs-svc@mappsazure.com" -Path "OU=Service-Accounts,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true
New-ADUser -Name "SQL FULLTEXT-SVC" -GivenName "SQL FULLTEXT" -Surname "-SVC" -SamAccountName "sql-fddl-svc" -UserPrincipalName "sql-fddl-svc@mappsazure.com" -Path "OU=Service-Accounts,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true

### Adding users into group ###
Add-ADGroupMember -Identity Group-Svc -Members iis-db-admin,tfsadmin,schedule-svc
Add-ADGroupMember -Identity Group-MSSQL-Svc -Members mssql-svc,sqlagent-svc,ssrs-svc,sql-fddl-svc
Add-ADGroupMember -Identity Group-Utils-Svc -Members schedule-svc
### Group Permission ###
Add-ADPrincipalGroupMembership -Identity Group-Svc -MemberOf Administrators
Add-ADPrincipalGroupMembership -Identity iis-db-admin -MemberOf IIS_IUSRS
Add-ADPrincipalGroupMembership -Identity Group-Utils-Svc -MemberOf Administrators

### Creating Logon Accounts ###
$PlainPassword = "KV2waysPzQNmZ3Z"
$SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
Import-module ActiveDirectory
New-ADUser -Name "DC-ADMIN" -GivenName "DC" -Surname "ADMIN" -SamAccountName "dc-admin-mapps" -UserPrincipalName "dc-master@mappsazure.com" -Path "OU=Mariapps-ADMIN,DC=mappsazure,DC=com" -AccountPassword $SecurePassword -Enabled $true -CannotChangePassword $true -PasswordNeverExpires $true

### creating com admin users from csv list
# Import active directory module for running AD cmdlets
Import-Module activedirectory
  
#Store the data from ADUsers.csv in the $ADUsers variable
$ADUsers = Import-csv C:\Users\bulk_users1.csv

#Loop through each row containing user details in the CSV file 
foreach ($User in $ADUsers)
{
	#Read user data from each field in each row and assign the data to a variable as below
		
	$Username 	= $User.username
	$Password 	= $User.password
	$Firstname 	= $User.firstname
	$Lastname 	= $User.lastname
	$OU 		= $User.ou #This field refers to the OU the user account is to be created in
    $department = $User.department
    $Password = $User.Password


	#Check to see if the user already exists in AD
	if (Get-ADUser -F {SamAccountName -eq $Username})
	{
		 #If user does exist, give a warning
		 Write-Warning "A user account with username $Username already exist in Active Directory."
	}
	else
	{
		#User does not exist then proceed to create the new user account
		
        #Account will be created in the OU provided by the $OU variable read from the CSV file
		New-ADUser `
            -SamAccountName $Username `
            -UserPrincipalName "$Username@mappsazure.com" `
            -Name "$Firstname $Lastname" `
            -GivenName $Firstname `
            -Surname $Lastname `
            -Enabled $True `
            -DisplayName "$Firstname $Lastname" `
            -Path $OU `
            -Department $department `
            -AccountPassword (convertto-securestring $Password -AsPlainText -Force) -CannotChangePassword $true -PasswordNeverExpires $true
            
	}
}