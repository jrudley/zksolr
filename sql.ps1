Param (
    [Parameter(Mandatory=$true)] [string] $VmAdminUsername,
    [Parameter(Mandatory=$true)] [string] $VmAdminPassword,
    [Parameter(Mandatory=$true)] [string] $SqlLoginUsername,
    [Parameter(Mandatory=$true)] [string] $SqlLoginPassword
)


Install-PackageProvider -Name 'NuGet' -RequiredVersion '2.8.5.201' -Force
Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
Install-Module -Name 'SqlServer' -AllowClobber -Force
 
# This script will be executed by the custom script extension in the SYSTEM user context. We need to talk to
# SQL Server with the VM administrator account, which is the default SQL administrator in the marketplace image.
# This PSCredential will allow us to act as the VM administrator.
$secureVmAdminPassword = ConvertTo-SecureString -String $VmAdminPassword -AsPlainText -Force
$vmAdminCredential = New-Object -TypeName 'PSCredential' -ArgumentList "$env:ComputerName\$VmAdminUsername", $secureVmAdminPassword
 
# Enable mixed mode authentication (service restart required). By default the marketplace image is Windows
# authentication only. We need to do this in the execution context of the VM administrator.

    Invoke-Sqlcmd -ServerInstance 'localhost' -Database 'master'  `
        -Query "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2"
    Restart-Service -Name 'MSSQLServer' -Force
 
    # Add SQL login
    $secureSqlLoginPassword = ConvertTo-SecureString -String $SqlLoginPassword -AsPlainText -Force
    
    $sqlLoginCredential = New-Object -TypeName 'PSCredential' -ArgumentList $SqlLoginUsername, $secureSqlLoginPassword
    $exists = Get-SqlLogin -ServerInstance 'localhost' -LoginName $SqlLoginUsername -ErrorAction SilentlyContinue
    if (!($exists))
    {
    write-output "Adding $sqlLoginUserName to instance"
    Add-SqlLogin -ServerInstance 'localhost' -LoginName $SqlLoginUsername -LoginType 'SqlLogin' -Enable -GrantConnectSql `
        -LoginPSCredential $sqlLoginCredential 
    }


if (!(Test-Path 's:\data')) {
New-Item -ItemType Directory 's:\data'
}

    Invoke-Sqlcmd -ServerInstance 'localhost' -Database 'master'  `
 -Query "EXEC master..sp_addsrvrolemember @loginame = N'$SqlLoginUsername', @rolename = N'sysadmin';EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'DefaultData', REG_SZ, N's:\data'
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'DefaultLog', REG_SZ, N's:\data'
GO" 



