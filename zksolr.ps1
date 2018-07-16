
param (
    [string]$blobStorageKey,
    [string]$blobStorageName,
    [string]$containerName = 'files',
    [int]$vmId,
    [int]$howManyNodes = 3,
    [string]$zkVersion = 'zookeeper-3.4.12',
    [string]$solrVersion = 'solr-6.6.2',
    [int]$tickTime = 2000,
    [string]$dataDirDrive = 'S:',
    [int]$clientPort = 2181, 
    [int]$initLimit = 5,
    [int]$syncLimit = 2,
    [string]$javaSourceURI = 'http://download.oracle.com/otn-pub/java/jdk/8u172-b11/a58eab1ec242421181065cdc37240b08/jre-8u172-windows-x64.exe',
    [int]$solrPort = 8984,
    [string]$zkNameForSvc = 'ZooKeeper',
    [string]$solrNameForSvc = 'solr'
)

add-windowsfeature telnet-client
# Check if PowerShellGEt is Installed
Get-Module PowerShellGet -list | Select-Object Name, Version, Path

# Install the NuGet modules from the PowerShell Gallery
if (Get-Module -ListAvailable -Name NuGet) {
    Write-Output "NuGet Module exists"
}
else {
    Write-Output "NuGet Module does not exist, installing.."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

# Install the Azure Resource Manager modules from the PowerShell Gallery
if (Get-Module -ListAvailable -Name AzureRM) {
    Write-Output "AzureRM Module exists"
}
else {
    Write-Output "AzureRM Module does not exist, installing.."
    Install-Module AzureRM -Force
    Import-Module AzureRM -Force
}

if (Get-Module -ListAvailable -Name SitecoreInstallFramework) {
    Write-Output "SitecoreInstallFramework Module exists"
}
else {
    Write-Output "SIF Module does not exist, installing.."
    Register-PSRepository -Name SitecoreGallery -SourceLocation 'https://sitecore.myget.org/F/sc-powershell/api/v2'
    Install-Module SitecoreInstallFramework -Force
}


Function DeGZip-File {
    Param(
        $infile
    )
    $outFile = $infile.Substring(0, $infile.LastIndexOfAny('.'))
    $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)

    $buffer = New-Object byte[](1024)
    while ($true) {
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0) {break}
        $output.Write($buffer, 0, $read)
    }

    $gzipStream.Close()
    $output.Close()
    $input.Close()
}

Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
#$7zip = 'https://www.7-zip.org/a/7z1805-x64.exe'
$7zip = 'https://www.7-zip.org/a/7z1805-x64.msi'
$nssm = 'https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip'
$zk3_4_10 = 'https://supergsego.com/apache/zookeeper/zookeeper-3.4.10/zookeeper-3.4.10.tar.gz'
$zk3_4_12 = 'http://mirrors.sonic.net/apache/zookeeper/current/zookeeper-3.4.12.tar.gz'
$zk3_5_4beta = 'http://mirrors.sonic.net/apache/zookeeper/zookeeper-3.5.4-beta/zookeeper-3.5.4-beta.tar.gz'
$solr7_3_1 = 'http://archive.apache.org/dist/lucene/solr/7.3.1/solr-7.3.1.zip'
$solr6_6_2 = 'http://archive.apache.org/dist/lucene/solr/6.6.2/solr-6.6.2.zip'

$disk = Get-Disk | Where-Object partitionstyle -eq 'raw' | Sort-Object number
$disk | 
    Initialize-Disk -PartitionStyle MBR -PassThru |
    New-Partition -UseMaximumSize -DriveLetter S |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false -Force


if (!(Test-Path "$dataDirDrive\downloads")) {
    New-Item -Path "$dataDirDrive\downloads" -ItemType Directory -Force
}

    
$javaDestination = "$dataDirDrive\downloads\$($javaSourceURI.Split('/')[-1])"
$client = new-object System.Net.WebClient 
$cookie = "oraclelicense=accept-securebackup-cookie"
$client.Headers.Add([System.Net.HttpRequestHeader]::Cookie, $cookie) 
if (!(Test-Path "$dataDirDrive\downloads\$($javaSourceURI.Split('/')[-1])")) {
    Write-Output "Downloading $javasourceURI"
    $client.downloadFile($javaSourceURI, $javaDestination)  
}
if (!(Test-Path "$dataDirDrive\downloads\$($nssm.Split("/")[-1])")) {
    Write-Output "downloading $nssm"
    Invoke-WebRequest -Uri $nssm -OutFile "$dataDirDrive\downloads\$($nssm.Split("/")[-1])"   
}
if (!(Test-Path "$dataDirDrive\downloads\$($7zip.Split("/")[-1])")) {
    Write-Output "downloading $7zip"
    Invoke-WebRequest -Uri $7zip -OutFile "$dataDirDrive\downloads\$($7zip.Split("/")[-1])"   
}
if (!(Test-Path "$dataDirDrive\downloads\$($zk3_4_10.Split("/")[-1])")) {
    Write-Output "downloading $zk3_4_10"
    Invoke-WebRequest -Uri $zk3_4_10 -OutFile "$dataDirDrive\downloads\$($zk3_4_10.Split("/")[-1])"
}
if (!(Test-Path "$dataDirDrive\downloads\$($zk3_4_12.Split("/")[-1])")) {
    Write-Output "downloading $zk3_4_12"
    Invoke-WebRequest -Uri $zk3_4_12 -OutFile "$dataDirDrive\downloads\$($zk3_4_12.Split("/")[-1])"
}
if (!(Test-Path "$dataDirDrive\downloads\$($zk3_5_4beta.Split("/")[-1])")) {
    Write-Output "downloading $zk3_5_4beta"
    Invoke-WebRequest -Uri $zk3_5_4beta -OutFile "$dataDirDrive\downloads\$($zk3_5_4beta.Split("/")[-1])"
}
if (!(Test-Path "$dataDirDrive\downloads\$($solr7_3_1.Split("/")[-1])")) {
    Write-Output "downloading $solr7_3_1"
    Invoke-WebRequest -Uri $solr7_3_1 -OutFile "$dataDirDrive\downloads\$($solr7_3_1.Split("/")[-1])"
}
if (!(Test-Path "$dataDirDrive\downloads\$($solr6_6_2.Split("/")[-1])")) {
    Write-Output "downloading $solr6_6_2"
    Invoke-WebRequest -Uri $solr6_6_2 -OutFile "$dataDirDrive\downloads\$($solr6_6_2.Split("/")[-1])"
}

$7zipFilePath = "$dataDirDrive\downloads\$($7zip.Split("/")[-1])"
$FLAGS = "/qn /l $dataDirDrive\downloads\7zipInstallLog.log"
Start-Process  -FilePath "$7zipFilePath" $FLAGS -Wait -PassThru

DeGZip-File "$dataDirDrive\downloads\$($zk3_4_10.Split("/")[-1])"
DeGZip-File "$dataDirDrive\downloads\$($zk3_4_12.Split("/")[-1])"
DeGZip-File "$dataDirDrive\downloads\$($zk3_5_4beta.Split("/")[-1])"

if (-not (test-path "$env:ProgramFiles\7-Zip\7z.exe")) {throw "$env:ProgramFiles\7-Zip\7z.exe needed"} 
set-alias untar "$env:ProgramFiles\7-Zip\7z.exe" 

$zk = $zk3_4_10.Split("/")[-1].Replace('.gz', '')
untar x "$dataDirDrive\downloads\$zk" -o"$dataDirDrive\downloads\"

$zk = $zk3_4_12.Split("/")[-1].Replace('.gz', '')
untar x "$dataDirDrive\downloads\$zk" -o"$dataDirDrive\downloads\"

$zk = $zk3_5_4beta.Split("/")[-1].Replace('.gz', '')
untar x "$dataDirDrive\downloads\$zk" -o"$dataDirDrive\downloads\"

$solr7_3_1_base = $solr7_3_1.Split("/")[-1].Replace('.zip', '')
$solr6_6_2_base = $solr6_6_2.Split("/")[-1].Replace('.zip', '')
Expand-Archive -Path "$dataDirDrive\downloads\$($solr7_3_1.Split("/")[-1])" -DestinationPath "$dataDirDrive\downloads\" 
Expand-Archive -Path "$dataDirDrive\downloads\$($solr6_6_2.Split("/")[-1])" -DestinationPath "$dataDirDrive\downloads\" 
Expand-Archive -Path "$dataDirDrive\downloads\$($nssm.Split("/")[-1])" -DestinationPath "$dataDirDrive\downloads"
   
$nssm_base = "$dataDirDrive\downloads\$($nssm.Split("/")[-1])".Replace('.zip', '')
Copy-Item -Path $nssm_base -Destination "S:\" -Recurse
    
Start-Process "$dataDirDrive\downloads\jre-8u172-windows-x64.exe" `
    -ArgumentList 'INSTALL_SILENT=Enable REBOOT=Disable SPONSORS=Disable AUTO_UPDATE=Disable'  `
    -Wait -PassThru

Copy-Item "$dataDirDrive\downloads\$zkVersion" -Recurse -Destination "$dataDirDrive\"
"tickTime=$tickTime" | Out-File -Encoding utf8 "$dataDirDrive\$zkVersion\conf\zoo.cfg" -Append 
"dataDir=$dataDirDrive/$zkVersion/data" | Out-File -Encoding utf8 "$dataDirDrive\$zkVersion\conf\zoo.cfg" -Append
"clientPort=$clientPort" | Out-File -Encoding utf8 "$dataDirDrive\$zkVersion\conf\zoo.cfg" -Append
"initLimit=$initLimit" | Out-File -Encoding utf8 "$dataDirDrive\$zkVersion\conf\zoo.cfg" -Append
"syncLimit=$syncLimit" | Out-File -Encoding utf8 "$dataDirDrive\$zkVersion\conf\zoo.cfg" -Append
#todo: launch in new process
[Environment]::SetEnvironmentVariable("ZOOKEEPER_HOME", "$dataDirDrive\$zkVersion", "Machine")
[Environment]::SetEnvironmentVariable("JAVA_HOME", '"C:\Program Files\Java\jre1.8.0_172"', "Machine")
$oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
setx /M PATH "$oldpath;%ZOOKEEPER_HOME%\bin;"

#configure cluster ip's in config file
$hostname = $env:COMPUTERNAME
$hostname = $hostname -replace '[^a-zA-Z-]', '' #remove integers from hostname
$i = 1
while ($i -le $howManyNodes) { 
    #need better solution around IP'ing for the config file. We can depend on Azure dhcp for hostnames, but this solution will only work in Azure
    #"server.$i=10.0.0.$(($i+3)):2888:3888" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append
    "server.$i=$($hostname)$($i):2888:3888" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append

    $i = $i + 1
}

New-Item "S:\$zkVersion\data" -ItemType Directory

#$vmId | Out-File -Encoding utf8 "S:\$zkVersion\data\myid"
[IO.File]::WriteAllLines("S:\$zkVersion\data\myid", $vmid)

$nssm = "$dataDirDrive\nssm-2.24-101-g897c7ad\win64\nssm.exe"
$ScriptPath = "$dataDirDrive\$zkVersion\bin\zkserver.cmd"


Start-Process -FilePath $nssm -ArgumentList "install $zkNameForSvc $ScriptPath" -NoNewWindow -Wait
Start-Sleep -Seconds 2

If (Get-Service $zkNameForSvc -ErrorAction SilentlyContinue) {
    Write-Output "$zkNameForSvc Found!"
}
Else {
    Write-Output "$zkNameForSvc service not found!"
}

#install SOLR
Copy-Item -Path "$dataDirDrive\downloads\$solr6_6_2_base" -Destination "$dataDirDrive\" -Recurse

#build out solr cloud cmd line
$solrSvrArray = @()
$solrSvrArrayCert = @()
$hostname = $env:COMPUTERNAME
$hostname = $hostname -replace '[^a-zA-Z-]', '' #remove integers from hostname
$i = 1
while ($i -le $howManyNodes) { 
    $solrSvrArray += "$($hostname)$($i):2181"
    $i = $i + 1
}
$i = 1
while ($i -le $howManyNodes) { 
    $solrSvrArrayCert += "$($hostname)$($i)"
    $i = $i + 1
}
$solrSvrArray += 'solrCloud'
$solrSvrArrayCsv = $solrSvrArray -join ','
#ssl setup
if ($vmId -eq 1) {
    $zkcli = "$dataDirDrive\$solrVersion\server\scripts\cloud-scripts\zkcli.bat"
    &"$zkcli"  -cmd clusterprop -name urlScheme -val https -zkhost "$($env:computername):2181"

    $existingCert = Get-ChildItem Cert:\LocalMachine\Root | where-object FriendlyName -eq 'solrcloud'
    if (!($existingCert)) {
        Write-Output 'Creating & trusting an new SSL Cert for solrCloud'
 
        # Create SAN Cert
        $cert = New-SelfSignedCertificate  -FriendlyName 'solrCloud' -DnsName $solrSvrArrayCert -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(10) -Subject 'solrCloud'
        #$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -eq 'solrCloud'
     
        # Export Server Root Certificates
        # Check if C:\Certificates\Export\$buildName exists, and if not, create it
        if (!(Test-Path 'C:\Certificates\Export\')) {
            New-Item -ItemType Directory -Path 'C:\Certificates\Export\'
            Write-Output 'C:\Certificates\Export\'
        }
        # Create keystore file
        if (!(Test-Path -Path "$dataDirDrive\$solrVersion\server\etc\solr-ssl.keystore.pfx")) {
            Write-Host "Exporting cert for Solr to use"
 
            $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -eq 'solrCloud'

            $certStore = "$dataDirDrive\$solrVersion\server\etc\solr-ssl.keystore.pfx"
            $certPwd = ConvertTo-SecureString -String "secret" -Force -AsPlainText
            $cert | Export-PfxCertificate -FilePath $certStore -Password $certpwd | Out-Null
        }
 
        if (!(Test-Path -Path "$dataDirDrive\$solrVersion\bin\solr.in.cmd.old")) {
            Write-Host "Rewriting solr config"
            $cfg = Get-Content "$dataDirDrive\$solrVersion\bin\solr.in.cmd"
            Rename-Item "$dataDirDrive\$solrVersion\bin\solr.in.cmd" "$dataDirDrive\$solrVersion\bin\solr.in.cmd.old"
            $newCfg = $cfg | % { $_ -replace "REM set SOLR_SSL_KEY_STORE=etc/solr-ssl.keystore.jks", "set SOLR_SSL_KEY_STORE=$certStore" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_KEY_STORE_PASSWORD=secret", "set SOLR_SSL_KEY_STORE_PASSWORD=secret" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_TRUST_STORE=etc/solr-ssl.keystore.jks", "set SOLR_SSL_TRUST_STORE=$certStore" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_TRUST_STORE_PASSWORD=secret", "set SOLR_SSL_TRUST_STORE_PASSWORD=secret" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_HOST=192.168.1.1", "set SOLR_HOST=$env:COMPUTERNAME" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_TRUST_STORE_TYPE=JKS", "set SOLR_SSL_TRUST_STORE_TYPE=PKCS12" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_KEY_STORE_TYPE=JKS", "set SOLR_SSL_KEY_STORE_TYPE=PKCS12" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_NEED_CLIENT_AUTH=false", "set SOLR_SSL_NEED_CLIENT_AUTH=false" }
            $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_WANT_CLIENT_AUTH=false", "set SOLR_SSL_WANT_CLIENT_AUTH=false" }
            $newCfg | Set-Content "$dataDirDrive\$solrVersion\bin\solr.in.cmd" 
        }
        # Solr SAN Cert Export
        #$localFileDirectory = "C:\Certificates\Export\"
        #$containerName = "certificates"
        $serverRootCertName = 'solrCloud'
        $serverRootCertExportFile = "SolrCert.cer"

        $certificateSubject = $serverRootCertName
        $thumbprint = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=$certificateSubject"}).Thumbprint;
        Write-Host -Object "My thumbprint is: $thumbprint";

        $path = 'Cert:\LocalMachine\My\' + $thumbprint 
        Export-Certificate -cert $path -FilePath C:\Certificates\Export\$serverRootCertExportFile

        # Export Certificate Store
        Copy-Item -Path "$dataDirDrive\$solrVersion\server\etc\solr-ssl.keystore.pfx" -Destination "C:\Certificates\Export\solr-ssl.keystore.pfx"
        #import cert into trusted stor for browser 
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\Certificates\Export\SolrCert.cer")
        $rootStore = Get-Item cert:\LocalMachine\Root
        $rootStore.Open("ReadWrite")
        $rootStore.Add($cert)
        $rootStore.Close()

        # remove the untrusted copy of the cert
        $cert | Remove-Item
    }
    # Change Log File Size to 100MB from 4MB
    $filePath = "$dataDirDrive\$solrVersion\server\resources\log4j.properties"

    $find = 'log4j.appender.file.MaxFileSize=4MB'
    $replace = 'log4j.appender.file.MaxFileSize=100MB'

    (Get-Content $filePath).replace($find, $replace) | Set-Content $filePath

    # Connect to Storage Account and Set Context
    $ctx = New-AzureStorageContext -StorageAccountName $blobStorageName -StorageAccountKey $blobStorageKey
    New-AzureStorageContainer -Context $ctx -Name $containerName
    $files = Get-ChildItem 'C:\Certificates\Export'

    foreach ($file in $files) {
        $fqName = $file.FullName 
        Set-AzureStorageBlobContent -Blob $file.Name -Container $containerName -File $fqName -Context $ctx -Force
    }

    Copy-Item -Path "$dataDirDrive\$solrVersion\server\solr\configsets\basic_configs" -Destination "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs" -Recurse
    #swap out id for _uniqueid
    if (!(Test-Path -Path "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema.old")) {
        $newCfg = Get-Content "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema"
        Rename-Item "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema" "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema.old"
        $newCfg = $newCfg | % { $_ -replace "<uniqueKey>id</uniqueKey>", "<uniqueKey>_uniqueid</uniqueKey>" }
        $newCfg | Set-Content "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema" -Encoding UTF8
    }
    #insert new fieldname
    $Match = [regex]::Escape('<field name="_text_" type="text_general" indexed="true" stored="false" multiValued="true"/>')
    $NewLine = '<field name="_uniqueid" type="string" indexed="true" required="true" stored="true"/>'
    $Content = Get-Content S:\solr-6.6.2\server\solr\configsets\sitecore_configs\conf\managed-schema
    $Index = ($content | Select-String -Pattern $Match).LineNumber + 1
    $NewContent = @()
    0..($Content.Count - 1) | Foreach-Object {
        if ($_ -eq $index) {
            $NewContent += $NewLine
        }
        $NewContent += $Content[$_]
    }
    $NewContent | Out-File "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema" -Encoding utf8


}
else {
    if (!(Test-Path 'C:\Certificates\Export\')) {
        New-Item -ItemType Directory -Path 'C:\Certificates\Export\'
        Write-Output 'C:\Certificates\Export\'
    }
    $ctx = New-AzureStorageContext -StorageAccountName $blobStorageName -StorageAccountKey $blobStorageKey

    $blobs = Get-AzureStorageBlob -Container $containerName -Context $ctx
    foreach ($blob in $blobs) { 
        Get-AzureStorageBlobContent `
            -Container $containerName  -Blob $blob.Name -Destination 'C:\Certificates\Export\' `
            -Context $ctx  
    }
    # Install Server Root Certs
    $serverRootCertName = "SolrCert.cer"
    Import-Certificate -FilePath "C:\Certificates\Export\$serverRootCertName" -CertStoreLocation Cert:\LocalMachine\Root

    # Import Certificate Store
    $certStoreFile = "solr-ssl.keystore.pfx"
    Copy-Item -Path "C:\Certificates\Export\$certStoreFile" -Destination "$dataDirDrive\$solrVersion\server\etc\solr-ssl.keystore.pfx"
    
    $certStore = "$dataDirDrive\$solrVersion\server\etc\solr-ssl.keystore.pfx"
    if (!(Test-Path -Path "$dataDirDrive\$solrVersion\bin\solr.in.cmd.old")) {
        Write-Host "Rewriting solr config"
        $certStore = "$dataDirDrive\$solrVersion\server\etc\solr-ssl.keystore.pfx"
        $cfg = Get-Content "$dataDirDrive\$solrVersion\bin\solr.in.cmd"
        Rename-Item "$dataDirDrive\$solrVersion\bin\solr.in.cmd" "$dataDirDrive\$solrVersion\bin\solr.in.cmd.old"
        $newCfg = $cfg | % { $_ -replace "REM set SOLR_SSL_KEY_STORE=etc/solr-ssl.keystore.jks", "set SOLR_SSL_KEY_STORE=$certStore" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_KEY_STORE_PASSWORD=secret", "set SOLR_SSL_KEY_STORE_PASSWORD=secret" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_TRUST_STORE=etc/solr-ssl.keystore.jks", "set SOLR_SSL_TRUST_STORE=$certStore" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_TRUST_STORE_PASSWORD=secret", "set SOLR_SSL_TRUST_STORE_PASSWORD=secret" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_HOST=192.168.1.1", "set SOLR_HOST=$env:COMPUTERNAME" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_TRUST_STORE_TYPE=JKS", "set SOLR_SSL_TRUST_STORE_TYPE=PKCS12" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_KEY_STORE_TYPE=JKS", "set SOLR_SSL_KEY_STORE_TYPE=PKCS12" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_NEED_CLIENT_AUTH=false", "set SOLR_SSL_NEED_CLIENT_AUTH=false" }
        $newCfg = $newCfg | % { $_ -replace "REM set SOLR_SSL_WANT_CLIENT_AUTH=false", "set SOLR_SSL_WANT_CLIENT_AUTH=false" }
        $newCfg | Set-Content "$dataDirDrive\$solrVersion\bin\solr.in.cmd" 
    }
    # Change Log File Size to 100MB from 4MB
    $filePath = "$dataDirDrive\$solrVersion\server\resources\log4j.properties"

    $find = 'log4j.appender.file.MaxFileSize=4MB'
    $replace = 'log4j.appender.file.MaxFileSize=100MB'

    (Get-Content $filePath).replace($find, $replace) | Set-Content $filePath

    Copy-Item -Path "$dataDirDrive\$solrVersion\server\solr\configsets\basic_configs" -Destination "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs" -Recurse
    #swap out id for _uniqueid
    if (!(Test-Path -Path "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema.old")) {
        $newCfg = Get-Content "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema"
        Rename-Item "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema" "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema.old"
        $newCfg = $newCfg | % { $_ -replace "<uniqueKey>id</uniqueKey>", "<uniqueKey>_uniqueid</uniqueKey>" }
        $newCfg | Set-Content "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema" -Encoding UTF8
    }
    #insert new fieldname
    $Match = [regex]::Escape('<field name="_text_" type="text_general" indexed="true" stored="false" multiValued="true"/>')
    $NewLine = '<field name="_uniqueid" type="string" indexed="true" required="true" stored="true"/>'
    $Content = Get-Content S:\solr-6.6.2\server\solr\configsets\sitecore_configs\conf\managed-schema
    $Index = ($content | Select-String -Pattern $Match).LineNumber + 1
    $NewContent = @()
    0..($Content.Count - 1) | Foreach-Object {
        if ($_ -eq $index) {
            $NewContent += $NewLine
        }
        $NewContent += $Content[$_]
    }
    $NewContent | Out-File "$dataDirDrive\$solrVersion\server\solr\configsets\sitecore_configs\conf\managed-schema" -Encoding utf8

}


$nssm = "$dataDirDrive\nssm-2.24-101-g897c7ad\win64\nssm.exe"
$ScriptPath = "$dataDirDrive\$solrVersion\bin\solr.cmd"
#nssm install solr "S:\solr-7.3.1\bin\solr.cmd" "start -cloud -p 8983 -z """zks1:2181, zks2:2181, zks3:2181""""
#Start-Process -FilePath $nssm -ArgumentList "install solr $ScriptPath start -cloud -p $solrPort -z """$solrSvrArray"""" -NoNewWindow -Wait
#Start-Process -FilePath $nssm -ArgumentList "install solr $ScriptPath start -cloud -p $solrPort -z """$solrSvrArray"""" -NoNewWindow -Wait
#need to get start-process working for -wait
&"$nssm" install solr $ScriptPath "start -cloud -p $solrPort -z """$solrSvrArrayCsv""" -f"  
"start -cloud -p 8983 -z (servername):2181 -noprompt"
#Start-Sleep -Seconds 2
&"$nssm" set solr Start SERVICE_DEMAND_START
Start-Sleep -Seconds 2

If (Get-Service $solrNameForSvc -ErrorAction SilentlyContinue) {
    Write-Output "$solrNameForSvc Found!"
}
Else {
    Write-Output "$solrNameForSvc service not found!"
}

Restart-Computer -Force
