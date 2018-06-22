
param (
    [int]$vmId,
    [int]$howManyNodes = 3,
    [string]$zkVersion = 'zookeeper-3.4.12',
    [int]$tickTime = 2000,
    [string]$dataDirDrive = 'S:',
    [int]$clientPort = 2181, 
    [int]$initLimit = 5,
    [int]$syncLimit = 2,
    [string]$javaSourceURI = 'http://download.oracle.com/otn-pub/java/jdk/8u172-b11/a58eab1ec242421181065cdc37240b08/jre-8u172-windows-x64.exe',
    [int]$solrPort = 8983
)
 
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
$solr7_3_1 = 'http://mirrors.advancedhosters.com/apache/lucene/solr/7.3.1/solr-7.3.1.zip'

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
Expand-Archive -Path "$dataDirDrive\downloads\$($solr7_3_1.Split("/")[-1])" -DestinationPath "$dataDirDrive\downloads\" 
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


Start-Process -FilePath $nssm -ArgumentList "install ZooKeeper $ScriptPath" -NoNewWindow -Wait
Start-Sleep -Seconds .5

#install SOLR
Copy-Item -Path $solr7_3_1_base -Destination "$dataDirDrive\" -Recurse

$nssm = "$dataDirDrive\nssm-2.24-101-g897c7ad\win64\nssm.exe"
$ScriptPath = "$dataDirDrive\$solr7_3_1_base\bin\solr.cmd"

#build out solr cloud cmd line
$solrSvrArray = @()
$hostname = $env:COMPUTERNAME
$hostname = $hostname -replace '[^a-zA-Z-]', '' #remove integers from hostname
$i = 1
while ($i -le $howManyNodes) { 
    $solrSvrArray += "$($hostname)$($i):2181"
    $i = $i + 1
}
$solrSvrArray = $solrSvrArray -join ','

Start-Process -FilePath $nssm -ArgumentList "install solr $ScriptPath start -cloud -p $solrPort -z `"$solrSvrArray`"" -NoNewWindow -Wait
Start-Sleep -Seconds .5

Restart-Computer -Force

