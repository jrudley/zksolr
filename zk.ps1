
    param (
        [int]$vmId,
        [int]$howManyNodes,
        [string]$zkVersion = 'zookeeper-3.4.12'   
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

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    #$7zip = 'https://www.7-zip.org/a/7z1805-x64.exe'
    $7zip = 'https://www.7-zip.org/a/7z1805-x64.msi'
    $zk3_4_10 = 'https://supergsego.com/apache/zookeeper/zookeeper-3.4.10/zookeeper-3.4.10.tar.gz'
    $zk3_4_12 = 'http://mirrors.sonic.net/apache/zookeeper/current/zookeeper-3.4.12.tar.gz'
    $zk3_5_4beta = 'http://mirrors.sonic.net/apache/zookeeper/zookeeper-3.5.4-beta/zookeeper-3.5.4-beta.tar.gz'
    #$solr7_3_1 = 'http://mirrors.advancedhosters.com/apache/lucene/solr/7.3.1/solr-7.3.1.zip'

    $disk = Get-Disk | Where-Object partitionstyle -eq 'raw' | Sort-Object number
    $disk | 
        Initialize-Disk -PartitionStyle MBR -PassThru |
        New-Partition -UseMaximumSize -DriveLetter S |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false -Force


    if (!(Test-Path S:\downloads)) {
        New-Item -Path S:\downloads -ItemType Directory -Force
    }

    $javaSource = 'http://download.oracle.com/otn-pub/java/jdk/8u172-b11/a58eab1ec242421181065cdc37240b08/jre-8u172-windows-x64.exe'
    $javaDestination = "S:\downloads\$($javaSource.Split('/')[-1])"
    $client = new-object System.Net.WebClient 
    $cookie = "oraclelicense=accept-securebackup-cookie"
    $client.Headers.Add([System.Net.HttpRequestHeader]::Cookie, $cookie) 
    if (!(Test-Path "S:\downloads\$($javaSource.Split('/')[-1])")) {
        Write-Output "downloading $javaSource"
        $client.downloadFile($javaSource, $javaDestination)  
    }

    if (!(Test-Path "S:\downloads\$($7zip.Split("/")[-1])")) {
        Write-Output "downloading $7zip"
        Invoke-WebRequest -Uri $7zip -OutFile "S:\downloads\$($7zip.Split("/")[-1])"   
    }
    if (!(Test-Path "S:\downloads\$($zk3_4_10.Split("/")[-1])")) {
        Write-Output "downloading $zk3_4_10"
        Invoke-WebRequest -Uri $zk3_4_10 -OutFile "S:\downloads\$($zk3_4_10.Split("/")[-1])"
    }
    if (!(Test-Path "S:\downloads\$($zk3_4_12.Split("/")[-1])")) {
        Write-Output "downloading $zk3_4_12"
        Invoke-WebRequest -Uri $zk3_4_12 -OutFile "S:\downloads\$($zk3_4_12.Split("/")[-1])"
    }
    if (!(Test-Path "S:\downloads\$($zk3_5_4beta.Split("/")[-1])")) {
        Write-Output "downloading $zk3_5_4beta"
        Invoke-WebRequest -Uri $zk3_5_4beta -OutFile "S:\downloads\$($zk3_5_4beta.Split("/")[-1])"
    }
    <#if (!(Test-Path "S:\downloads\$($solr7_3_1.Split("/")[-1])")) {
        Write-Output "downloading $solr7_3_1"
        Invoke-WebRequest -Uri $solr7_3_1 -OutFile "S:\downloads\$($solr7_3_1.Split("/")[-1])"
    }#>
    $7zipFilePath = "S:\downloads\$($7zip.Split("/")[-1])"
    $FLAGS = "/qn /l S:\downloads\7zipInstallLog.log"
    Start-Process  -FilePath "$7zipFilePath" $FLAGS -Wait -PassThru

    DeGZip-File "S:\downloads\$($zk3_4_10.Split("/")[-1])"
    DeGZip-File "S:\downloads\$($zk3_4_12.Split("/")[-1])"
    DeGZip-File "S:\downloads\$($zk3_5_4beta.Split("/")[-1])"

    if (-not (test-path "$env:ProgramFiles\7-Zip\7z.exe")) {throw "$env:ProgramFiles\7-Zip\7z.exe needed"} 
    set-alias untar "$env:ProgramFiles\7-Zip\7z.exe" 

    $zk = $zk3_4_10.Split("/")[-1].Replace('.gz', '')
    untar x S:\downloads\$zk -o"S:\downloads\"

    $zk = $zk3_4_12.Split("/")[-1].Replace('.gz', '')
    untar x S:\downloads\$zk -o"S:\downloads\"

    $zk = $zk3_5_4beta.Split("/")[-1].Replace('.gz', '')
    untar x S:\downloads\$zk -o"S:\downloads\"

    #$solr7_3_1_base = $solr7_3_1.Split("/")[-1].Replace('.zip','')
    #Expand-Archive -Path "S:\downloads\$($solr7_3_1.Split("/")[-1])" -DestinationPath "S:\downloads\" #"S:\downloads\$solr7_3_1_base"
    Start-Process 'S:\downloads\jre-8u172-windows-x64.exe' `
        -ArgumentList 'INSTALL_SILENT=Enable REBOOT=Disable SPONSORS=Disable AUTO_UPDATE=Disable'  `
        -Wait -PassThru

    Copy-Item "S:\downloads\$zkVersion" -Recurse -Destination s:\
    #Copy-Item S:\zookeeper-3.4.12\conf\zoo_sample.cfg -Recurse -Destination S:\zookeeper-3.4.12\conf\zoo.cfg

    #(Get-Content S:\zookeeper-3.4.12\conf\zoo.cfg).replace('dataDir=/tmp/zookeeper', 'dataDir=zookeeper-3.4.12/data') | Set-Content S:\zookeeper-3.4.12\conf\zoo.cfg
    "tickTime=2000" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append 
    "dataDir=s:/zookeeper-3.4.12/data" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append
    "clientPort=2181" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append
    "initLimit=5" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append
    "syncLimit=2" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append
    #todo: launch in new process
    [Environment]::SetEnvironmentVariable("ZOOKEEPER_HOME", "S:\$zkVersion", "Machine")
    [Environment]::SetEnvironmentVariable("JAVA_HOME", '"C:\Program Files\Java\jre1.8.0_172"', "Machine")
    $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
    setx /M PATH "$oldpath;%ZOOKEEPER_HOME%\bin;"
    #[Environment]::SetEnvironmentVariable("ZOOKEEPER_HOME", "S:\$zkVersion", "User")
    #[Environment]::SetEnvironmentVariable("JAVA_HOME", '"C:\Program Files\Java\jre1.8.0_172"', "User")
    #setx PATH "%PATH%;%ZOOKEEPER_HOME%\bin;"
    #configure cluster ip's in config file
    $i = 1
    while ($i -le $howManyNodes) { 
    #need better solution around IP'ing for the config file. We can depend on Azure dhcp for hostnames, but this solution will only work in Azure
    "server.$i=10.0.0.$(($i+3)):2888:3888" | Out-File -Encoding utf8 "S:\$zkVersion\conf\zoo.cfg" -Append
    $i = $i + 1
}

New-Item "S:\$zkVersion\data" -ItemType Directory
#increment by 1 due to copyindex starting at 0
$vmId = $vmId  + 1 
#$vmId | Out-File -Encoding utf8 "S:\$zkVersion\data\myid"
[IO.File]::WriteAllLines("S:\$zkVersion\data\myid",  $vmid)

