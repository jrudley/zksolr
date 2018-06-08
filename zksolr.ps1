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
#$7zip = 'https://www.7-zip.org/a/7z1805-x64.exe'
$7zip = 'https://www.7-zip.org/a/7z1805-x64.msi'
$zk3_4_12 = 'http://mirrors.sonic.net/apache/zookeeper/current/zookeeper-3.4.12.tar.gz'
$zk3_5_4beta = 'http://mirrors.sonic.net/apache/zookeeper/zookeeper-3.5.4-beta/zookeeper-3.5.4-beta.tar.gz'
$solr7_3_1 = 'http://mirrors.advancedhosters.com/apache/lucene/solr/7.3.1/solr-7.3.1.zip'
if (!(Test-Path c:\temp)) {
    New-Item -Path c:\temp -ItemType Directory -Force
}

$javaSource = 'http://download.oracle.com/otn-pub/java/jdk/8u172-b11/a58eab1ec242421181065cdc37240b08/jre-8u172-windows-x64.exe'
$javaDestination = "c:\temp\$($javaSource.Split('/')[-1])"
$client = new-object System.Net.WebClient 
$cookie = "oraclelicense=accept-securebackup-cookie"
$client.Headers.Add([System.Net.HttpRequestHeader]::Cookie, $cookie) 
if (!(Test-Path "c:\temp\$($javaSource.Split('/')[-1])")) {
    Write-Output "downloading $javaSource"
    $client.downloadFile($javaSource, $javaDestination)  
}

if (!(Test-Path "c:\temp\$($7zip.Split("/")[-1])")) {
    Write-Output "downloading $7zip"
    Invoke-WebRequest -Uri $7zip -OutFile "c:\temp\$($7zip.Split("/")[-1])"   
}
if (!(Test-Path "c:\temp\$($zk3_4_12.Split("/")[-1])")) {
    Write-Output "downloading $zk3_4_12"
    Invoke-WebRequest -Uri $zk3_4_12 -OutFile "c:\temp\$($zk3_4_12.Split("/")[-1])"
}
if (!(Test-Path "c:\temp\$($zk3_5_4beta.Split("/")[-1])")) {
    Write-Output "downloading $zk3_5_4beta"
    Invoke-WebRequest -Uri $zk3_5_4beta -OutFile "c:\temp\$($zk3_5_4beta.Split("/")[-1])"
}
if (!(Test-Path "c:\temp\$($solr7_3_1.Split("/")[-1])")) {
    Write-Output "downloading $solr7_3_1"
    Invoke-WebRequest -Uri $solr7_3_1 -OutFile "c:\temp\$($solr7_3_1.Split("/")[-1])"
}
$7zipFilePath = "c:\temp\$($7zip.Split("/")[-1])"
$FLAGS = "/qn /l C:\temp\7zipInstallLog.log"
Start-Process  -FilePath "$7zipFilePath" $FLAGS -Wait -PassThru

DeGZip-File "c:\temp\$($zk3_4_12.Split("/")[-1])"
DeGZip-File "c:\temp\$($zk3_5_4beta.Split("/")[-1])"

if (-not (test-path "$env:ProgramFiles\7-Zip\7z.exe")) {throw "$env:ProgramFiles\7-Zip\7z.exe needed"} 
set-alias untar "$env:ProgramFiles\7-Zip\7z.exe" 
$zk = $zk3_4_12.Split("/")[-1].Replace('.gz', '')
untar x c:\temp\$zk

$zk = $zk3_5_4beta.Split("/")[-1].Replace('.gz', '')
untar x c:\temp\$zk

$solr7_3_1_base = $solr7_3_1.Split("/")[-1].Replace('.zip','')
Expand-Archive -Path "c:\temp\$($solr7_3_1.Split("/")[-1])" -DestinationPath "c:\temp\$solr7_3_1_base"