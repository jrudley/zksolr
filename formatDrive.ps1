param (
    [string]$dataDriveLetter
)

$disk = Get-Disk | Where-Object partitionstyle -eq 'raw' | Sort-Object number
$disk | 
    Initialize-Disk -PartitionStyle MBR -PassThru |
    New-Partition -UseMaximumSize -DriveLetter $dataDriveLetter |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false -Force
