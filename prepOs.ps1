param (
[string]$DnsZone
)

$disk = Get-Disk | Where-Object partitionstyle -eq 'raw' | Sort-Object number
$disk[0] |  Initialize-Disk -PartitionStyle MBR -PassThru |    New-Partition -UseMaximumSize -DriveLetter 's' |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false -Force

$disk[1] |  Initialize-Disk -PartitionStyle MBR -PassThru |    New-Partition -UseMaximumSize -DriveLetter 't' |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel "Logs" -Confirm:$false -Force

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name 'NV Domain' -Value $dnsZone

Restart-Computer -Force
