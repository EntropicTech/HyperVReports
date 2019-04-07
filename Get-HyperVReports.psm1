function Get-ClusterCheck {
    [CmdletBinding()]
    param(
    )

    $ClusterCheckTest = $False
    $ClusterCheckTest = Get-Cluster -ErrorAction SilentlyContinue
    if ($ClusterCheckTest) {
        $Script:ClusterCheck = $True
    } else {
        $Script:ClusterCheck = $False
    }

}

function Get-HyperVReports {
    [CmdletBinding()]
    param(
    )

    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "                   Hyper-V Reports"                     -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "[1]  Hyper-V Cluster Log Search" -ForegroundColor White
    Write-Host "[2]  Maintenance QC" -ForegroundColor White
    Write-Host "[3]  Cluster Aware Update History" -ForegroundColor White
    Write-Host "[4]  Storage Reports" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    $MenuChoice = Read-Host "Menu Choice"
    if ($MenuChoice -eq 1) {
        Get-HyperVClusterLogs
    } elseif ($MenuChoice -eq 2) {
        Get-HyperVMaintenanceQC
    } elseif ($MenuChoice -eq 3) {
        Get-HyperVCAULogs
    } elseif ($MenuChoice -eq 4) {
        Get-HyperVStorageReport
    } else {
        Clear-Host
        Write-Host "Incorrect Choice. Choose a number from the menu."
        Start-Sleep -s 3
        Get-HyperVReports
    }
}

function Get-HyperVCAULogs {
    [CmdletBinding()]
    param(
    )

    #Variables
    $Cluster = (Get-Cluster).Name
    $CAUDates = ( (Get-WinEvent -LogName *ClusterAwareUpdating*).TimeCreated | Get-Date -Format MM/dd/yyy) | Get-Unique
    $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue    

    # Gathers CAU Dates from logs and prints for $StartDate input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    Write-Host "Dates CAU was performed:" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    Write-Output $CAUDates
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    
    $StartDateRequest = Read-Host "Which date do you want logs from"
    $StartDate = $StartDateRequest | Get-Date -Format MM/dd/yyyy

    # Prints CAU logs
    Write-Host `n
    Write-Host "CAU logs from $StartDate for $Cluster." -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    
    $ClusterNodes | ForEach-Object {
        Get-WinEvent -ComputerName $_.Name -LogName *ClusterAwareUpdating* | Where-Object { $_.TimeCreated -Match $StartDate } | Select-Object TimeCreated,Message | Sort-Object TimeCreated
    } | Format-Table -AutoSize
    
    # Prints HotFix logs
    Write-Host "Updates installed during this CAU run." -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    
    $ClusterNodes  | ForEach-Object {
        Get-HotFix -ComputerName $_.Name | Where-Object { $_.InstalledOn -Match $StartDate }
    } | Format-Table -AutoSize
}

function Get-HyperVClusterLogs {
    [CmdletBinding()]
    param(
    )

    # Prints the Menu. Accepts input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "Hyper-V Cluster Event Log Search"                       -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "[1]  Search last 24 hours" -ForegroundColor White
    Write-Host "[2]  Specify date range" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    
    $MenuChoice = Read-Host "Please select menu number"
    
    # Collects information for filter.
    $Messagetxt = Read-Host "Enter text to filter the Event Logs by VM Name or Event log text"
    
    if ($MenuChoice -eq 1) {
        $StartDate = (Get-Date).AddDays(-1)   
        $EndDate = (Get-Date).AddDays(1)   
    } elseif ($MenuChoice -eq 2) {
        $DateFormat = Get-Date -Format d
        Write-Host "The date format for this environment is '$DateFormat'." -ForegroundColor Yellow
        $StartDate = Read-Host "Enter oldest search date."
        $EndDate = Read-Host "Enter latest search date."
    }
    Write-Host `n
    
    # Filter for log collection.           
    $Filter = @{
        LogName = "*Hyper-V*"
        StartTime = $StartDate
        EndTime = $EndDate
    }
    
    $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue

    if ($ClusterCheck -ne $False) {
        foreach ($Node in $ClusterNodes) {
            Write-Host $Node.Name -ForegroundColor Green
            Get-WinEvent -ComputerName $Node.Name -FilterHashtable $Filter | Where-Object -Property Message -like "*$Messagetxt*" | Select-Object TimeCreated,ProviderName,Message | Sort-Object TimeCreated | Format-List
        }
    } elseif ($ClusterCheck -eq $False) {
        Write-Host $env:COMPUTERNAME -ForegroundColor Green
        Get-WinEvent -FilterHashtable $Filter | Where-Object -Property Message -like "*$Messagetxt*" | Select-Object TimeCreated,ProviderName,Message | Sort-Object TimeCreated | Format-List
    }
}

Function Get-HyperVMaintenanceQC {
    [CmdletBinding()]
    param(
    )
    
    Clear-Host

    # Gather Cluster Variables
    $Cluster = Get-Cluster
    $ClusterNodes = Get-ClusterNode

    #Variable cleanup
    $TotalVMHostMemory = $False
    $TotalUsableVMHostMemory = $False
    $VirtMemory = $False
    $NonClusteredVMs = $False
        
    if ($ClusterCheck -eq $False) {  
        Write-host "This is not a Hyper-V cluster node. Try again." -ForegroundColor Red
        break
    }
    
    #Start The Maths
    Write-Host "Calculating cluster memory usage..." -ForegroundColor Green -BackgroundColor Black

    $VMHostMemory = foreach ($Node in $ClusterNodes) {
        
        [PSCustomObject]@{
            Name = $Node.Name
            TotalMemory = [math]::Round( (Get-WmiObject Win32_ComputerSystem -ComputerName $Node.Name).TotalPhysicalMemory /1GB )
            AvailableMemory = [math]::Round(( (Get-WmiObject Win32_OperatingSystem -ComputerName $Node.Name).FreePhysicalMemory ) /1024 /1024 )
            UsableMemory = [math]::Round( (Get-Counter -ComputerName $Node.Name -Counter "\Hyper-V Dynamic Memory Balancer(System Balancer)\Available Memory").Readings.Split(":")[1] / 1024 )
        }
    }

    foreach ($VMHost in $VMHostMemory) {
        $TotalVMHostMemory += $VMHost.TotalMemory
        $TotalAvailableVMHostMemory += $VMHost.AvailableMemory
        $TotalUsableVMHostMemory += $VMHost.UsableMemory
        $VirtMemory += $VMHost.AvailableMemory - $VMHost.UsableMemory
    }

    $Nodecount = $ClusterNodes.Count
    $SingleNodeVirtMemory = [math]::Round($VirtMemory/$Nodecount)
    $SingleNodeMemory = $VMHostMemory.TotalMemory[0]
    $Nodecheck = $TotalVMHostMemory / $SingleNodeMemory
    $HAMemory = $SingleNodeMemory - ($TotalUsableVMHostMemory + $SingleNodeVirtMemory)

    #Collect unclustered VMs
    $NonClusteredVMs = foreach ($Node in $ClusterNodes) {
        Get-VM -ComputerName $Node.Name | Where-Object { $_.IsClustered -eq $False }
    }

    #Clear screen and print report.
    Clear-Host
        
    if ($Nodecount -eq "1") {
        Write-Host "===========================================" -ForegroundColor DarkGray
        Write-Host "    $Cluster is a single node cluster."
        Write-Host "===========================================" -ForegroundColor DarkGray
    } else {
        Write-Host "===========================================" -ForegroundColor DarkGray
        Write-Host "       $Cluster has $Nodecount nodes."
        Write-Host "===========================================" -ForegroundColor DarkGray
    }

    # Print Node Memory Report                      
    Write-Host "  $TotalVMHostMemory GB - Physical memory of cluster."   
    Write-Host "  $SingleNodeMemory GB - Physical memory of each node."    
    Write-Host "  $TotalUsableVMHostMemory GB - Useable memory of cluster."    
    Write-Host "===========================================" -ForegroundColor DarkGray

    # Prints error if all nodes don't have the same amount of memory.    
    if ($Nodecheck -ne $Nodecount) {        
        Write-Host "  Nodes have different amounts of memory!" -ForegroundColor Red        
        Write-Host "===========================================" -ForegroundColor DarkGray
    }
        
    # Checks if cluster is HA.    
    if ($TotalUsableVMHostMemory -le $SingleNodeMemory) {       
        Write-host " Cluster would NOT survive single failure!" -ForegroundColor Red
        Write-Host "-------------------------------------------" -ForegroundColor DarkGray       
        Write-Host " More than $HAMemory GB of memory needed to be HA."
    } else {    
        Write-Host "  Cluster would survive single failure." -ForegroundColor Green
    }

    Write-Host "===========================================" -ForegroundColor DarkGray

    # Checks if nonclustered VMs exist and prints list

    if ($Null -eq $NonClusteredVMs){
        Write-Host "          All VMs are clustered." -ForegroundColor Green
        Write-Host "-------------------------------------------" -ForegroundColor DarkGray
    } else {
        Write-Host "          VMs NOT in cluster." -ForegroundColor Yellow
        Write-Host "-------------------------------------------" -ForegroundColor DarkGray
    }
    
    $VMs = foreach ($VM in $NonClusteredVMs) {
       if ($VM.State -eq "Running") { 

            [PSCustomObject]@{
                VMName = $VM.Name
                VMState = $VM.State
                VMHost = $VM.Computername
            }
        } 
        if ($VM.State -eq "Off") {

            [PSCustomObject]@{
                VMName = $VM.Name
                VMState = $VM.State
                VMHost = $VM.Computername
            }
        }
    }

    $NonClusteredVMsSorted = $VMs | Sort-Object VMState

    foreach ($VM in $NonClusteredVMsSorted) {
        Write-Host  $VM.VMHost - $VM.VMState - $VM.VMName -ForegroundColor Yellow
    }
}

function Get-HyperVStorageReport {
    [CmdletBinding()]
    param(
    )

    # Prints the Menu. Accepts input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "Hyper-V Storage Reports"                       -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "[1]  Full report" -ForegroundColor White
    Write-Host "[2]  Storage Utilization" -ForegroundColor White
    Write-Host "[3]  Cluster Storage IO - 2016 Only" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    
    $MenuChoice = Read-Host "Menu Choice"
    
    $CSVs = Get-Partition | Where-Object AccessPaths -like *ClusterStorage* | Select-Object AccessPaths,DiskNumber   

    $CSVInfo = foreach ($CSV in $CSVs) {
        $AccessPathVolumeID = $CSV.AccessPaths.Split("/")[1]
        $ClusterPath = $CSV.AccessPaths.Split("/")[0]
        $ClusterSharedVolume = Get-ClusterSharedVolume -Name ($ClusterPath.Split("\")[2]) | Select-Object -ExpandProperty SharedVolumeInfo | Select-Object -Property FriendlyVolumeName -ExpandProperty Partition
        $VolumeBlock = Get-Volume | Where-Object ObjectID -like *$AccessPathVolumeID*
        $QOS = Get-StorageQosVolume | Where-Object MountPoint -Like *$ClusterPath* -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                "#" = $CSV.DiskNumber
                Block = (Get-CimInstance -ClassName Win32_Volume | Where-Object Label -Like $VolumeBlock.FileSystemLabel).BlockSize
                ClusterPath = $ClusterSharedVolume.FriendlyVolumeName
                "Used(GB)" = [math]::Round($ClusterSharedVolume.UsedSpace /1GB)
                "Size(GB)" = [math]::Round($ClusterSharedVolume.Size /1GB)
                "Free %" = [math]::Round($ClusterSharedVolume.PercentFree, 1)
                IOPS = $QOS.IOPS
                Latency = [math]::Round($QOS.Latency, 2)
                "MB/s" = [math]::Round(($QOS.Bandwidth /1MB), 1)
            }
    }
    $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue
    $LocalDrives = foreach ($Node in $ClusterNodes) {
        $Drives = Invoke-Command -ComputerName $Node { Get-Volume | Where-Object FileSystem -NE CSVFS | Where-Object DriveLetter -NE C }
        foreach ($Drive in $Drives) {
            [PSCustomObject]@{
                ServerName = $Drive.PSComputerName
                Drive = $Drive.DriveLetter
                Block = $Drive.AllocationUnitSize
                FileSystemLabel = $Drive.FileSystemLabel
                Size = $Drive.Size
                SizeRemaining = $Drive.SizeRemaining
            }
        }
    }
    if ($MenuChoice -eq 1) {
        $CSVInfo | Format-Table -AutoSize
        $LocalDrives | Format-Table -AutoSize
    } elseif ($MenuChoice -eq 2) {
        $CSVInfo | Select-Object "#",ClusterPath,"Used(GB)","Size(GB)","Free %" | Sort-Object "#" | Format-Table -AutoSize
        $LocalDrives | Format-Table -AutoSize           
    } elseif ($MenuChoice -eq 3) {
        $CSVInfo | Select-Object "#",ClusterPath,"Size(GB)",IOPS,Latency,MB/s | Sort-Object "#" | Format-Table -AutoSize 
    } else {
        Write-Host "Incorrect Choice. Choose a number from the menu."
        Start-Sleep -s 3
        Get-HyperVStorageReport
    }
}
