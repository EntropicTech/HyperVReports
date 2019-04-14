function Get-HyperVReports {
    [CmdletBinding()]
    param(
    )
    process {
        # Requires -RunAsAdministrator
        
        # Sets Console to black background
        $host.UI.RawUI.BackgroundColor = "Black"
        
        # Checks to see if the cluster service is running.
        $ClusterCheckTest = $False
        $ClusterCheckTest = Get-Cluster -ErrorAction SilentlyContinue
        if ($ClusterCheckTest) {
            $Script:ClusterCheck = $True
            Get-HyperVReportsMenu
        } else {
            $Script:ClusterCheck = $False
            Get-HyperVReportsMenu
        }

        # Pull operating system version
        $Script:OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
    }
}

function Get-HyperVReportsMenu {
    [CmdletBinding()]
    param(
    )
    begin {
        Clear-Host
        Write-Host -------------------------------------------------------- -ForegroundColor Green
        Write-Host "                   Hyper-V Reports"                     -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor Green
        Write-Host "[1]  Hyper-V Cluster Log Search" -ForegroundColor White
        Write-Host "[2]  Maintenance QC" -ForegroundColor White
        Write-Host "[3]  Cluster Aware Update History" -ForegroundColor White
        Write-Host "[4]  Storage Reports" -ForegroundColor White
        Write-Host "[5]  VM Reports" -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor Green
        $MenuChoice = Read-Host "Menu Choice"
    }
    process {
        
        # Prints report based on MenuChoice.
        switch ($MenuChoice) {
            1 { Get-HyperVClusterLogs }
            2 { Get-HyperVMaintenanceQC }
            3 { Get-HyperVCAULogs }
            4 { Get-HyperVStorageReport }
            5 { Get-HyperVVMInfo }
            default { 
                Clear-Host
                Write-Host "Incorrect Choice. Choose a number from the menu."
                Start-Sleep -s 3
                Get-HyperVReports 
            }
        }  
    }
}

function Get-HyperVCAULogs {
    [CmdletBinding()]
    param(
    )
    begin {
        try {
            # Variables
            $Cluster = (Get-Cluster).Name
            $CAUDates = ( (Get-WinEvent -LogName *ClusterAwareUpdating*).TimeCreated | Get-Date -Format MM/dd/yyy) | Get-Unique
            $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Couldn't process cluster nodes!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red 
        }    
        
        # Gathers CAU Dates from logs and prints for $StartDate input.
        Clear-Host
        Write-Host -------------------------------------------------------- -ForegroundColor  Green
        Write-Host "Dates CAU was performed:" -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor  Green
        Write-Output $CAUDates
        Write-Host -------------------------------------------------------- -ForegroundColor  Green
        $StartDateRequest = Read-Host "Which date would you like the logs from"
    }
    process {
        
        Write-Host `n
        Write-Host "Collecting CAU logs and hotfix information..."

        # Formatting provided startdate for use in filtering.
        $StartDate = $StartDateRequest | Get-Date -Format MM/dd/yyyy
        
        # Collects HotFixs from cluster nodes.
        try {
            $Hotfixes = $False
            $Hotfixes = foreach ($Node in $ClusterNodes) {
            Get-HotFix -ComputerName $Node.Name | Where-Object InstalledOn -Match $StartDate
            }
        } catch {
            Write-Host "Couldn't collect the hotfixes from cluster nodes!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        
        # Collects eventlogs for cluster nodes.
        try {
            $EventLogs = $False
            $EventLogs = foreach ($Node in $ClusterNodes) {
            Get-WinEvent -ComputerName $Node.Name -LogName *ClusterAwareUpdating* | Where-Object TimeCreated -Match $StartDate | Select-Object TimeCreated,Message 
            }
        } catch {
            Write-Host "Couldn't collect the event logs from cluster nodes!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }        
    }
    end {    
        
        Clear-Host

        # Prints CAU logs
        Write-Host `n
        Write-Host "CAU logs from $StartDate for $Cluster." -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor  Green
        if ($Eventlogs) {
            $Eventlogs | Sort-Object TimeCreated | Format-Table -AutoSize
        } else {
            Write-Host "No Logs Found"
        } 
        
        # Prints HotFix logs
        Write-Host "Updates installed during this CAU run." -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor  Green
        if ($Hotfixes) {
            $Hotfixes | Format-Table -AutoSize
        } else {
            Write-Host "No Hotfixes Found"
        }              
    }
}

function Get-HyperVClusterLogs {
    [CmdletBinding()]
    param(
    )
    begin {
    # Prints the Menu. Accepts input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "           Hyper-V Cluster Event Log Search"            -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "[1]  Search last 24 hours" -ForegroundColor White
    Write-Host "[2]  Specify date range" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    $MenuChoice = Read-Host "Please select menu number"
    }
    process {
        
        # Collects text to filter the event log with.
        $Messagetxt = Read-Host "Enter text to filter the Event Logs by VM Name or Event log text"
        
        #Builds a 24hour $StartDate and #EndDate unless date is provided.
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
        try {
            $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Couldn't collect information from cluster nodes!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red            
        }
        
        #Builds $EventLogs variable used in report.
        if ($ClusterCheck -ne $False) {
            foreach ($Node in $ClusterNodes) {
                $EventLogs = $False
                Write-Host $Node.Name -ForegroundColor Green
                $Eventlogs = Get-WinEvent -ComputerName $Node.Name -FilterHashtable $Filter -ErrorAction SilentlyContinue | Where-Object -Property Message -like "*$Messagetxt*" | Select-Object TimeCreated,ProviderName,Message
                if ($EventLogs) {
                    $EventLogs | Sort-Object TimeCreated | Format-List
                } else {
                    Write-Host "No Logs Found"
                    Write-Host `n
                }
            }
        } elseif ($ClusterCheck -eq $False) {
            $EventLogs = $False
            Write-Host $env:COMPUTERNAME -ForegroundColor Green
            $EventLogs = Get-WinEvent -FilterHashtable $Filter | Where-Object -Property Message -like "*$Messagetxt*" | Select-Object TimeCreated,ProviderName,Message 
            if ($EventLogs) {
                $EventLogs | Sort-Object TimeCreated | Format-List
            } else {
                 Write-Host "No Logs Found"
            }
        }
    }
}

Function Get-HyperVMaintenanceQC {
    [CmdletBinding()]
    param(
    )
    begin {
        # Gather Cluster Variables
        $Cluster = Get-Cluster
        $ClusterNodes = Get-ClusterNode

        # Variable cleanup
        $TotalVMHostMemory = $False
        $TotalUsableVMHostMemory = $False
        $VirtMemory = $False
        $NonClusteredVMs = $False
        
        if ($ClusterCheck -eq $False) {  
            Write-host "This is not a Hyper-V cluster node. Try again." -ForegroundColor Red
            break
        }
    
        Clear-Host
    }
    process {
        Write-Host "Calculating cluster memory usage..." -ForegroundColor Green -BackgroundColor Black

        # Building variable that has memory info for all of the cluster nodes.
        $VMHostMemory = foreach ($Node in $ClusterNodes) {
            [PSCustomObject]@{
                Name = $Node.Name
                TotalMemory = [math]::Round( (Get-WmiObject Win32_ComputerSystem -ComputerName $Node.Name).TotalPhysicalMemory /1GB )
                AvailableMemory = [math]::Round(( (Get-WmiObject Win32_OperatingSystem -ComputerName $Node.Name).FreePhysicalMemory ) /1024 /1024 )
                UsableMemory = [math]::Round( (Get-Counter -ComputerName $Node.Name -Counter "\Hyper-V Dynamic Memory Balancer(System Balancer)\Available Memory").Readings.Split(":")[1] / 1024 )
            }
        }
        
        # Adding the hosts memory values together.
        foreach ($VMHost in $VMHostMemory) {
            $TotalVMHostMemory += $VMHost.TotalMemory
            $TotalAvailableVMHostMemory += $VMHost.AvailableMemory
            $TotalUsableVMHostMemory += $VMHost.UsableMemory
            $VirtMemory += $VMHost.AvailableMemory - $VMHost.UsableMemory
        }

        # Calculate math for different variables.
        $Nodecount = $ClusterNodes.Count
        $SingleNodeVirtMemory = [math]::Round($VirtMemory/$Nodecount)
        $SingleNodeMemory = $VMHostMemory.TotalMemory[0]
        $Nodecheck = $TotalVMHostMemory / $SingleNodeMemory
        $UsableMemoryAfterFailure = ($TotalUsableVMHostMemory + $SingleNodeVirtMemory)
        $HAMemory = $SingleNodeMemory - $UsableMemoryAfterFailure        

        # Collect unclustered VMs
        $NonClusteredVMs = foreach ($Node in $ClusterNodes) {
            Get-VM -ComputerName $Node.Name | Where-Object IsClustered -eq $False 
        }
        
        # Sort Nonclustered VMs by their state for readability.
        $NonClusteredVMsSorted = $NonClusteredVMs | Sort-Object State

    }
    end {
        
        # Clear screen and print report.
        Clear-Host
        
        if ($Nodecount -eq "1") {
            Write-Host "===========================================" -ForegroundColor DarkGray
            Write-Host "    $Cluster is a single node cluster."
            Write-Host "===========================================" -ForegroundColor DarkGray
        } else {
            Write-Host "===========================================" -ForegroundColor DarkGray
            Write-Host "         $Cluster has $Nodecount nodes."
            Write-Host "===========================================" -ForegroundColor DarkGray
        }

        # Print Node Memory Report                      
        Write-Host "  $TotalVMHostMemory GB - Physical memory of cluster."   
        Write-Host "  $SingleNodeMemory GB - Physical memory of each node."    
        Write-Host "  $UsableMemoryAfterFailure GB - Useable memory with 1 failure."    
        Write-Host "===========================================" -ForegroundColor DarkGray

        # Prints error if all nodes don't have the same amount of memory.    
        if ($Nodecheck -ne $Nodecount) {        
            Write-Host "  Nodes have different amounts of memory!" -ForegroundColor Red        
            Write-Host "===========================================" -ForegroundColor DarkGray
        }
        
        # Checks if cluster is HA.    
        if ($TotalUsableVMHostMemory -le $SingleNodeMemory -and $HAMemory -gt 0) {       
            Write-host " Cluster would NOT survive single failure!" -ForegroundColor Red
            Write-Host "-------------------------------------------" -ForegroundColor DarkGray       
            Write-Host " More than $HAMemory GB of memory needed to be HA."
        } else {    
            Write-Host "  Cluster would survive single failure." -ForegroundColor Green
        }

        Write-Host "===========================================" -ForegroundColor DarkGray

        # Checks if nonclustered VMs exist and prints list.
        if ($Null -eq $NonClusteredVMs) {
            Write-Host "          All VMs are clustered." -ForegroundColor Green
            Write-Host "-------------------------------------------" -ForegroundColor DarkGray
        } else {
            Write-Host "          VMs NOT in cluster." -ForegroundColor Yellow
            Write-Host "-------------------------------------------" -ForegroundColor DarkGray
        }
        
        # Prints nonclustered VMs.
        foreach ($VM in $NonClusteredVMsSorted) {
            Write-Host  $VM.ComputerName - $VM.State - $VM.Name -ForegroundColor Yellow
        }
    }
}

function Get-HyperVStorageReport {
    [CmdletBinding()]
    param(
    )
    begin {
        
        # Prints the Menu. Accepts input.
        Clear-Host
        Write-Host -------------------------------------------------------- -ForegroundColor Green
        Write-Host "               Hyper-V Storage Reports"                       -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor Green
        Write-Host "[1]  Full report" -ForegroundColor White
        Write-Host "[2]  Storage Utilization" -ForegroundColor White
        Write-Host "[3]  Cluster Storage IO - 2016 Only" -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor Green    
        $MenuChoice = Read-Host "Menu Choice"
    }
    process {   
        try {
            
            # Collects data to build variable from.
            $OSVersion = [environment]::OSVersion.Version.Major
            $CSVs = Get-Partition | Where-Object AccessPaths -like *ClusterStorage* | Select-Object AccessPaths,DiskNumber
            
            # Builds variable to use in report data.
            $CSVInfo = foreach ($CSV in $CSVs) {
                $AccessPathVolumeID = $CSV.AccessPaths.Split("/")[1]
                $ClusterPath = $CSV.AccessPaths.Split("/")[0]
                $FriendlyPath = ($ClusterPath).Split("\")[2]
                $ClusterSharedVolume = Get-ClusterSharedVolume | Select-Object -ExpandProperty SharedVolumeInfo | Where-Object FriendlyVolumeName -like *$FriendlyPath* | Select-Object -Property FriendlyVolumeName -ExpandProperty Partition
                $VolumeBlock = Get-Volume | Where-Object ObjectID -like *$AccessPathVolumeID*
                if ($OSVersion -eq 10) {
                    $QOS = Get-StorageQosVolume | Where-Object MountPoint -Like *$ClusterPath* 
                    [PSCustomObject]@{
                        "#" = $CSV.DiskNumber
                        Block = $VolumeBlock.AllocationUnitSize
                        ClusterPath = $ClusterSharedVolume.FriendlyVolumeName
                        "Used(GB)" = [math]::Round($ClusterSharedVolume.UsedSpace /1GB)
                        "Size(GB)" = [math]::Round($ClusterSharedVolume.Size /1GB)
                        "Free %" = [math]::Round($ClusterSharedVolume.PercentFree, 1)
                        IOPS = $QOS.IOPS
                        Latency = [math]::Round($QOS.Latency, 2)
                        "MB/s" = [math]::Round(($QOS.Bandwidth /1MB), 1)
                    }
                } else {
                    [PSCustomObject]@{
                        "#" = $CSV.DiskNumber
                        Block = (Get-CimInstance -ClassName Win32_Volume | Where-Object Label -Like $VolumeBlock.FileSystemLabel).BlockSize
                        ClusterPath = $ClusterSharedVolume.FriendlyVolumeName
                        "Used(GB)" = [math]::Round($ClusterSharedVolume.UsedSpace /1GB)
                        "Size(GB)" = [math]::Round($ClusterSharedVolume.Size /1GB)
                        "Free %" = [math]::Round($ClusterSharedVolume.PercentFree, 1)
                    }
                }
            }
        } catch {
            Write-Host "Couldn't process Cluster Shared Volume data!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }         
    }
    end {
        
        # Prints report based on MenuChoice.
        switch ($MenuChoice) {
            1 { $CSVInfo | Sort-Object "#" | Format-Table -AutoSize }
            2 { $CSVInfo | Select-Object "#",ClusterPath,"Used(GB)","Size(GB)","Free %" | Sort-Object "#" | Format-Table -AutoSize }
            3 { $CSVInfo | Select-Object "#",ClusterPath,"Size(GB)",IOPS,Latency,MB/s | Sort-Object "#" | Format-Table -AutoSize }
            default { 
                Write-Host "Incorrect Choice. Choose a number from the menu."
                Start-Sleep -s 3
                Get-HyperVStorageReport
            }
        }
    }
}

function Get-HyperVVMInfo {
    [CmdletBinding()]
    param(
    )
    begin {
        
        # Prints the Menu. Accepts input.
        Clear-Host
        Write-Host -------------------------------------------------------- -ForegroundColor Green
        Write-Host "                  Hyper-V VM Reports"                   -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor Green
        Write-Host "[1]  Full report" -ForegroundColor White
        Write-Host "[2]  VM Resource Allocation" -ForegroundColor White
        Write-Host "[3]  VM Networking" -ForegroundColor White
        Write-Host -------------------------------------------------------- -ForegroundColor Green    
        $MenuChoice = Read-Host "Menu Choice"
    }    
    process {
        
        # Pull Cluster node data for script.
        try {
            $ClusterNodes = Get-ClusterNode -ErrorAction Stop
        } catch {
            Write-Host "Couldn't collect information from cluster nodes!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red            
        }
        
        # Filter for IPv4 addresses
        $IPv4 = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
        
        # Collects VMs into variable for foreach loop
        $VMs = foreach ($Node in $ClusterNodes) {
            Get-VM -ComputerName $Node.Name    
        }   
        try{
        
            # Collects information from VMs and creates $VMInfo variable with all VM info.
            $VMInfo = foreach ($VM in $VMs) {
                $VMNetworkAdapter = Get-VMNetworkAdapter -ComputerName $VM.Computername -VMName $VM.VMName
                $VMNetworkAdapterVlan = Get-VMNetworkAdapter -ComputerName $VM.Computername -VMName $VM.VMName | Get-VMNetworkAdapterVlan
                    [PSCustomObject]@{
                        Host = $VM.ComputerName
                        VMName = $VM.VMName
                        vCPU = $VM.ProcessorCount
                        RAM = [math]::Round($VM.MemoryStartup /1GB)
                        IPAddress = $VMNetworkAdapter.Ipaddresses | Select-String -Pattern $IPv4
                        VLAN = $VMNetworkAdapterVlan.AccessVlanId
                        MAC = $VMNetworkAdapter.MacAddress
                        vSwitch = $VMNetworkAdapter.SwitchName
                    }   
            }                    
        } catch {
            Write-Host "Couldn't collect information from the VMs!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red              
        }       
    }
    end {
        
        # Prints report based on MenuChoice.
        switch ($MenuChoice) {
            1 { $VMInfo | Sort-Object Host | Format-Table -AutoSize }
            2 { $VMInfo | Select-Object Host,VMName,vCPU,RAM | Sort-Object Host | Format-Table -AutoSize }
            3 { $VMInfo | Select-Object Host,VMName,IPAddress,VLAN,MAC,VSwitch | Sort-Object Host | Format-Table -AutoSize }
            default { 
                Write-Host "Incorrect Choice. Choose a number from the menu."
                Start-Sleep -s 3
                Get-HyperVStorageReport
            }
        }
    }    
}
Get-HyperVReports
