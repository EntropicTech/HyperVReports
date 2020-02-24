function Get-HyperVReports {
    <#
        .SYNOPSIS
            Get-HyperVReports prints the menu for selecting which report you would like to print.
    #>
    [CmdletBinding()]
    param()
     
    # Sets Console to black background
    $Host.UI.RawUI.BackgroundColor = "Black"

    # Prints the Menu. Accepts input.
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

    # Prints report based on $MenuChoice.
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

function Get-HyperVCAULogs {
    <#
        .SYNOPSIS
            Get-HyperVCAULogs collects CAU event log data and hotfixes and prints a report.
    #>
    [CmdletBinding()]
    param()

    # Collect Variables
    try {                        
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
        Write-Host "Couldn't collect the eventlogs from cluster nodes!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }        

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

function Get-HyperVClusterLogs {
    <#
        .SYNOPSIS
            Get-HyperVClusterLogs searches the Hyper-V eventlogs of a Hyper-V cluster and prints a report.
    #>     
    [CmdletBinding()]
    param()   

    # Setting up Variables.
    $ClusterCheck = $False
    $ClusterCheck = Get-Cluster
    $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue
    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
	$DomainNodes = foreach ($Node in $ClusterNodes) {
		$Node.Name + "." + $Domain
    }
    
    # Prints the Menu. Accepts input. 
    Clear-Host 
    Write-Host -------------------------------------------------------- -ForegroundColor Green 
    Write-Host "           Clustered Hyper-V Eventlog Search"            -ForegroundColor White 
    Write-Host -------------------------------------------------------- -ForegroundColor Green 
    Write-Host "[1]  Search last 24 hours" -ForegroundColor White 
    Write-Host "[2]  Specify date range" -ForegroundColor White 
    Write-Host -------------------------------------------------------- -ForegroundColor Green 
    $MenuChoice = Read-Host "Please select menu number"
    Write-Host `n   

    # Builds a 24hour $StartDate and #EndDate unless date is provided.
    Switch ($MenuChoice) {
        1 {
            $StartDate = (Get-Date).AddDays(-1)    
            $EndDate = (Get-Date).AddDays(1)
        } 2 {
            $DateFormat = Get-Date -Format d 
            Write-Host "The date format for this environment is '$DateFormat'." -ForegroundColor Yellow
            Write-Host `n 
            $StartDate = Read-Host "Enter oldest search date." 
            $EndDate = Read-Host "Enter latest search date."
            Write-Host `n         
        } default {
            Clear-Host
            Write-Host "Incorrect Choice. Choose a number from the menu."
            Start-Sleep -s 3
            Get-HyperVClusterLogs
        }
    }

    # Collects text to filter the event log with. 
    $Messagetxt = Read-Host "Enter the text you would like to search the eventlogs for"  
    Write-Host `n
    
    # Filter for log collection.            
    $Filter = @{
        LogName = "*Hyper-V*" 
        StartTime = $StartDate 
        EndTime = $EndDate 
    }               

    # Builds $EventLogs variable used in report. 
    if ($ClusterCheck) { 

        # Clear any old jobs out related to this script. 
        Get-Job | Where-Object Command -like *Get-WinEvent* | Remove-Job
            
        # Setup ScriptBlock for Invoke-Command.
        $EventLogScriptBlock = {  
            param($Filter,$Messagetxt) 
            Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue | Where-Object -Property Message -like "*$Messagetxt*"
        } 
        
        Write-Host "Reviewing Hyper-V servers for eventlogs containing $Messagetxt. Please be patient."    
        # Use jobs to pull event logs from all cluster nodes at the same time.
        Invoke-Command -ComputerName $DomainNodes -ScriptBlock $EventLogScriptBlock -ArgumentList $Filter,$Messagetxt -AsJob | Wait-Job | Out-Null

        # Collect eventlogs from jobs and assign to $EventLogs
        $EventLogs = Get-Job | Where-Object Command -like *Get-WinEvent* | Receive-Job                      
        $EventLogNodes = $EventLogs.PSComputerName | Get-Unique

        Clear-Host
        Write-Host -------------------------------------------------------------------------------------------------------------------------------------- -ForegroundColor Green 
        Write-Host "                                               Clustered Hyper-V Eventlog Search"                                                      -ForegroundColor White 
        Write-Host -------------------------------------------------------------------------------------------------------------------------------------- -ForegroundColor Green 
        Write-Host `n       

        foreach ($Node in $DomainNodes) {
            Write-Host $Node.split(".")[0] -ForegroundColor Green
            if ($EventLogNodes -contains $Node) {
                $EventLogs | Where-Object PSComputerName -EQ $Node | Select-Object TimeCreated,ProviderName,Message | Sort-Object TimeCreated | Format-List 
            } else { 
                Write-Host "No Logs found." 
                Write-Host `n 
            }
        }  
    } elseif ($ClusterCheck -eq $False) { 
        $EventLogs = $False 
        Write-Host $env:COMPUTERNAME -ForegroundColor Green 
        $EventLogs = Get-WinEvent -FilterHashtable $Filter | Where-Object -Property Message -Like "*$Messagetxt*" | Select-Object TimeCreated,ProviderName,Message  
        if ($EventLogs) { 
            $EventLogs | Sort-Object TimeCreated | Format-List 
        } else { 
            Write-Host "No Logs Found" 
        } 
    } 
} 

Function Get-HyperVMaintenanceQC {
    <#
        .SYNOPSIS
            Get-HyperVMaintenanceQC tests Hyper-V cluster to ensure single node failure and no unclustered VMS.
    #>
    [CmdletBinding()]
    param()

    $ClusterCheck = Get-Cluster -ErrorAction SilentlyContinue
    if ($ClusterCheck -eq $False) {  
        Write-host "This script only works for clustered Hyper-V servers." -ForegroundColor Red
        Start-Sleep -s 3
        Get-HyperVReports
    }
    
    # Gather Cluster Variables
    $Cluster = Get-Cluster
    $ClusterNodes = Get-ClusterNode
    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
	$DomainNodes = foreach ($Node in $ClusterNodes) {
		$Node.Name + "." + $Domain
    }
    
    # Variable Setup
    $TotalVMHostMemory = $False
    $TotalUsableVMHostMemory = $False
    $VirtMemory = $False
    $NonClusteredVMs = $False
    
    Clear-Host
    Write-Host "Calculating cluster memory usage..." -ForegroundColor Green -BackgroundColor Black

    # Building variable that has memory info for all of the cluster nodes.
    try {
        $VMHostMemory = foreach ($Node in $ClusterNodes) {
            [PSCustomObject]@{
                Name = $Node.Name
                TotalMemory = [math]::Round( (Get-WmiObject Win32_ComputerSystem -ComputerName $Node.Name).TotalPhysicalMemory /1GB )
                AvailableMemory = [math]::Round(( (Get-WmiObject Win32_OperatingSystem -ComputerName $Node.Name).FreePhysicalMemory ) /1024 /1024 )
                UsableMemory = [math]::Round( (Get-Counter -ComputerName $Node.Name -Counter "\Hyper-V Dynamic Memory Balancer(System Balancer)\Available Memory").Readings.Split(":")[1] / 1024 )
            }
        }
    } catch {
        Write-Host "Couldn't collect Memory usage from cluster nodes!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
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

    # Clear any old jobs out related to this script. 
    Get-Job | Where-Object Command -like *Get-VM* | Remove-Job
            
    # Setup ScriptBlock for Invoke-Command.
    $GetVMScriptBlock = {  
        Get-VM | Where-Object IsClustered -EQ $False
    } 
  
    # Use jobs to pull event logs from all cluster nodes at the same time.
    Invoke-Command -ComputerName $DomainNodes -ScriptBlock $GetVMScriptBlock -AsJob | Wait-Job | Out-Null

    # Collect eventlogs from jobs and assign to $EventLogs
    $NonClusteredVMs = Get-Job | Where-Object Command -like *Get-VM* | Receive-Job  
       
    # Sort Nonclustered VMs by their state for readability.
    $NonClusteredVMsSorted = $NonClusteredVMs | Sort-Object State

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
        $VMOutput = " " + $VM.ComputerName + " - " + $VM.State + " - " + $VM.Name
        Write-Host $VMOutput -ForegroundColor Yellow
    }
}

function Get-HyperVStorageReport {
    <#
        .SYNOPSIS
            Get-HyperVStorageReport collects Cluster Shared Volumes and prints a report of their data.
    #>
    [CmdletBinding()]
    param()

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

    # Builds $CSVINfo to gather disk info for final report.
    try {
        
        # Variable Setup
        $OSVersion = [environment]::OSVersion.Version.Major
        $CSVs = Get-Partition | Where-Object AccessPaths -like *ClusterStorage* | Select-Object AccessPaths,DiskNumber

        $results = foreach ($CSV in $CSVs) {    
            
            # Collecting CSV information
            $AccessPathVolumeID = $CSV.AccessPaths.Split("/")[1]
            $ClusterPath = $CSV.AccessPaths[0].TrimEnd("\")                
            $FriendlyPath = $ClusterPath.Split("\")[2]
            $ClusterSharedVolume = Get-ClusterSharedVolume | Select-Object -ExpandProperty SharedVolumeInfo | Where-Object FriendlyVolumeName -like $ClusterPath | Select-Object -Property FriendlyVolumeName -ExpandProperty Partition
            $VolumeBlock = Get-Volume | Where-Object Path -like $AccessPathVolumeID
            $CSVState =  (Get-ClusterSharedVolumeState | Where-Object VolumeFriendlyName -Like $FriendlyPath)[0]
            
            if ($OSVersion -eq 10) {
                $QOS = Get-StorageQosVolume | Where-Object MountPoint -Like *$ClusterPath* 
                [PSCustomObject]@{
                    "#" = $CSV.DiskNumber
                    Block = $VolumeBlock.AllocationUnitSize
                    CSVName = $CSVState.Name
                    ClusterPath = $ClusterPath
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
                    Block = (Get-CimInstance -ClassName Win32_Volume | Where-Object Label -Like $VolumeBlock.FileSystemLabel).BlockSize[0]
                    CSVName = $CSVState.Name
                    ClusterPath = $ClusterPath
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

    # Prints report based on $MenuChoice.
    switch ($MenuChoice) {
        1 { $results | Sort-Object "#" | Format-Table -AutoSize }
        2 { $results | Select-Object "#",CSVName,ClusterPath,"Used(GB)","Size(GB)","Free %" | Sort-Object "#" | Format-Table -AutoSize }
        3 { $results | Select-Object "#",CSVName,ClusterPath,"Size(GB)",IOPS,Latency,MB/s | Sort-Object "#" | Format-Table -AutoSize }
        default { 
            Write-Host "Incorrect Choice. Choose a number from the menu."
            Start-Sleep -s 3
            Get-HyperVStorageReport
        }
    }
}

function Get-HyperVVMInfo {
    <#
        .SYNOPSIS
            Get-HyperVVMInfo collects Hyper-V VM info and prints report of their data.
    #>    
    [CmdletBinding()]
    param()    

    # Prints the Menu. Accepts input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "                  Hyper-V VM Reports"                   -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "[1]  VM vCPU and RAM" -ForegroundColor White	
    Write-Host "[2]  VM Networking" -ForegroundColor White
    Write-Host "[3]  VM VHDX Size/Location/Type" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green    
    $MenuChoice = Read-Host "Menu Choice"

    # Pull Cluster node data for script.
    $ClusterNodes = Get-ClusterNode -ErrorAction Stop
    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
	$DomainNodes = foreach ($Node in $ClusterNodes) {
		$Node.Name + "." + $Domain
	}
	
    # Filter for IPv4 addresses
    $IPv4 = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
    
    Write-Host `n
    Write-Host "Gathering data from VMs... Please be patient." -ForegroundColor White

    # Clear any old jobs out related to this script. 
    Get-Job | Where-Object Command -like *Get-VM* | Remove-Job

    # Setup ScriptBlock for Invoke-Command.
    $VMInfoPull = {  
        Get-VM | Select-Object ComputerName,VMName,ProcessorCount,MemoryStartup
    } 
            
    # Use psjobs to pull VM data from all cluster nodes at the same time.
    Invoke-Command -ComputerName $DomainNodes -ScriptBlock $VMInfoPull -AsJob | Wait-Job | Out-Null

    # Collect VM data from jobs and assign to $VMs
    $VMs = Get-Job | Where-Object Command -like *Get-VM* | Receive-Job  

    # Collects information from VMs and creates $VMInfo variable with all VM info.  
    try{           
        $VMInfo = foreach ($VM in $VMs) {
            if ($MenuChoice -eq 1) {
                [PSCustomObject]@{
                    Host = $VM.ComputerName
                    VMName = $VM.VMName
                    vCPU = $VM.ProcessorCount
                    RAM = [math]::Round($VM.MemoryStartup /1GB)                                                
                }                                                 
            } elseif ($MenuChoice -eq 2) {
                $VMNetworkAdapters = Get-VMNetworkAdapter -ComputerName $VM.Computername -VMName $VM.VMName
                foreach ($Adapter in $VMNetworkAdapters) {
                    $VMNetworkAdapterVlans = Get-VMNetworkAdapterVlan -VMNetworkAdapter $Adapter
                    foreach ($AdapterVlan in $VMNetworkAdapterVlans) {
                        [PSCustomObject]@{
                            Host = $VM.ComputerName
                            VMName = $VM.VMName
                            IPAddress = $Adapter.Ipaddresses | Select-String -Pattern $IPv4
                            VLAN = $AdapterVlan.AccessVlanId
                            MAC = $Adapter.MacAddress
                            vSwitch = $Adapter.SwitchName
                        }
                    }
                }  
            } elseif ($MenuChoice -eq 3) {
                $Disks = Get-VMHardDiskDrive -ComputerName $VM.Computername -VMName $VM.VMName | Get-VHD -ComputerName $VM.Computername
                foreach ($Disk in $Disks) {
                    [PSCustomObject]@{
                        VMName = $VM.VMName
                        Disk = $Disk.Path
                        Size = [math]::Round($Disk.FileSize /1GB)
                        PotentialSize = [math]::Round($Disk.Size /1GB)
                        "VHDX Type" = $Disk.VhdType
                    }
                }
            }  
        }                    
    } catch {
        Write-Host "Couldn't collect information from the VMs!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red              
    }       

    # Prints report based on $MenuChoice.
    switch ($MenuChoice) {
        1 { $VMInfo | Select-Object Host,VMName,vCPU,RAM | Sort-Object Host | Format-Table -AutoSize }
        2 { $VMInfo | Select-Object Host,VMName,IPAddress,VLAN,MAC,VSwitch | Sort-Object Host | Format-Table -AutoSize }
        3 { $VMInfo | Select-Object VMName,Disk,Size,PotentialSize,"VHDX Type" | Sort-Object VMName | Format-Table -AutoSize }
        default { 
            Write-Host "Incorrect Choice. Choose a number from the menu."
            Start-Sleep -s 3
            Get-HyperVStorageReport
        }
    }
}    
Get-HyperVReports
