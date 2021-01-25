function Get-HyperVReports
{
    <#
        .SYNOPSIS
            Get-HyperVReports prints the menu for selecting which report you would like to print.
    #>
    [CmdletBinding()]
    param()
     
    Get-AdminCheck

    # Sets Console to black background
    $Host.UI.RawUI.BackgroundColor = 'Black'

    # Prints the Menu. Accepts input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host '                   Hyper-V Reports'                     -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host '[1]  Hyper-V Cluster Log Search'                        -ForegroundColor White
    Write-Host '[2]  Maintenance QC'                                    -ForegroundColor White
    Write-Host '[3]  Cluster Aware Update History'                      -ForegroundColor White
    Write-Host '[4]  Storage Reports'                                   -ForegroundColor White
    Write-Host '[5]  VM Reports'                                        -ForegroundColor White
    Write-Host '[6]  Storage Cleanup Analyzer'                          -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    $MenuChoice = Read-Host 'Menu Choice'

    # Prints report based on $MenuChoice.
    switch ($MenuChoice) 
    {
        1 { Get-HyperVClusterLogs }
        2 { Get-HyperVMaintenanceQC }
        3 { Get-HyperVCAULogs }
        4 { Get-HyperVStorageReport }
        5 { Get-HyperVVMInfo }
        6 { Get-HyperVStorageCleanupAnalyzer }
        default 
        { 
            Clear-Host
            Write-Host 'Incorrect Choice. Choose a number from the menu.'
            Start-Sleep -Seconds 3
            Get-HyperVReports 
        }
    }  
}

function Get-ClusterCheck
{
    <#
        .SYNOPSIS
            This function performs a check to see if this script is being executed on a clustered Hyper-V server. It converts that into a bool for use in the script.
    #>
    [CmdletBinding()]
    param()

    # Variable Setup
    $ErrorActionPreference = 'SilentlyContinue'      
    $result = $False   

    # Check to see if this is a functional cluster. If so, return $True.
    $BoolClusterCheck = Get-Cluster
    if ($BoolClusterCheck) 
    {
        $result = $True
    }
    $result
}

function Get-AdminCheck
{
    <#
        .SYNOPSIS
            This function performs a check to see if this script is being executed in an administrative prompt. Breaks if not.
    #>
    [CmdletBinding()]
    param()

    # Checks to see if it is being run in an administrative prompt. Breaks the script if not.
    if ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544') -eq $False )
    {
        Write-Error 'This script must be run with administrator privledges. Relaunch script in an administrative prompt.'
        break
    }
}

Function Get-DomainNodes
{
    <#
        .SYNOPSIS
            Get-DomainNodes creates an object that contains all of the clusternodes with their FQDN.       
    #>    
    [CmdletBinding()]
    param()

    $ClusterNodes = Get-ClusterNode -ErrorAction Stop
    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $DomainNodes = foreach ($node in $ClusterNodes)
    {
		$node.Name + '.' + $Domain
    }
    $DomainNodes
}

function Get-HyperVVMs
{
    <#
        .SYNOPSIS
            Get-HyperVVMs uses PSJobs to pull all of the VMs from all Hyper-V servers at the same time.     
    #>    
    [CmdletBinding()]
    param()

    if (Get-ClusterCheck)
    {
        $VMs = Get-VM -ComputerName (Get-DomainNodes)
    }
    else
    {
        $VMs = Get-VM
    }  
    $VMs
}

function Get-HyperVCAULogs
{
    <#
        .SYNOPSIS
            Get-HyperVCAULogs collects CAU event log data and hotfixes and prints a report.
    #>
    [CmdletBinding()]
    param()

    Get-AdminCheck

    # Verifying this is being run on a cluster.
    $ClusterCheck = Get-ClusterCheck
    if ($ClusterCheck -eq $False)
    {  
        Write-host 'This script only works for clustered Hyper-V servers.' -ForegroundColor Red
        Start-Sleep -Seconds 3
        Get-HyperVReports
    }

    # Collect Variables
    try 
    {                        
        $Cluster = (Get-Cluster).Name
        $CAUDates = ( (Get-WinEvent -LogName *ClusterAwareUpdating*).TimeCreated | Get-Date -Format MM/dd/yyy) | Get-Unique
        $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue
    }
    catch 
    {
        Write-Host "Couldn't process cluster nodes!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red 
    }    
    
    # Gathers CAU Dates from logs and prints for $StartDate input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    Write-Host 'Dates CAU was performed:' -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    Write-Output $CAUDates
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    $StartDateRequest = Read-Host 'Which date would you like the logs from'

    Write-Host `r
    Write-Host 'Collecting CAU logs and hotfix information...'

    # Formatting provided startdate for use in filtering.
    $StartDate = $StartDateRequest | Get-Date -Format MM/dd/yyyy
    
    # Collects HotFixs from cluster nodes.
    try 
    {
        $Hotfixes = $False
        $Hotfixes = foreach ($Node in $ClusterNodes) 
        {
            Get-HotFix -ComputerName $Node.Name | Where-Object InstalledOn -Match $StartDate
        }
    }
    catch
    {
        Write-Host "Couldn't collect the hotfixes from cluster nodes!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    
    # Collects eventlogs for cluster nodes.
    try
    {
        $EventLogs = $False
        $EventLogs = foreach ($Node in $ClusterNodes)
        {
            Get-WinEvent -ComputerName $Node.Name -LogName *ClusterAwareUpdating* | Where-Object TimeCreated -Match $StartDate | Select-Object TimeCreated,Message 
        }
    }
    catch
    {
        Write-Host "Couldn't collect the eventlogs from cluster nodes!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }        

    Clear-Host

    # Prints CAU logs
    Write-Host `r
    Write-Host "CAU logs from $StartDate for $Cluster." -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    if ($Eventlogs)
    {
        $Eventlogs | Sort-Object TimeCreated | Format-Table -AutoSize
    }
    else
    {
        Write-Host "No Logs Found"
    } 
    
    # Prints HotFix logs
    Write-Host 'Updates installed during this CAU run.' -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor  Green
    if ($Hotfixes) 
    {
        $Hotfixes | Format-Table -AutoSize
    }
    else
    {
        Write-Host 'No Hotfixes Found'
    }              
}

function Get-HyperVClusterLogs
{
    <#
        .SYNOPSIS
            Get-HyperVClusterLogs searches the Hyper-V eventlogs of a Hyper-V cluster and prints a report.
    #>     
    [CmdletBinding()]
    param()   

    Get-AdminCheck

    # Setting up Variables.
    $ClusterCheck = Get-ClusterCheck
    if ($ClusterCheck)
    {
        $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue
        $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        $DomainNodes = foreach ($node in $ClusterNodes)
        {
		    $node.Name + '.' + $Domain
        }
    }

    # Prints the Menu. Accepts input. 
    Clear-Host 
    Write-Host -------------------------------------------------------- -ForegroundColor Green 
    Write-Host '           Clustered Hyper-V Eventlog Search'           -ForegroundColor White 
    Write-Host -------------------------------------------------------- -ForegroundColor Green 
    Write-Host '[1]  Search last 24 hours' -ForegroundColor White
    Write-Host '[2]  Search last 48 hours' -ForegroundColor White 
    Write-Host '[3]  Search last 7 days' -ForegroundColor White  
    Write-Host '[4]  Specify date range to search' -ForegroundColor White 
    Write-Host -------------------------------------------------------- -ForegroundColor Green 
    $MenuChoice = Read-Host 'Select menu number'
    Write-Host `r   

    # Builds a 24, 48 or 7 day $StartDate and #EndDate unless date is provided.
    Switch ($MenuChoice)
    {
        1 { $DaysBack = -1 }
        2 { $DaysBack = -2 }
        3 { $DaysBack = -7 }
    }
    if ($MenuChoice -eq '1' -or $MenuChoice -eq '2' -or $MenuChoice -eq '3' )
    {
        $StartDate = (Get-Date).AddDays($DaysBack)   
        $EndDate = (Get-Date).AddDays(1)       
    }
    elseif ($MenuChoice -eq '4')
    {
        $DateFormat = Get-Date -Format d 
        Write-Host "The date format for this environment is '$DateFormat'." -ForegroundColor Yellow
        Write-Host `r 
        $StartDate = Read-Host 'Enter oldest search date' 
        $EndDate = Read-Host 'Enter latest search date'
        if ($EndDate -eq '')
        {
            $EndDate = (Get-Date).AddDays(1)
        }
        Write-Host `r        
    }
    else
    {
        Clear-Host
        Write-Host 'Incorrect Choice. Choose a number from the menu.'
        Start-Sleep -Seconds 3
        Get-HyperVClusterLogs
    }

    # Collects text to filter the event log with. 
    $Messagetxt = Read-Host 'Enter the text you would like to search the eventlogs for'  
    Write-Host `r
    
    # Filter for log collection.            
    $Filter = @{
        LogName = "*Hyper-V*" 
        StartTime = $StartDate 
        EndTime = $EndDate 
    }               

    Write-Host 'Reviewing Hyper-V servers for eventlogs containing $Messagetxt. Please be patient.'   

    Clear-Host
    Write-Host -------------------------------------------------------------------------------------------------------------------------------------- -ForegroundColor Green 
    Write-Host '                                               Clustered Hyper-V Eventlog Search'                                                     -ForegroundColor White 
    Write-Host -------------------------------------------------------------------------------------------------------------------------------------- -ForegroundColor Green
    Write-Host "Search results for: $Messagetxt"
    Write-Host `r
       

    # Builds $EventLogs variable used in report. 
    if ($ClusterCheck -eq $True)
    { 

        # Clear any old jobs out related to this script. 
        Get-Job | Where-Object Command -like *Get-WinEvent* | Remove-Job
            
        # Setup ScriptBlock for Invoke-Command.
        $EventLogScriptBlock = {  
            param($Filter,$Messagetxt) 
            Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue | Where-Object -Property Message -like "*$Messagetxt*"
        } 
         
        # Use jobs to pull event logs from all cluster nodes at the same time.
        Invoke-Command -ComputerName $DomainNodes -ScriptBlock $EventLogScriptBlock -ArgumentList $Filter,$Messagetxt -AsJob | Wait-Job | Out-Null

        # Collect eventlogs from jobs and assign to $EventLogs
        $EventLogs = Get-Job | Where-Object Command -like *Get-WinEvent* | Receive-Job                      
        $EventLogNodes = $EventLogs.PSComputerName | Get-Unique   

        foreach ($node in $DomainNodes)
        {
            Write-Host $node.split(".")[0] -ForegroundColor Green
            if ($EventLogNodes -contains $node)
            {
                $EventLogs | Where-Object PSComputerName -EQ $node | Select-Object TimeCreated,ProviderName,Message | Sort-Object TimeCreated | Format-List 
            }
            else
            {
                Write-Host `r  
                Write-Host 'No Logs found.' 
                Write-Host `n 
            }
        }  
    }
    elseif ($ClusterCheck -eq $False)
    { 
        $EventLogs = $False 
        Write-Host $env:COMPUTERNAME -ForegroundColor Green 
        $EventLogs = Get-WinEvent -FilterHashtable $Filter | Where-Object -Property Message -Like "*$Messagetxt*" | Select-Object TimeCreated,ProviderName,Message  
        if ($EventLogs)
        { 
            $EventLogs | Sort-Object TimeCreated | Format-List 
        }
        else
        { 
            Write-Host 'No Logs Found.' 
        } 
    } 
} 

Function Get-HyperVMaintenanceQC
{
    <#
        .SYNOPSIS
            Get-HyperVMaintenanceQC tests Hyper-V cluster to ensure single node failure and no unclustered VMS.
    #>
    [CmdletBinding()]
    param()

    Get-AdminCheck

    # Verifying this is being run on a cluster.
    $ClusterCheck = Get-ClusterCheck
    if ($ClusterCheck -eq $False)
    {  
        Write-host 'This script only works for clustered Hyper-V servers.' -ForegroundColor Red
        Start-Sleep -Seconds 3
        Get-HyperVReports
    }
    
    # Gather cluster variables
    $Cluster = Get-Cluster
    $DomainNodes = Get-DomainNodes
    
    Clear-Host
    Write-Host 'Calculating cluster memory usage...' -ForegroundColor Green -BackgroundColor Black

    # Building variable that has memory info for all of the cluster nodes.
    try
    {
        $VMHostMemory = foreach ($node in $DomainNodes)
        {
            [PSCustomObject]@{
                Name = $node.Split('.')[0]
                TotalMemory = [math]::Round( (Get-WmiObject Win32_ComputerSystem -ComputerName $node).TotalPhysicalMemory /1GB )
                AvailableMemory = [math]::Round(( (Get-WmiObject Win32_OperatingSystem -ComputerName $node).FreePhysicalMemory ) /1024 /1024 )
                UsableMemory = [math]::Round( (Get-Counter -ComputerName $node -Counter '\Hyper-V Dynamic Memory Balancer(System Balancer)\Available Memory').Readings.Split(':')[1] / 1024 )
            }
        }
    }
    catch
    {
        Write-Host "Couldn't collect Memory usage from cluster nodes!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }  
    
    # Adding the hosts memory values together.
    foreach ($VMHost in $VMHostMemory)
    {
        $TotalVMHostMemory += $VMHost.TotalMemory
        $TotalAvailableVMHostMemory += $VMHost.AvailableMemory
        $TotalUsableVMHostMemory += $VMHost.UsableMemory
        $VirtMemory += $VMHost.AvailableMemory - $VMHost.UsableMemory
    }

    # Calculate math for different variables.
    $Nodecount = $DomainNodes.Count
    $SingleNodeVirtMemory = $VirtMemory | Sort-Object -Descending | Select-Object -Last 1 # Reviews nodes and takes the node with the lowest virt memory. 
    $SingleNodeMemory = $VMHostMemory.TotalMemory[0]
    $Nodecheck = $TotalVMHostMemory / $SingleNodeMemory
    $UsableMemoryAfterFailure = ($TotalUsableVMHostMemory + $SingleNodeVirtMemory)
    $HAMemory = $SingleNodeMemory - $UsableMemoryAfterFailure
    [decimal]$NPlusMath = $UsableMemoryAfterFailure / $SingleNodeMemory
    $Nplus = $NPlusMath.ToString().Split('.')[0]
       
    # Sort nonclustered VMs by their state for readability.
    $VMs = Get-HyperVVMs
    $NonClusteredVMsSorted = $VMs | Where-Object IsClustered -EQ $False | Sort-Object State

    # Print the top of the report.
    Clear-Host    
    if ($Nodecount -eq '1')
    {
        # Header
        Write-Host '===========================================' -ForegroundColor DarkGray
        Write-Host "  $Cluster is a single node cluster"
        Write-Host '===========================================' -ForegroundColor DarkGray
        Write-Host '      Single node clusters are NOT HA.' -ForegroundColor Red
    }
    else
    {
        # Header
        Write-Host '===========================================' -ForegroundColor DarkGray
        Write-Host "        $Cluster - $Nodecount Nodes"
        Write-Host '===========================================' -ForegroundColor DarkGray
        
        # Print node memory report.                      
        Write-Host -NoNewline "   $TotalVMHostMemory " -ForegroundColor Green; Write-Host 'GB - Total cluster memory'   
        Write-Host -NoNewline "   $SingleNodeMemory " -ForegroundColor Green ; Write-Host 'GB - Memory of each node'
        if ($NPlus -gt 0)
        {
            Write-Host -NoNewline "   $UsableMemoryAfterFailure " -ForegroundColor Green ; Write-Host 'GB - Usable memory with 1 failure'         
        }
        else
        {
            Write-Host -NoNewline "   $UsableMemoryAfterFailure " -ForegroundColor Red ; Write-Host 'GB - Usable memory with 1 failure'  
        }      
        Write-Host '===========================================' -ForegroundColor DarkGray

        # Prints error if all nodes don't have the same amount of memory.    
        if ($Nodecheck -ne $Nodecount)
        {        
            Write-Host '  Nodes have different amounts of memory!'   -ForegroundColor Red        
            Write-Host '===========================================' -ForegroundColor DarkGray
        }
        
        # Checks if cluster is HA.    
        if ($TotalUsableVMHostMemory -le $SingleNodeMemory -and $HAMemory -gt 0)
        {       
            Write-host ' Cluster would NOT survive single failure!' -ForegroundColor Red
            Write-Host '===========================================' -ForegroundColor DarkGray       
            Write-Host " More than $HAMemory GB of memory needed to be HA"
        }
        else
        {    
            Write-Host "             Cluster is N+$Nplus" -ForegroundColor Green
        }
    }

    Write-Host '===========================================' -ForegroundColor DarkGray

    # Checks if nonclustered VMs exist and prints list.
    if ($Null -eq $NonClusteredVMsSorted)
    {
        Write-Host '          All VMs are clustered' -ForegroundColor Green
        Write-Host '===========================================' -ForegroundColor DarkGray
    }
    else
    {
        Write-Host '           Unclustered VMs Found!' -ForegroundColor Yellow
        Write-Host '-------------------------------------------' -ForegroundColor DarkGray
    }
    
    # Prints nonclustered VMs.
    foreach ($VM in $NonClusteredVMsSorted)
    {
        $VMOutput = ' ' + ($VM.ComputerName).Split('.')[0] + ' - ' + $VM.State + ' - ' + $VM.Name
        Write-Host $VMOutput -ForegroundColor Yellow
    }
    
    Write-Host '===========================================' -ForegroundColor DarkGray
}

function Get-HyperVStorageReport
{
    <#
        .SYNOPSIS
            Get-HyperVStorageReport collects Cluster Shared Volumes and prints a report of their data.
    #>
    [CmdletBinding()]
    param()

    Get-AdminCheck

    # Prints the Menu. Accepts input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host '               Hyper-V Storage Reports'                 -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host '[1]  Cluster Storage - Full report'                     -ForegroundColor White
    Write-Host '[2]  Cluster Storage - Utilization'                     -ForegroundColor White
    Write-Host '[3]  Cluster Storage - IO (2016/2019 Only)'             -ForegroundColor White
    Write-Host '[4]  Local Storage - Utilization'                       -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green    
    $MenuChoice = Read-Host 'Menu Choice'                               

    if ($MenuChoice -eq 1 -or $MenuChoice -eq 2 -or $MenuChoice -eq 3)
    {
        Write-Host `r
        Write-Host 'Pulling information for Cluster Shared Volumes...' -ForegroundColor White

        # Builds $CSVINfo to gather disk info for final report.
        try
        {
            # Variable Setup
            $OSVersion = [environment]::OSVersion.Version.Major
            $CSVs = Get-Partition | Where-Object AccessPaths -like *ClusterStorage* | Select-Object AccessPaths,DiskNumber
            if (Get-ClusterSharedVolume)
            {
                $results = foreach ($csv in $CSVs)
                {   
                    # Collecting CSV information
                    $AccessPathVolumeID = $csv.AccessPaths.Split('/')[1]
                    $ClusterPath = $csv.AccessPaths[0].TrimEnd('\')                
                    $FriendlyPath = $ClusterPath.Split('\')[2]
                    $ClusterSharedVolume = Get-ClusterSharedVolume | Select-Object -ExpandProperty SharedVolumeInfo | Where-Object FriendlyVolumeName -eq $ClusterPath | Select-Object -Property FriendlyVolumeName -ExpandProperty Partition
                    $CSVName =  (Get-ClusterSharedVolumeState | Where-Object VolumeFriendlyName -eq $FriendlyPath).Name | Get-Unique
                    $VolumeBlock = Get-Volume | Where-Object Path -like $AccessPathVolumeID

                    if ($OSVersion -ge 10)
                    {
                        $QOS = Get-StorageQosVolume | Where-Object MountPoint -eq ($ClusterPath + '\')
                        [PSCustomObject]@{
                            '#' = $csv.DiskNumber
                            Block = $VolumeBlock.AllocationUnitSize
                            CSVName = $CSVName
                            ClusterPath = $ClusterPath
                            'Size(GB)' = [math]::Round($ClusterSharedVolume.Size /1GB)
                            'Used(GB)' = [math]::Round($ClusterSharedVolume.UsedSpace /1GB)
                            'Free(GB)' = [math]::Round( ($ClusterSharedVolume.Size - $ClusterSharedVolume.UsedSpace) /1GB)
                            '% Free' = [math]::Round($ClusterSharedVolume.PercentFree, 1)
                            IOPS = $QOS.IOPS
                            Latency = [math]::Round($QOS.Latency, 2)
                            'MB/s' = [math]::Round(($QOS.Bandwidth /1MB), 1)
                        }
                    }
                    else
                    {
                        [PSCustomObject]@{
                            '#' = $csv.DiskNumber
                            Block = (Get-CimInstance -ClassName Win32_Volume | Where-Object Label -Like $VolumeBlock.FileSystemLabel).BlockSize[0]
                            CSVName = $CSVName
                            ClusterPath = $ClusterPath
                            'Size(GB)' = [math]::Round($ClusterSharedVolume.Size /1GB)
                            'Used(GB)' = [math]::Round($ClusterSharedVolume.UsedSpace /1GB)
                            'Free(GB)' = [math]::Round( ($ClusterSharedVolume.Size - $ClusterSharedVolume.UsedSpace) /1GB)
                            '% Free' = [math]::Round($ClusterSharedVolume.PercentFree, 1)
                        }
                    }
                }
            }
            else
            {
                Write-Host 'This environment does not have any clustered storage.' -ForegroundColor White
            }   
        }
        catch
        {
            Write-Host "Couldn't process Cluster Shared Volume data!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
        }         

    }
    elseif ($MenuChoice -eq 4)
    {
        Write-Host `r
        Write-Host 'Pulling information from local storage...' -ForegroundColor White

        # Collect local disk information.
        $Volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystem -ne 'CSVFS' -and $_.FileSystemLabel -notlike "*quorum*" }
        $results = foreach ($disk in $Volumes)
        {
            [PSCustomObject]@{
                Drive = $disk.DriveLetter
                Label = $disk.FileSystemLabel
                'Size(GB)' = [math]::Round($disk.Size /1GB)
                'Used(GB)' = [math]::Round( ($disk.Size - $disk.SizeRemaining) /1GB)
                'Free(GB)' = [math]::Round($disk.SizeRemaining /1GB)                
                '% Free' = [math]::Round(($disk.SizeRemaining / $disk.Size) * 100) 
            }
        }
    }

    # Prints report based on $MenuChoice.
    switch ($MenuChoice)
    {
        1 { $results | Sort-Object '#' | Format-Table * -AutoSize }
        2 { $results | Select-Object '#',CSVName,ClusterPath,'Size(GB)','Used(GB)','Free(GB)','% Free' | Sort-Object '#' | Format-Table -AutoSize }
        3 { $results | Select-Object '#',CSVName,ClusterPath,IOPS,Latency,MB/s | Sort-Object '#' | Format-Table -AutoSize }
        4 { $results | Sort-Object Drive | Format-Table -AutoSize }
        default
        { 
            Write-Host 'Incorrect Choice. Choose a number from the menu.'
            Start-Sleep -Seconds 3
            Get-HyperVStorageReport
        }
    }
}

function Get-HyperVVMInfo
{
    <#
        .SYNOPSIS
            Get-HyperVVMInfo collects Hyper-V VM info and prints report of their data.       
        
        .PARAMETER ExportToCSV
            Exports the report to specified .CSV in path.       
        
        .EXAMPLE
            C:\PS> Get-HyperVVMInfo -ExportToCSV C:\rs-pkgs\VMInfo.csv

    #>    
    [CmdletBinding()]
    param(

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [string]
        # Exports the report to specified .CSV in path.
        $ExportToCSV

    )

    Get-AdminCheck

    # Prints the Menu. Accepts input.
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host '                  Hyper-V VM Reports'                   -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host '[1]  VM vCPU and RAM' -ForegroundColor White	
    Write-Host '[2]  VM Networking' -ForegroundColor White
    Write-Host '[3]  VM VHDX Size/Location/Type' -ForegroundColor White
    Write-Host '[4]  VM VHDX IO/Latency (2016/2019 Only)' -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green    
    $MenuChoice = Read-Host 'Menu Choice'
    Write-Host `r

    # Pull Cluster node data for script.
    Write-Host 'Gathering data from VMs... ' -ForegroundColor White
    Write-Host `r
    
    $VMs = Get-HyperVVMs  
    
    # Collects information from VMs and creates $VMInfo variable with all VM info.  
    try
    {
        $results = foreach ($vm in $VMs)
        {
            if ($MenuChoice -eq 1)
            {
                [PSCustomObject]@{
                    Host = $vm.ComputerName
                    VMName = $vm.VMName
                    vCPU = $vm.ProcessorCount
                    RAM = [math]::Round($vm.MemoryStartup /1GB)                                                
                }                                                 
            }
            elseif ($MenuChoice -eq 2)
            {
                [Regex]$IPv4 = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                $VMNetworkAdapters = Get-VMNetworkAdapter -ComputerName $vm.Computername -VMName $vm.VMName
                foreach ($adapter in $VMNetworkAdapters)
                {
                    $VMNetworkAdapterVlans = Get-VMNetworkAdapterVlan -VMNetworkAdapter $Adapter
                    foreach ($adapterVlan in $VMNetworkAdapterVlans)
                    {
                        [PSCustomObject]@{
                            Host = $vm.ComputerName
                            VMName = $vm.VMName
                            IPAddress = $adapter.Ipaddresses | Select-String -Pattern $IPv4
                            VLAN = $adapterVlan.AccessVlanId
                            MAC = $adapter.MacAddress
                            vSwitch = $adapter.SwitchName
                        }
                    }
                }  
            }
            elseif ($MenuChoice -eq 3)
            {
                $Disks = Get-VMHardDiskDrive -ComputerName $vm.Computername -VMName $vm.VMName | Get-VHD -ComputerName $vm.Computername
                foreach ($disk in $Disks)
                {
                    [PSCustomObject]@{
                        VMName = $vm.VMName
                        Disk = $disk.Path
                        Size = [math]::Round($disk.FileSize /1GB)
                        PotentialSize = [math]::Round($disk.Size /1GB)
                        'VHDX Type' = $disk.VhdType
                    }
                }
            }
        }
        if ($MenuChoice -eq 4)
        {
            $OSVersion = [environment]::OSVersion.Version.Major           
            if ($OSVersion -ge 10)
            {              
                $VHDXIO = Get-StorageQoSFlow
                $results = foreach($vhdxio in $VHDXIO)
                {
                    $Latency = [math]::Round($vhdxio.InitiatorLatency, 2)
                    $Bandwidth = [math]::Round($vhdxio.InitiatorBandwidth /1MB, 2)

                    [PSCustomObject]@{
                        VMName = $vhdxio.InitiatorName
                        FilePath = $vhdxio.FilePath
                        IOPS = $vhdxio.InitiatorIOPS
                        Latency = [string]$Latency + ' ms'
                        Bandwidth = [string]$Bandwidth + ' MB/s'
                    }
                }
            }
            else
            {
                Write-Host 'This is only supported on Windows Server 2016 and up. Returning to menu.'
                Start-Sleep -s 2
                Get-HyperVVMInfo
            }
        }                      
    }
    catch
    {
        Write-Host "Couldn't collect information from the VMs!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red              
    }       

    # Prints report based on $MenuChoice.
    if ($MenuChoice -eq 1 -or $MenuChoice -eq 2)
    {
        if ($ExportToCSV)
        {
            $results | Sort-Object Host | Export-Csv -Path $ExportToCSV -NoTypeInformation
        }
        else
        {
            $results | Sort-Object Host | Format-Table -AutoSize
        }    
    }
    elseif ($MenuChoice -eq 3)
    {
        if ($ExportToCSV)
        {
            $results | Sort-Object VMName | Export-Csv -Path $ExportToCSV -NoTypeInformation
        }
        else
        {
            $results | Sort-Object VMName | Format-Table -AutoSize
        }    
    }
    elseif ($MenuChoice -eq 4)
    {
        if ($ExportToCSV)
        {
            $results | Sort-Object IOPS -Descending | Export-Csv -Path $ExportToCSV -NoTypeInformation
        }
        else
        {
            $results | Sort-Object IOPS -Descending | Format-Table -AutoSize 
        }   
    }
    else
    {
        Write-Host 'Incorrect Choice. Choose a number from the menu.'
        Start-Sleep -Seconds 3
        Get-HyperVStorageReport    
    }
    
    # Checks to see if a CSV exists at the export path.
    if ($ExportToCSV)
    {
        $TestExport = Test-Path $ExportToCSV
        if ($TestExport -eq $True)
        {
            Write-Host "Export to $ExportToCSV completed successfully."
        }
        else
        {
            Write-Host "Export to $ExportToCSV failed. Verify path and try again."
        }
    }
}


function Get-HyperVStorageCleanupAnalyzer
{
    <#
        .SYNOPSIS
            Get-HyperVStorageCleanupAnalyzer goes through the Hyper-V environment looking for things taking up space.       
    #>   
    [CmdletBinding()]
    param()
    
    Get-AdminCheck

    # Script to pull the number of DiskShadows that are currently on the Hyp.
    $GetHyperVDiskShadows = {
        
        # HyperVDiskShadows    
        $DiskShadowScript = $env:TEMP + '\Temp.dsh'
        'list shadows all' | Set-Content $DiskShadowScript
        $DiskShadows = diskshadow /s $DiskShadowScript
        [String]$NoDiskShadowCheck = $DiskShadows | Select-String -SimpleMatch 'No shadow copies found in system.'
        if ($NoDiskShadowCheck -like '*No*')
        {
            [String]$NumberOfDiskShadows = 0    
        }
        else
        {
            [String]$DiskShadowInfo = $DiskShadows | Select-String -SimpleMatch 'Number of shadow copies listed:'
            [String]$NumberOfDiskShadows = $DiskShadowInfo.Split('')[5]
        }
    
        [PSCustomObject]@{
                DiskShadows = $NumberOfDiskShadows
        }    
    }

    # Script to check all VMs to verify they don't have Save as the Automatic Stop Action.
    $GetHyperVStopAction = {

        # HyperVStopAction
        [int]$SaveActionCheck = 0
        foreach ($vm in $VMs)
        {
            if ($vm.AutomaticStopAction -eq 'Save')
            {
                $SaveActionCheck = $SaveActionCheck + 1
                [PSCustomObject]@{
                    VMName = $vm.VMName
                    StopAction = $vm.AutomaticStopAction
                }
            }    
        }
    }

    # Script to check the environment for any Checkpoints that exist.
    $GetHyperVVMCheckpoints = {

        # HyperVCheckpoints
        if (Get-ClusterNode)
        {
            Get-VMSnapshot -ComputerName (Get-ClusterNode) -VMName *
        }
        else
        {
            Get-VMSnapshot -VMName *
        }  
    }

    # Script to pull all VM disks and check to see if they are an avhdx.
    $GetHyperVVMAVHDX = {
    
        # GetHyperVVMAVHDX
        if (Get-ClusterNode)
        {
            $VMs = Get-VM -ComputerName (Get-ClusterNode)    
        }
        else
        {
            $VMs = Get-VM
        }

        foreach ($vm in $VMs)
        {
            $VMDisks = Get-VMHardDiskDrive -ComputerName $vm.Computername -VMName $vm.VMName | Get-VHD -ComputerName $vm.Computername
            foreach ($disk in $VMDisks)
            {
                if ($disk.Path -like '*.avhdx' -or $disk.Path -like '*.avhd' )
                {
                    [PSCustomObject]@{
                        VMName = $vm.Name
                        Path = $disk.Path
                    }                 
                }     
            }      
        }    
    }

    # Script to pull all VM disks and check to see if they are not being used.
    $GetHyperVUnusedVHDXs = {
        
        # HyperVUnusedVHDX
        $AllVMDiskRoots = [System.Collections.ArrayList]@()
        if (Get-ClusterNode)
        {
            $VMs = Get-VM -ComputerName (Get-ClusterNode)    
        }
        else
        {
            $VMs = Get-VM
        }
        foreach ($vm in $VMs)
        {
            $VMDisks = Get-VMHardDiskDrive -ComputerName $vm.Computername -VMName $vm.VMName | Get-VHD -ComputerName $vm.Computername
            foreach ($disk in $VMDisks)
            {
                if ($disk.Path -like '*.vhdx' -or $disk.Path -like '*.vhd')
                {
                    $AllVMDiskRoots += $disk.Path.ToLower()
                }
                elseif ($disk.Path -like '*.avhdx' -or $disk.Path -like '*.avhd')
                {
	                $Path = $disk.Path
                    while($Path = (Get-VHD -Path $Path).ParentPath)
	                {
		                $AllVMDiskRoots += $Path.ToLower()
	                }
                }     
            }
        }

        # Collect all VHDXs on clustered and unclustered storage.   
        $LocalDriveLetters = (Get-Volume).DriveLetter  
        $LocalVHDXDataPull = [System.Collections.ArrayList]@() 
        $LocalVHDXDataPull += foreach ($driveLetter in $LocalDriveLetters)
        {
            (Get-ChildItem -Path ($driveLetter + ':\') -Include '*.vhdx','*.vhd' -Recurse -ErrorAction SilentlyContinue ).FullName 
        }  
    
        $AllVHDXs = [System.Collections.ArrayList]@()
        $AllVHDXs = $LocalVHDXDataPull.Where({$_ -ne $null})        
        
        # Compare the list of all VHDXs to the list of VHDXs in use and then create a list of VHDXs not in use by any VMs.
        foreach ($vhdx in $AllVHDXs)
        {
            if ( -not ( $AllVMDiskRoots.Contains($vhdx.ToLower()) ))
            {
                [PSCustomObject]@{
                    UnusedVHDX = $vhdx
                }
            }
        }     
    }

    # Script to collect all HRLs on clustered and unclustered storage. 
    $GetHyperVHRL = {
      
        # HyperVHRL
        $LocalHRLDataPull = [System.Collections.ArrayList]@()
        $AllHRLs = [System.Collections.ArrayList]@()
        $LocalDriveLetters = (Get-Volume).DriveLetter   
        $LocalHRLDataPull += foreach ($driveLetter in $LocalDriveLetters)
        {
            Get-ChildItem -Path ($driveLetter + ':\') -Filter '*.hrl' -Recurse -ErrorAction SilentlyContinue
        }

        $AllHRLs = $LocalHRLDataPull.Where({$_ -ne $null})

        # Check to see if any hrl files are larger than 5GB.
        foreach ($hrl in $AllHRLs)
        {
            if ( ($hrl.Length -gt 5368706371) -or ((Get-Date).AddDays(-7)) -ge ($hrl.LastWriteTime | Get-Date -Format d) )
            {
                [PSCustomObject]@{
                    FullName = $hrl.FullName
                    Size = [math]::Round($hrl.Length /1GB)
                    LastWritten = $hrl.LastWriteTime | Get-Date -Format d
                }
            }
        }    
    }

    # Collect all VHDX.tmp files on clustered and unclustered storage. 
    $GetHyperVVHDXTemp = {
     
        # HyperVVHDXTmp
        $LocalTmpVHDXDataPull = [System.Collections.ArrayList]@()
        $LocalDriveLetters = (Get-Volume).DriveLetter   
        $LocalTmpVHDXDataPull += foreach ($driveLetter in $LocalDriveLetters)
        {
            (Get-ChildItem -Path ($driveLetter + ':\') -Include '*.vhdx.tmp','*.vhd.tmp' -Recurse -ErrorAction SilentlyContinue ).FullName
        }
    
        # Clean the $null values out of the data pull and output the clean data as a PSObject.
        $AllTmpVHDXs = [System.Collections.ArrayList]@()
        $AllTmpVHDXs = $LocalTmpVHDXDataPull.Where({$_ -ne $null})
        if ($AllTmpVHDXs)
        {
            foreach ($tmpVHDX in $AllTmpVHDXs)
            {
                [PSCustomObject]@{
                    'VHDXtmp' = $tmpVHDX 
                }
            }
        }    
    }

    # Clear any old jobs out. 
    Get-Job | Where-Object Command -like *HyperV* | Remove-Job -Force   
         
    # Use PSJobs to launch all of the scripts at the same time.
    Start-Job -ScriptBlock $GetHyperVDiskShadows | Out-Null
    Start-Job -ScriptBlock $GetHyperVStopAction | Out-Null
    Start-Job -ScriptBlock $GetHyperVVMCheckpoints | Out-Null
    Start-Job -ScriptBlock $GetHyperVVMAVHDX | Out-Null
    #Start-Job -ScriptBlock $GetHyperVUnusedVHDXs | Out-Null -  Removing this feature until I can work out the bugs with getting the primary VHDX of VMs with a backup chain straightened out.
    Start-Job -ScriptBlock $GetHyperVHRL | Out-Null
    Start-Job -ScriptBlock $GetHyperVVHDXTemp | Out-Null  

    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for Disk Shadows...' -ForegroundColor White
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    # Collect diskshadows from the job and assign to $HyperVDiskShadows.
    $HyperVDiskShadows = Get-Job | Where-Object Command -like *HyperVDiskShadows* | Wait-Job | Receive-Job  
    $NumberOfDiskShadows = ($HyperVDiskShadows).Diskshadows
    if ( $NumberOfDiskShadows -eq '0' )
    {
        Write-Host 'No Disk Shadows found.' -ForegroundColor Green 
    }
    else
    {
        Write-Host "$NumberOfDiskShadows Disk Shadows found!" -ForegroundColor Yellow 
    }

    Write-Host `r
    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for VMs with their Automatic Stop Action set to Save...' -ForegroundColor White
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    # Collect VM Stop Action from the job and assign to $HyperVSaveAction.
    $HyperVStopAction = Get-Job | Where-Object Command -like *HyperVStopAction* | Wait-Job | Receive-Job  
    $VMsWithStopAction = ($HyperVStopAction).VMName
    if ( $VMsWithStopAction.Count -eq '0' )
    {
        Write-Host 'No VMs with Save set as the Automatic Stop Action found.' -ForegroundColor Green 
    }
    else
    {
        $VMsWithStopAction | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    }

    Write-Host `r
    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for Checkpoints...' -ForegroundColor White
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    # Collect checkpoints from the job and assign to $HyperVDiskShadows.
    $HyperVCheckpoints = Get-Job | Where-Object Command -like *HyperVCheckpoints* | Wait-Job | Receive-Job  
    $VMSnapshots = $HyperVCheckpoints
    if ($VMSnapshots)
    {
       $VMSnapshots | ForEach-Object { Write-Host "$($_.VMName) - $($_.CreationTime)" -ForegroundColor Yellow }
    }
    else
    {
        Write-Host 'No Checkpoints found.' -ForegroundColor Green      
    }

    Write-Host `r 
    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for AVHDXs...' -ForegroundColor White 
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    # Collect AVHDXs from the job and assign to $HyperVVMAVHDX.
    $HyperVVMAVHDX = Get-Job | Where-Object Command -like *GetHyperVVMAVHDX* | Wait-Job | Receive-Job  
    $VMAVHDXs = $HyperVVMAVHDX
    if ($VMAVHDXs)
    {
       $VMAVHDXs | ForEach-Object { Write-Host "$($_.VMName) - $($_.Path)" -ForegroundColor Yellow }
    }
    else
    {
        Write-Host 'No AVHDXs found.' -ForegroundColor Green      
    }
     
    Write-Host `r
    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for hrl files that are larger than 5GB...' -ForegroundColor White
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    # Collect HRL files from the job and assign to $HyperVHRL.
    $HyperVHRL = Get-Job | Where-Object Command -like *HyperVHRL* | Wait-Job | Receive-Job  
    $HRLs = $HyperVHRL | Where-Object Size -gt 5
    if ($HRLs)
    {
        foreach ($hrl in $HRLs)
        {
            Write-Host "$($Hrl.Size) GB - $($hrl.FullName)" -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host 'All hrl files smaller than 5GBs.' -ForegroundColor Green
    }

    Write-Host `r
    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for hrl files that are older than a week...' -ForegroundColor White
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    $HRLs = $HyperVHRL
    if ($HRLs)
    {
        foreach ($hrl in $HRLs)
        {
            if (((Get-Date).AddDays(-7)) -ge ($hrl.LastWritten | Get-Date -Format d))
            {            
                Write-Host "$($Hrl.LastWritten) - $($Hrl.Size) GB - $($hrl.FullName)" -ForegroundColor Yellow
            }           
        }            
    }
    else
    {
        Write-Host 'All hrls are newer than a week.' -ForegroundColor Green
    }

    Write-Host `r
    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for VHDX.tmp files...' -ForegroundColor White
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    # Collect VHDX.tmp from the job and assign to $HyperVVHDXTmp
    $HyperVVHDXTmp = Get-Job | Where-Object Command -like *HyperVVHDXTmp* | Wait-Job | Receive-Job  
    $TmpVHDXs = $HyperVVHDXTmp
    if ($TmpVHDXs)
    {
        foreach ($tmpVHDX in $TmpVHDXs)
        {
            Write-Host $tmpVHDX.vhdxtmp -ForegroundColor Yellow
        }
    }
    else
    {        
        Write-Host 'No VHDX.tmp files found.' -ForegroundColor Green
    }

    <# Removing this feature until I can work out the bugs with getting the primary VHDX of VMs with a backup chain straightened out.
    Write-Host `r
    Write-Host `r
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White
    Write-Host 'Checking for VHDXs that are not in use...' -ForegroundColor White
    Write-Host '-----------------------------------------------------------------' -ForegroundColor White

    # Collect unused vHDXs from the job and assign to $HyperVUnusedVHDX.
    $HyperVUnusedVHDX = Get-Job | Where-Object Command -like *HyperVUnusedVHDX* | Wait-Job | Receive-Job    
    $UnusedVHDXs = ($HyperVUnusedVHDX).UnusedVHDX   
    if ($UnusedVHDXs)
    {
        foreach ($unusedVHDX in $UnusedVHDXs)
        {
            Write-Host $unusedVHDX -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host 'No unused VHDXs found.' -ForegroundColor Green
    }
    #>
}