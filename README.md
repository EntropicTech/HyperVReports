# HyperVReports

This script is a collection of information reports about single node and clustered Hyper-V environments. It quickly provides insight into various aspects of the environment including:

 * Parsing the Hyper-V logs for a single node or across a cluster
 * N+1 Maintenance QC
 * Cluster Aware Update report
 * Clustered Shared Volume IO and utilization
 * Informational reports for VMs
 * Analyze local and clustered storage for anything taking up space that isn't needed

## Getting Started

The Preferred method is to install directly from the PSGallery.

```
# Set your current PowerShell session to use TLS1.2. This is a requirement for the PSGallery.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Install the HyperVReports module.
Install-Module -Name HyperVReports -Force -AllowClobber

# If it's already installed then you just need to update it.
Update-Module -Name HyperVReports -Force
```

## Get-HyperVReports

Brings up menu to choose desired report.

```
--------------------------------------------------------
                   Hyper-V Reports
--------------------------------------------------------
[1]  Hyper-V Cluster Log Search
[2]  Maintenance QC
[3]  Cluster Aware Update History
[4]  Storage Reports
[5]  VM Reports
[6]  Storage Cleanup Analyzer
--------------------------------------------------------
Menu Choice: 
```

## Get-HyperVClusterLogs

Filter the Hyper-V Cluster logs by time range and error text.

```
--------------------------------------------------------
           Clustered Hyper-V Eventlog Search
--------------------------------------------------------
[1]  Search last 24 hours
[2]  Search last 48 hours
[3]  Search last 7 days
[4]  Specify date range to search
--------------------------------------------------------
Please select menu number: 1
--------------------------------------------------------------------------------------------------------------------------------------
                                               Clustered Hyper-V Eventlog Search
--------------------------------------------------------------------------------------------------------------------------------------
Search results for: RDP

ET-HV-01

TimeCreated  : 4/14/2019 7:55:18 AM
ProviderName : Microsoft-Windows-Hyper-V-Worker
Message      : 'ET-RDP-01' was reset by the guest operating system. (Virtual machine ID 7D563560-D084-404F-9409-6D7D053CFEB3)

TimeCreated  : 4/14/2019 7:55:38 AM
ProviderName : Microsoft-Windows-Hyper-V-Chipset
Message      : 'ET-RDP-01' successfully booted an operating system. (Virtual machine ID 7D563560-D084-404F-9409-6D7D053CFEB3)


ET-HV-02

TimeCreated  : 4/14/2019 7:55:18 AM
ProviderName : Microsoft-Windows-Hyper-V-Worker
Message      : 'ET-RDP-01' was reset by the guest operating system. (Virtual machine ID 7D563560-D084-404F-9409-6D7D053CFEB3)

TimeCreated  : 4/14/2019 7:55:38 AM
ProviderName : Microsoft-Windows-Hyper-V-Chipset
Message      : 'ET-RDP-01' successfully booted an operating system. (Virtual machine ID 7D563560-D084-404F-9409-6D7D053CFEB3)
```

## Get-HyperVMaintenanceQC

Verifies that the cluster can sustain a single node failure and that all VMs are clustered.
```
===========================================
         EntropicClus has 4 nodes.
===========================================
  1024 GB - Physical memory of cluster.
  256 GB - Physical memory of each node.
  200 GB - Useable memory with 1 failure.
===========================================
 Cluster would NOT survive single failure!
-------------------------------------------
 More than 56 GB of memory needed to be HA.
===========================================
          All VMs are clustered.
-------------------------------------------
```

## Get-HyperVCAULogs

Shows report of dates CAU was performed and then pulls the CAU logs and hotfixes installed for selected date.
```
--------------------------------------------------------
Dates CAU was performed:
--------------------------------------------------------
04/07/2019
03/24/2019
03/17/2019
03/14/2019
02/08/2019
02/07/2019
01/05/2019
12/01/2018
11/08/2018
11/03/2018
09/22/2018
09/08/2018
09/01/2018
08/04/2018
07/29/2018
07/20/2018
05/13/2018
--------------------------------------------------------
Which date would you like the logs from: 03/24/2019

Collecting CAU logs and hotfix information...

CAU logs from 03/24/2019 for EntropicClus.
--------------------------------------------------------

TimeCreated          Message                                                                                                                              
-----------          -------                                                                                                                              
3/24/2019 4:00:04 AM Starting CAU run {32FE9A85-A946-48AE-9E95-E33F8732807E} on cluster EntropicClus.                                                     
3/24/2019 4:00:19 AM Ignoring WUA warning The computer needs to be rebooted to complete past installation. The result of search may be incorrect. 0x240005
3/24/2019 4:00:19 AM Scan for updates succeeded. Found 2 updates                                                                                          
3/24/2019 4:00:26 AM Ignoring WUA warning The computer needs to be rebooted to complete past installation. The result of search may be incorrect. 0x240005
3/24/2019 4:22:41 AM Download for updates succeeded. Downloaded 2 updates                                                                                 
3/24/2019 4:23:35 AM Node ET-HV-01 entered node maintenance mode.                                                                                         
3/24/2019 4:24:07 AM Ignoring WUA warning The computer needs to be rebooted to complete past installation. The result of search may be incorrect. 0x240005
3/24/2019 5:16:09 AM Install for updates succeeded. Installed 2 updates                                                                                   
3/24/2019 5:16:10 AM Rebooting node ET-HV-01.                                                                                                             
3/24/2019 5:57:43 AM Node ET-HV-01 has rebooted successfully.                                                                                             
3/24/2019 5:58:05 AM Scan for updates succeeded. Found 1 updates                                                                                          
3/24/2019 5:58:46 AM Download for updates succeeded. Downloaded 1 updates                                                                                 
3/24/2019 5:58:58 AM Install for updates succeeded. Installed 1 updates                                                                                   
3/24/2019 5:59:03 AM Scan for updates succeeded. Found 0 updates                                                                                          
3/24/2019 5:59:03 AM Node ET-HV-01 exited node maintenance mode.                                                                                          
3/24/2019 5:59:11 AM Starting CAU run {32FE9A85-A946-48AE-9E95-E33F8732807E} on cluster EntropicClus.                                                     
3/24/2019 5:59:20 AM Scan for updates succeeded. Found 2 updates                                                                                          
3/24/2019 6:27:40 AM Download for updates succeeded. Downloaded 2 updates                                                                                 
3/24/2019 6:28:45 AM Node ET-HV-02 entered node maintenance mode.                                                                                           
3/24/2019 6:45:30 AM Install for updates succeeded. Installed 2 updates                                                                                   
3/24/2019 6:45:31 AM Rebooting node ET-HV-02.                                                                                                               
3/24/2019 6:52:59 AM Node ET-HV-02 has rebooted successfully.                                                                                               
3/24/2019 6:53:15 AM Node ET-HV-02 exited node maintenance mode.                                                                                            
3/24/2019 6:53:15 AM Scan for updates succeeded. Found 0 updates                                                                                          
3/24/2019 6:53:15 AM CAU run {32FE9A85-A946-48AE-9E95-E33F8732807E} on cluster EntropicClus completed successfully.                                       


Updates installed during this CAU run.
--------------------------------------------------------

Source   Description HotFixID  InstalledBy         InstalledOn          
------   ----------- --------  -----------         -----------          
ET-HV-01 Update      KB4489889 NT AUTHORITY\SYSTEM 3/24/2019 12:00:00 AM
ET-HV-02 Update      KB4489889 NT AUTHORITY\SYSTEM 3/24/2019 12:00:00 AM
```

## Get-HyperVStorageReport

Pulls various reports for the Cluster Shared Volumes

```
--------------------------------------------------------
               Hyper-V Storage Reports
--------------------------------------------------------
[1]  Cluster Storage - Full report
[2]  Cluster Storage - Utilization
[3]  Cluster Storage - IO (2016/2019 Only)
[4]  Local Storage - Utilization
--------------------------------------------------------
Menu Choice: 1

# Block ClusterPath               Used(GB) Size(GB) Free % IOPS Latency MB/s
- ----- -----------               -------- -------- ------ ---- ------- ----
1 65536 C:\ClusterStorage\Volume2      978     1000    2.2  929   11.89  5.7
```

## Get-HyperVVMInfo

Prints various reports for the VMs

```
--------------------------------------------------------
                  Hyper-V VM Reports
--------------------------------------------------------
[1]  VM vCPU and RAM
[2]  VM Networking
[3]  VM VHDX Size/Location/Type
[4]  VM VHDX IO/Latency (2016/2019 Only)
--------------------------------------------------------
Menu Choice: 1

Host     VMName        vCPU RAM IPAddress     VLAN MAC          vSwitch  
----     ------        ---- --- ---------     ---- ---          -------  
ET-HV-01 ET-DC-2        2   2 192.168.0.60    0    00155D0A0C55 SETswitch
ET-HV-01 ET-RDP-01      4   4 192.168.0.18    0    00155D002027 SETswitch
ET-HV-01 ET-DC-01       2   2 192.168.0.20    0    00155D002021 SETswitch
ET-HV-01 ET-FS-01       4   4 192.168.0.7     0    00155D0A0C51 SETswitch
ET-HV-01 ET-RDP-03      4   4 192.168.0.25    0    00155D002026 SETswitch
ET-HV-02 ET-QB-01       8   8 192.168.0.23    0    00155D002023 SETswitch
ET-HV-02 ET-RDP-02      4   4 192.168.0.45    0    00155D0A0C54 SETswitch
```

## Get-HyperVStorageCleanupAnalyzer

Checks environment for things taking up space that might be able to be addressed to recover space.

```
-----------------------------------------------------------------
Checking for Disk Shadows...
-----------------------------------------------------------------
No Disk Shadows found.


-----------------------------------------------------------------
Checking for VMs with their Automatic Stop Action set to Save...
-----------------------------------------------------------------
No VMs with Save set as the Automatic Stop Action found.


-----------------------------------------------------------------
Checking for Checkpoints...
-----------------------------------------------------------------
ET-SVR-01 - 11/06/2018 20:03:19


-----------------------------------------------------------------
Checking for AVHDXs...
-----------------------------------------------------------------
ET-SVR-01 - C:\ClusterStorage\Volume2\VMs\516791-Helios\516791-HELIOS_94504D42-8991-4B10-B5C6-E99AC0E3EC0F.avhd


-----------------------------------------------------------------
Checking for hrl files that are larger than 5GB...
-----------------------------------------------------------------
All hrl files smaller than 5GBs.


-----------------------------------------------------------------
Checking for hrl files that are older than a week...
-----------------------------------------------------------------
All hrls are newer than a week.


-----------------------------------------------------------------
Checking for VHDX.tmp files...
-----------------------------------------------------------------
No VHDX.tmp files found.


-----------------------------------------------------------------
Checking for VHDXs that are not in use...
-----------------------------------------------------------------
C:\ClusterStorage\Volume1\VMs\Backup.vhd
C:\ClusterStorage\Volume1\VMs\OS.vhdx
```
