function Get-ClusterCheck{
    [CmdletBinding()]
    param(
    )
    $ClusterCheckTest = $False
    $ClusterCheckTest = Get-Cluster -ErrorAction SilentlyContinue
    if($ClusterCheckTest){
        $Script:ClusterCheck = $True
    } else {
        $Script:ClusterCheck = $False
    }
}

function Get-HyperVReports{
    [CmdletBinding()]
    param(
    )
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "                   Hyper-V Reports"                     -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "[1]  Get-HyperVLogs" -ForegroundColor White
    Write-Host "[2]  Get-MaintenanceQC" -ForegroundColor White
    Write-Host "[3]  Get-CAULogs" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    $MenuChoice = Read-Host "Please select menu number"
    if($MenuChoice -eq 1){
        Get-HyperVLogs
    } elseif($MenuChoice -eq 2){
        Get-MaintenanceQC
    } elseif($MenuChoice -eq 3){
        Get-CAULogs
    } else {
        Clear-Host
        Write-Host "Incorrect Choice. Choose a number from the menu."
        Start-Sleep -s 3
        Get-HyperVReports
    }
}

function Get-CAULogs{
    [CmdletBinding()]
    param(
    )
    $FormatEnumerationLimit = -1

    #Variables
    $Cluster = (Get-Cluster).Name
    $CAUDates = ((Get-WinEvent -LogName *ClusterAwareUpdating*).TimeCreated | Get-Date -Format MM/dd/yyy) | Get-Unique
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

function Get-HyperVLogs{
    [CmdletBinding()]
    param(
        [DateTime]$StartDate,
        [DateTime]$EndDate,
        [String]$Messagetxt
    )
        #Variables
        $StartDate = $Null
        $EndDate = $Null
        $MessageTxt = $Null
        $ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue
        
        # Prints the Menu. Accepts input.
        Clear-Host
            
        if($StartDate -eq $Null){
            Write-Host -------------------------------------------------------- -ForegroundColor Green
            Write-Host "           Hyper-V Cluster Event Log Search"            -ForegroundColor White
            Write-Host -------------------------------------------------------- -ForegroundColor Green
            Write-Host "[1]  Search last 24 hours" -ForegroundColor White
            Write-Host "[2]  Specify date range" -ForegroundColor White
            Write-Host -------------------------------------------------------- -ForegroundColor Green
            $MenuChoice = Read-Host "Please select menu number"
        }
        
        # Collects information for filter.
        if($StartDate -eq $Null){
            $MessageTxt = Read-Host "Enter text to filter the Event Logs by VM Name or Event log text"
            if($MenuChoice -eq 1){
                $StartDate = (Get-Date).AddDays(-1)   
                $EndDate = (Get-Date).AddDays(1)   
            } elseif($MenuChoice -eq 2){
                    $DateFormat = Get-Date -Format d
                    Write-Host "The date format for this environment is '$DateFormat'." -ForegroundColor Yellow
                    $StartDate = Read-Host "Enter earliest search date."
                    $EndDate = Read-Host "Enter latest search date."
            }
        }

        # Filter for log collection.
        $Filter = @{
            LogName = "*Hyper-V*"
            StartTime = $StartDate
            EndTime = $EndDate
        }

        # Checks for cluster and chooses appropriate script.
        Write-Host `n
        if($ClusterCheck -ne $True){
            ForEach($Node in $ClusterNodes){
                Write-Host $Node -ForegroundColor Green
                Get-WinEvent -ComputerName $Node -FilterHashtable $Filter | Where-Object -Property Message -like "*$MessageTxt*" | Select-Object TimeCreated,ProviderName,Message | Sort-Object TimeCreated | Format-List
            }
        } elseif ($ClusterCheck -eq $False) {
            Write-Host $env:COMPUTERNAME -ForegroundColor Green
            Get-WinEvent -FilterHashtable $Filter | Where-Object -Property Message -like "*$MessageTxt*" | Select-Object TimeCreated,ProviderName,Message | Sort-Object TimeCreated | Format-List
        }
}
