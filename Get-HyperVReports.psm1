#Variables
$ClusterCheck = $Null

function Get-ClusterCheck{
    #Checks to see if Get-Cluster is working to validate that this is a clustered node.
    [CmdletBinding()]
    param(
        [bool]$ClusterCheckTest
    )
    $ClusterCheckTest = $False
    $ClusterCheckTest = Get-Cluster -ErrorAction SilentlyContinue
    if($ClusterCheckTest){
        $Script:ClusterCheck = $True
        } Else {
            $Script:ClusterCheck = $False
            Write-Host "Get-Cluster didn't return information. Goodbye."
            break
        }

}

function Get-HyperVReports{
    Clear-Host
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "                   Hyper-V Reports"                     -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    Write-Host "[1]  Get-Clusterlogs" -ForegroundColor White
    Write-Host "[2]  Get-MaintenanceQC" -ForegroundColor White
    Write-Host -------------------------------------------------------- -ForegroundColor Green
    $MenuChoice = Read-Host "Please select menu number"
    if($MenuChoice -eq 1){
        Get-Clusterlogs
    } elseif($MenuChoice -eq 2){
        Get-MaintenanceQC
    }
}
