$ErrorActionPreference = "Stop"

try { 
    Install-Module pester -force -Confirm:$false -Scope CurrentUser -SkipPublisherCheck
} Catch {}
try {
    $ECode = 0

    Set-Location $ENV:GITHUB_WORKSPACE\Test\
    Import-Module Pester -Force

    $outputfolder = "$PSScriptRoot\PesterOutput\"
    New-Item $outputfolder -Force -ItemType Directory
    $results = Invoke-Pester  -PassThru -Path  "$PSScriptRoot\Service-Path-Enumeration-TestCases.ps1" 
} catch {
    Write-Host "Something failed during script execution. Error: $_" -ForegroundColor Red
} Finally {
    if ($results.FailedCount -gt 0) {
        Write-Host "Failed tests: $($results.FailedCount)"
        $logs = @(
            "$PSScriptRoot\ScriptOutput\Silent_True_Log.txt",
            "$PSScriptRoot\ScriptOutput\Service_Log.txt",
            "$PSScriptRoot\ScriptOutput\Software_Log.txt",
            "$PSScriptRoot\ScriptOutput\Silent_False_Log.txt",
            "$PSScriptRoot\ScriptOutput\SoftwareServicesAndFixEnv.txt"
        )
        Foreach ($LogPath in $logs){
            if (Test-Path $LogPath){
                Write-Host ">>> Log file '$LogPath' content:"
                Get-Content $LogPath
            } else {
                Write-Host ">>> Log File '$LogPath' not found"
            }
        }
        $ECode = 2
    } elseif ($results.TotalCount -eq 0){
        Write-Host "Tests not started..."
        $ECode = 3
    }
}

Exit $ECode