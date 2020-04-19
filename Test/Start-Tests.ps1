$outputfolder = "$PSScriptRoot\PesterOutput\"
New-Item $outputfolder -Force -ItemType Directory
$results = Invoke-Pester -Script "$PSScriptRoot\Service-Path-Enumeration-TestCases.ps1" -OutputFormat NUnitXml `
                         -OutputFile "$outputfolder\Services-And-Software-Verification.xml" -PassThru
if ($results.FailedCount -gt 0) {
    Write-Host "Tests failed..."
    Exit 2
}