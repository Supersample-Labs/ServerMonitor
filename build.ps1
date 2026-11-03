$ErrorActionPreference = 'Stop'
$projectFile = Join-Path $PSScriptRoot 'ServerMonitor.csproj'
$publishFolder = Join-Path $PSScriptRoot 'Release/ServerMonitor-win-x64'
dotnet publish $projectFile -c Release -r win-x64 --self-contained true -o $publishFolder
if ($LASTEXITCODE -ne 0) { throw 'Publishing failed.' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $publishFolder
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'THIRD-PARTY-NOTICES.txt')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'THIRD-PARTY-NOTICES.txt') -Destination $publishFolder
}
Write-Host "Published self-contained Windows x64 app: $publishFolder"
