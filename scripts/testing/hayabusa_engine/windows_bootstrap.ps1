# Run only in an ephemeral GitHub-hosted windows-2022 job, never on a lab/production host.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ArtifactDirectory,
      [Parameter(Mandatory)][string]$ReportDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This bootstrap only supports disposable GitHub-hosted runners.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated ephemeral Windows runner is required to export Security.evtx.'
}
$work = Join-Path $env:RUNNER_TEMP ('hayabusa-windows-' + [Guid]::NewGuid().ToString('N'))
$distro = 'HayabusaTest-' + [Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $work, $ReportDirectory -Force | Out-Null
$client = $null
$server = $null
$imported = $false
function Download-Verified([string]$Url, [string]$Destination, [string]$Sha256) {
    Invoke-WebRequest -Uri $Url -OutFile $Destination
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant() -ne $Sha256) {
        throw ('Checksum mismatch: ' + [IO.Path]::GetFileName($Destination))
    }
}
function Start-QuietProcess([string]$Executable, [string[]]$Arguments) {
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $psi.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $null = $process.Start()
    # Drain output asynchronously but never publish raw client/server logs or keys.
    $null = $process.StandardOutput.ReadToEndAsync()
    $null = $process.StandardError.ReadToEndAsync()
    return $process
}
function Linux-Path([string]$Path) {
    $normalized = $Path.Replace('\', '/')
    $result = & wsl.exe -d $distro --exec wslpath -a $normalized
    if ($LASTEXITCODE -ne 0) { throw 'Unable to translate Windows path for WSL.' }
    return ($result | Out-String).Trim()
}
try {
    Download-Verified 'https://cloud-images.ubuntu.com/wsl/releases/22.04/current/ubuntu-jammy-wsl-amd64-wsl.rootfs.tar.gz' (Join-Path $work 'rootfs.tar.gz') 'de9f6149da07b90350a3ccd94b4858b82fef71f0ec2982acb93de583c4c87585'
    Download-Verified 'https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-windows-amd64.exe' (Join-Path $work 'velociraptor.exe') '686e4f5888fdd66d07ace3b6c1cbd7d2dd0d8d5fb4d3b5d905a7df3341dfb86f'
    Download-Verified 'https://raw.githubusercontent.com/omerbenamram/evtx/8930398ff61c56bdc0f8ab5781e4093ee34d9026/samples/security.evtx' (Join-Path $work 'security.evtx') '5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d'
    Download-Verified 'https://github.com/Yamato-Security/hayabusa/releases/download/v4.3.0/hayabusa-4.3.0-win-x64-live-response.zip' (Join-Path $work 'hayabusa-live-response.zip') 'a4a84bd39c8f3943c96c7a4783927de98f21529ae4780a73cabae90562700783'
    $fixtureDirectory = Join-Path $work 'endpoint-fixture'
    New-Item -ItemType Directory -Path $fixtureDirectory | Out-Null
    Copy-Item -LiteralPath (Join-Path $work 'security.evtx') -Destination $fixtureDirectory
    $preflight = Join-Path $work 'hayabusa-preflight'
    Expand-Archive -LiteralPath (Join-Path $work 'hayabusa-live-response.zip') -DestinationPath $preflight
    $nativeVersion = & (Join-Path $preflight 'hayabusa-4.3.0-win-x64.exe') dfir-timeline --help
    if ($LASTEXITCODE -ne 0 -or ($nativeVersion | Out-String) -notmatch '4\.3\.0') { throw 'Native Windows Hayabusa version preflight failed.' }
    $nativeVersion = (($nativeVersion | Out-String) -split "`n" | Where-Object { $_ -match '^Hayabusa v4\.3\.0' } | Select-Object -First 1).Trim()
    Remove-Item -LiteralPath $preflight -Recurse -Force
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $work 'velociraptor.exe')
    if ($signature.Status -ne 'Valid') { throw 'Windows Velociraptor Authenticode verification failed.' }
    [IO.File]::WriteAllText((Join-Path $work 'corrupt.evtx'), 'Deliberately invalid EVTX for failure-path testing.')
    & wsl.exe --import $distro (Join-Path $work 'wsl') (Join-Path $work 'rootfs.tar.gz') --version 1
    if ($LASTEXITCODE -ne 0) { throw 'WSL1 import failed.' }
    $imported = $true
    # The pinned Canonical manifest includes Python3, PyYAML, CA certificates and libpcre3.
    & wsl.exe -d $distro --exec python3 -c 'import yaml, ssl; print("WSL Python dependencies ready")'
    if ($LASTEXITCODE -ne 0) { throw 'Pinned WSL rootfs dependencies unavailable.' }
    $scriptLinux = Linux-Path (Join-Path $PSScriptRoot 'windows_wsl.py')
    $sharedLinux = Linux-Path $work
    $artifactLinux = Linux-Path $ArtifactDirectory
    $server = Start-QuietProcess 'wsl.exe' @('-d', $distro, '--exec', 'python3', $scriptLinux,
        '--shared', $sharedLinux, '--windows-shared', $work, '--artifacts', $artifactLinux)
    $deadline = [DateTime]::UtcNow.AddMinutes(4)
    while (-not (Test-Path (Join-Path $work 'ready'))) {
        if ($server.HasExited) { throw 'Linux frontend bootstrap failed; inspect sanitized report.' }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Linux frontend readiness timeout.' }
        Start-Sleep -Seconds 1
    }
    # Add a benign, identifiable Application log record on this disposable runner.
    & eventcreate.exe /T INFORMATION /ID 100 /L APPLICATION /SO HayabusaIntegration /D 'Ephemeral Windows to Linux Hayabusa integration test' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create test Application event.' }
    $client = Start-QuietProcess (Join-Path $work 'velociraptor.exe') @('-c', (Join-Path $work 'client.config.yaml'), 'client')
    $deadline = [DateTime]::UtcNow.AddMinutes(32)
    while (-not $server.HasExited) {
        if ($client.HasExited) { throw 'Windows Velociraptor client exited prematurely.' }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Windows integration timeout.' }
        Start-Sleep -Seconds 2
    }
    if ($server.ExitCode -ne 0) { throw 'Linux integration assertions failed; inspect sanitized report.' }
    $report = Get-Content -Raw (Join-Path $work 'windows-report.json') | ConvertFrom-Json
    if ($report.status -ne 'PASS') { throw 'Windows integration did not report PASS.' }
    $report | Add-Member -NotePropertyName windows_binary_sha256 -NotePropertyValue '686e4f5888fdd66d07ace3b6c1cbd7d2dd0d8d5fb4d3b5d905a7df3341dfb86f'
    $report | Add-Member -NotePropertyName windows_authenticode -NotePropertyValue 'Valid'
    $report | Add-Member -NotePropertyName runner_image -NotePropertyValue $env:ImageVersion
    $report | Add-Member -NotePropertyName wsl_version -NotePropertyValue 1
    $report | Add-Member -NotePropertyName native_hayabusa_version -NotePropertyValue (($nativeVersion | Out-String).Trim())
    $report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $work 'windows-report.json') -Encoding utf8
    Write-Host 'Windows uploads and installed Linux monitor integration passed.'
} finally {
    [IO.File]::WriteAllText((Join-Path $work 'stop'), 'stop')
    if ($null -ne $client -and -not $client.HasExited) { $client.Kill($true); $client.WaitForExit() }
    if ($null -ne $server -and -not $server.HasExited) {
        if (-not $server.WaitForExit(15000)) { $server.Kill($true); $server.WaitForExit() }
    }
    $reportPath = Join-Path $work 'windows-report.json'
    if (Test-Path $reportPath) {
        Copy-Item -LiteralPath $reportPath -Destination (Join-Path $ReportDirectory 'windows-report.json')
    } else {
        @{status='FAIL'; failed_stage='Windows bootstrap'; detail='No Linux report produced; raw secrets and logs deliberately excluded.'} | ConvertTo-Json | Set-Content (Join-Path $ReportDirectory 'windows-report.json')
    }
    # Report a possible AV block without publishing host paths or changing protection.
    $safeReportPath = Join-Path $ReportDirectory 'windows-report.json'
    $safeReport = Get-Content -Raw $safeReportPath | ConvertFrom-Json
    try {
        $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { ($_.Resources -join ' ') -match '(?i)hayabusa|velociraptor' })
        $safeReport | Add-Member -NotePropertyName defender_related_detection_count -NotePropertyValue $threats.Count
    } catch {
        $safeReport | Add-Member -NotePropertyName defender_related_detection_count -NotePropertyValue 'unavailable'
    }
    $safeReport | ConvertTo-Json -Depth 10 | Set-Content $safeReportPath -Encoding utf8
    if ($imported) {
        & wsl.exe --terminate $distro | Out-Null
        & wsl.exe --unregister $distro | Out-Null
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
