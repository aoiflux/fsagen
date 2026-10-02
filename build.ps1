<#
.SYNOPSIS
    Builds every release binary for fsagen into dist/, then writes the checksums.
.DESCRIPTION
    Set NO_COLOR to turn the colours off. build.sh is the POSIX twin and writes a
    byte-identical SHA256SUMS for the same version and toolchain.

    Colours go through Write-Host -ForegroundColor rather than ANSI escapes, so
    the output renders on Windows PowerShell 5.1 as well as PowerShell 7.
.PARAMETER Version
    The version to build, such as v0.1.0. It names every file and is stamped
    into the binaries, so fsagen --version reports it too. Defaults to git
    describe, which is what a test build wants.
.EXAMPLE
    .\build.ps1 v0.1.0
.EXAMPLE
    .\build.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$App = 'fsagen'
# Every platform a release ships for. The gate additionally compiles freebsd,
# which is vetted but not published.
$Targets = @(
    @{ OS = 'windows'; Arch = 'amd64' }
    @{ OS = 'windows'; Arch = 'arm64' }
    @{ OS = 'linux';   Arch = 'amd64' }
    @{ OS = 'linux';   Arch = 'arm64' }
    @{ OS = 'darwin';  Arch = 'amd64' }
    @{ OS = 'darwin';  Arch = 'arm64' }
)

$Root = $PSScriptRoot
$Dist = Join-Path $Root 'dist'
$Plain = [bool]$env:NO_COLOR

function Write-Part {
    param([string]$Text, [string]$Color = 'Gray', [switch]$NoNewline)
    $splat = @{ Object = $Text; NoNewline = $NoNewline }
    if (-not $Plain) { $splat.ForegroundColor = $Color }
    Write-Host @splat
}
function Write-Rule    { Write-Part ('  ' + ('-' * 68)) DarkGray }
function Write-Field   { param($Name, $Value)
                         Write-Part ('  {0,-10} ' -f $Name) DarkGray -NoNewline
                         Write-Part $Value Gray }
function Write-Note    { param($Text)
                         Write-Part ('  {0,-10} ' -f '') DarkGray -NoNewline
                         Write-Part "! $Text" Yellow }
function Write-Heading { param($Text) Write-Host ''; Write-Part "  $Text" White }
function Write-Status  { param([string]$Mark, [string]$Color, [string]$Rest)
                         Write-Part ('    {0,-4}  ' -f $Mark) $Color -NoNewline
                         Write-Part $Rest Gray }
function Stop-Build    { param($Text)
                         Write-Part "  error $Text" Red; Write-Host ''; exit 1 }

function Format-Size { param([long]$Bytes) '{0:N1} MiB' -f ($Bytes / 1MB) }

# A binary's name carries its version and platform, so several releases can sit
# in one directory without colliding.
function Get-ArtifactName {
    param([string]$OS, [string]$Arch)
    $ext = if ($OS -eq 'windows') { '.exe' } else { '' }
    "{0}_{1}_{2}_{3}{4}" -f $App, $Version, $OS, $Arch, $ext
}

function Invoke-Go {
    param([string[]]$GoArgs, [hashtable]$Env)
    $saved = @{}
    foreach ($k in $Env.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
    try {
        foreach ($k in $Env.Keys) { Set-Item -Path "Env:$k" -Value $Env[$k] }
        # Start-Process is avoided here so the compiler's own output comes back
        # inline; PowerShell passes these arguments through unchanged.
        $out = & go @GoArgs 2>&1 | Out-String
        return @{ Code = $LASTEXITCODE; Output = $out }
    } finally {
        foreach ($k in $saved.Keys) {
            if ($null -eq $saved[$k]) { Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue }
            else { Set-Item -Path "Env:$k" -Value $saved[$k] }
        }
    }
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Stop-Build 'go is not on PATH' }
if (-not (Test-Path (Join-Path $Root 'go.mod'))) { Stop-Build "no go.mod in $Root" }

if ($Version) {
    # A version names every file and goes inside the binaries, so it has to be
    # one Go accepts as a module version: v, three numbers, an optional
    # prerelease.
    $Version = $Version.Trim()
    if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$') {
        Stop-Build "version must look like v1.2.3 or v1.2.3-rc.1, not '$Version'"
    }
    $Origin = 'given'
} else {
    $Version = & git -C $Root describe --tags --always --dirty 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Version)) { $Version = 'dev' }
    $Version = $Version.Trim()
    $Origin = 'git describe'
}

# Stamping a version the commit does not carry is how a release ends up
# promising bytes it was not built from. It stays allowed, because test builds
# want it; it does not stay quiet.
$Tag = & git -C $Root describe --tags --exact-match 2>$null
if ($LASTEXITCODE -ne 0) { $Tag = '' } else { $Tag = ($Tag | Out-String).Trim() }
$Dirty = -not [string]::IsNullOrWhiteSpace((& git -C $Root status --porcelain 2>$null | Out-String))

# The stamped variable is named after the module, so reading that path from
# go.mod is what stops a module rename leaving behind a -X that hits nothing.
$Module = (& go list -m 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $Module) { Stop-Build 'cannot read the module path (go list -m failed)' }
$Stamp = "$Module/runinfo.version"

$HostOS = (& go env GOOS).Trim()
$HostArch = (& go env GOARCH).Trim()

Write-Host ''
Write-Part "  $App release build" Cyan
Write-Rule
Write-Field 'version' "$Version  ($Origin)"
if (-not $Tag) {
    Write-Note 'no tag on this commit: fine for a test build, not for a release'
} elseif ($Tag -ne ($Version -replace '-dirty$', '')) {
    Write-Note "this commit is tagged $Tag, so these binaries claim a version they are not"
}
if ($Dirty) { Write-Note 'uncommitted changes: --version will report +modified' }
Write-Field 'toolchain' (& go env GOVERSION).Trim()
Write-Field 'output'    $Dist
Write-Field 'targets'   ("{0}  (windows, linux, darwin x amd64, arm64)" -f $Targets.Count)

# Clearing the contents rather than the directory itself keeps this working
# when another process holds the directory open, which on Windows is easy.
New-Item -ItemType Directory -Force $Dist | Out-Null
Get-ChildItem -LiteralPath $Dist -Force | Remove-Item -Recurse -Force

$started = [Diagnostics.Stopwatch]::StartNew()
$built = [Collections.Generic.List[string]]::new()
$failed = [Collections.Generic.List[string]]::new()

Write-Heading 'building'
foreach ($t in $Targets) {
    $label = "$($t.OS)/$($t.Arch)"
    $name = Get-ArtifactName $t.OS $t.Arch
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # -trimpath keeps the build host's paths out of the binary and -X puts the
    # version in; the revision printed beside it is Go's own VCS stamping.
    $r = Invoke-Go @('build', '-trimpath', '-ldflags', "-X $Stamp=$Version",
                     '-o', (Join-Path $Dist $name), '.') `
                   @{ CGO_ENABLED = '0'; GOOS = $t.OS; GOARCH = $t.Arch }
    $sw.Stop()
    if ($r.Code -eq 0) {
        $size = (Get-Item (Join-Path $Dist $name)).Length
        Write-Status 'OK' Green ('{0,-14} {1,-52} {2,9}  {3,5}s' -f `
            $label, $name, (Format-Size $size), $sw.Elapsed.TotalSeconds.ToString('0.0'))
        $built.Add($name)
    } else {
        Write-Status 'FAIL' Red ('{0,-14} build failed' -f $label)
        ($r.Output -split "`n") | Where-Object { $_.Trim() } | ForEach-Object {
            Write-Part ('          ' + $_.TrimEnd()) DarkGray
        }
        $failed.Add($label)
    }
}

# Every later step reads the built list, so stop here rather than walk it empty.
if ($built.Count -eq 0) {
    Write-Host ''; Write-Rule
    Write-Part ('  failed  all {0} targets' -f $Targets.Count) Red
    Write-Host ''; exit 1
}

Write-Heading 'checksums'
$sums = Join-Path $Dist 'SHA256SUMS'
$lines = foreach ($name in ($built | Sort-Object -CaseSensitive)) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $Dist $name)).Hash.ToLowerInvariant()
    "$hash  $name"
}
# LF endings and no BOM, so sha256sum on another machine reads the file as it
# would one written by build.sh.
[IO.File]::WriteAllText($sums, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
Write-Status 'OK' Green ('{0,-14} {1} entries, verify with: sha256sum -c SHA256SUMS' -f 'SHA256SUMS', $built.Count)

Write-Heading 'smoke test'
$hostArtifact = Join-Path $Dist (Get-ArtifactName $HostOS $HostArch)
if (-not (Test-Path $hostArtifact)) {
    Write-Status 'skip' Yellow ("$HostOS/$HostArch is not a release target, nothing to run")
} else {
    $reported = (& $hostArtifact --version | Out-String).Trim()
    Write-Status 'OK' Green ('{0,-14} {1}' -f "$HostOS/$HostArch", $reported)
    # -X is silently ignored when the variable it names has moved, so the
    # binary itself has to confirm the version these files are named after.
    if ($reported -notlike "$App $Version *") {
        Write-Host ''
        Stop-Build "built as $Version, but the binary reports: $reported"
    }
}

$total = ($built | ForEach-Object { (Get-Item (Join-Path $Dist $_)).Length } | Measure-Object -Sum).Sum
$started.Stop()

Write-Host ''
Write-Rule
if ($failed.Count -eq 0) {
    Write-Part ('  done  {0}/{1} targets, {2} total, {3}s' -f `
        $built.Count, $Targets.Count, (Format-Size $total), $started.Elapsed.TotalSeconds.ToString('0.0')) Green
    Write-Part '  this script checks nothing but --version; for the tests run: go run ./tools/gate' DarkGray
    Write-Host ''
} else {
    Write-Part ('  failed  {0} of {1} targets: {2}' -f $failed.Count, $Targets.Count, ($failed -join ' ')) Red
    Write-Host ''
    exit 1
}
