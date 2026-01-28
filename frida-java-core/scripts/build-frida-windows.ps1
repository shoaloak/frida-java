#!/usr/bin/env pwsh
# Build Frida for Windows using Microsoft toolchain
# PowerShell script to download and build Frida Core for Windows

# Copyright (C) 2026 Axel Koolhaas
#
# This file is part of frida-java.
#
# frida-java is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# frida-java is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with frida-java.  If not, see <https://www.gnu.org/licenses/>.

# Set error action preference to stop on errors
$ErrorActionPreference = "Stop"

# Constants
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Resolve-Path "$ScriptDir\..\.."
$TargetDir = Join-Path $ProjectDir "frida-java-core\frida-devkit"

function Get-FridaConfig {
    param([string]$ConfigPath = (Join-Path $ScriptDir "build.properties"))

    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Configuration file not found: $ConfigPath"
        exit 1
    }

    Get-Content $ConfigPath | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line -split '=', 2
            if ($parts.Length -eq 2) {
                $key = $parts[0].Trim()
                $value = $parts[1].Trim()

                # Create PascalCase as script variable
                $pascalParts = $key.Split('_') | ForEach-Object {
                    $_.Substring(0,1).ToUpper() + $_.Substring(1).ToLower()
                }
                $pascalKey = $pascalParts -join ''
                Set-Variable -Name $pascalKey -Value $value -Scope Script

                # Set as environment variable
                [Environment]::SetEnvironmentVariable($key, $value, [EnvironmentVariableTarget]::Process)
            }
        }
    }
}

# Function to get current architecture
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "x86" { return "x86" }
        "ARM64" { return "arm64" }
        default { return "unknown" }
    }
}

# Function to download and extract devkit
function Get-ArchDevkit {
    param([string]$Arch)

    Write-Host "Fetching Windows $Arch devkit..."
    $DevkitDir = "windows-$Arch"

    if (-not (Test-Path $DevkitDir)) {
        New-Item -ItemType Directory -Path $DevkitDir -Force | Out-Null
    }

    $ArchiveUrl = "$FridaUrl/$FridaVersion/frida-core-devkit-$FridaVersion-windows-$Arch.tar.xz"
    $TempArchive = "frida-core-devkit-$FridaVersion-windows-$Arch.tar.xz"

    try {
        # Download the archive
        Write-Host "Downloading from: $ArchiveUrl"
        Invoke-WebRequest -Uri $ArchiveUrl -OutFile $TempArchive -UseBasicParsing

        # Extract using tar (available in Windows 10/11)
        Write-Host "Extracting archive..."
        & tar -xf $TempArchive -C $DevkitDir

        # Clean up
        Remove-Item $TempArchive -Force
    }
    catch {
        Write-Error "Failed to download or extract devkit: $_"
        exit 1
    }
}

# Function to find Visual Studio installation
function Find-VSInstallation {
    # Try to find vswhere.exe
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

    if (-not (Test-Path $vswhere)) {
        Write-Error "Visual Studio installer (vswhere.exe) not found. Please install Visual Studio 2019 or later."
        exit 1
    }

    # Find VS installation with C++ build tools
    $vsPath = & "$vswhere" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

    if (-not $vsPath) {
        Write-Error "Visual Studio with C++ build tools not found. Please install Visual Studio with C++ development workload."
        exit 1
    }

    return $vsPath
}

# Function to setup Visual Studio environment
function Initialize-VSEnvironment {
    param([string]$VSPath, [string]$Arch)

    # Map our architecture names to vcvars script names
    $vcvarsScript = switch ($Arch) {
        "x86_64" { "vcvars64.bat" }
        "x86" { "vcvars32.bat" }
        "arm64" {
            # Check if we're on ARM64 host, otherwise use cross-compilation
            if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
                "vcvarsarm64.bat"
            } else {
                "vcvarsamd64_arm64.bat"  # Cross-compile from x64 to ARM64
            }
        }
        default { "vcvars64.bat" }
    }

    $vcvarsPath = Join-Path $VSPath "VC\Auxiliary\Build\$vcvarsScript"

    if (-not (Test-Path $vcvarsPath)) {
        Write-Error "vcvars script not found: $vcvarsScript"
        Write-Host "Available vcvars scripts:"
        $vcvarsDir = Join-Path $VSPath "VC\Auxiliary\Build"
        if (Test-Path $vcvarsDir) {
            Get-ChildItem "$vcvarsDir\vcvars*.bat" | ForEach-Object { Write-Host "  $($_.Name)" }
        }
        exit 1
    }

    Write-Host "Initializing Visual Studio environment using $vcvarsScript..."

    # Execute vcvars and capture environment variables
    $output = & cmd.exe /c "`"$vcvarsPath`" && set" 2>&1

    foreach ($line in $output) {
        if ($line -match "^([^=]+)=(.*)$") {
            $name = $matches[1]
            $value = $matches[2]
            [Environment]::SetEnvironmentVariable($name, $value, [EnvironmentVariableTarget]::Process)
        }
    }

    # Verify that cl.exe is now available
    try {
        $null = & where.exe cl.exe 2>$null
        Write-Host "Microsoft C/C++ compiler found and initialized for $Arch"
    }
    catch {
        Write-Error "Failed to initialize Visual Studio environment. cl.exe not found in PATH."
        exit 1
    }
}

# Function to create DEF file for DLL exports
function New-DefFile {
    param([string]$LibPath, [string]$DefPath)

    Write-Host "Creating DEF file for DLL exports..."

    # Use dumpbin to extract symbols from the static library
    $dumpbinOutput = & dumpbin.exe /symbols "$LibPath" 2>$null

    $exports = @()
    foreach ($line in $dumpbinOutput) {
        if ($line -match "External.*\|\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$") {
            $symbol = $matches[1]
            # Filter out compiler-generated symbols and include only frida symbols
            if ($symbol -match "^frida_" -or $symbol -match "^gum_" -or $symbol -match "^g_") {
                $exports += $symbol
            }
        }
    }

    if ($exports.Count -eq 0) {
        Write-Warning "No exports found in static library. Creating DLL without explicit exports."
        return $null
    }

    # Create DEF file
    $defContent = @"
EXPORTS
$($exports -join "`r`n")
"@

    Set-Content -Path $DefPath -Value $defContent -Encoding ASCII
    Write-Host "Created DEF file with $($exports.Count) exports"
    return $DefPath
}

# Function to build DLL using MSVC
function Build-DLL {
    param([string]$Arch, [string]$LibPath)

    $OutputDLL = "libfrida-core-$Arch.dll"
    $DefFile = "frida-core-$Arch.def"

    Write-Host "Building DLL using Microsoft Visual C++ compiler..."

    # Create DEF file
    $defPath = New-DefFile -LibPath $LibPath -DefPath $DefFile

    ################################################################################
    ## Define compilation flags and libraries
    ################################################################################

    # Determine machine type for linker based on architecture
    $machineType = switch ($Arch) {
        "x86_64" { "X64" }
        "x86" { "X86" }
        "arm64" { "ARM64" }
        default { "X64" }
    }

    ## Core linker flags
    # /DLL:           Create a dynamic link library
    # /OUT:           Specify output file name
    # /MACHINE:       Target machine architecture
    $coreFlags = @(
        "/DLL"
        "/OUT:$OutputDLL"
        "/MACHINE:$machineType"
        "$LibPath"
    )

    ## System libraries (based on Frida's actual meson.build dependencies)
    # ws2_32.lib:     Windows Sockets 2
    # winmm.lib:      Windows Multimedia API
    # psapi.lib:      Process Status API
    # shlwapi.lib:    Shell Lightweight API
    # ole32.lib:      Object Linking and Embedding
    # oleaut32.lib:   OLE Automation
    # uuid.lib:       Universally Unique Identifier
    # setupapi.lib:   Setup API
    # advapi32.lib:   Advanced Windows 32 Base API
    # shell32.lib:    Windows Shell API
    # user32.lib:     Windows User API
    # kernel32.lib:   Windows Kernel API
    # gdi32.lib:      Graphics Device Interface
    # dbghelp.lib:    Debug Help Library
    # version.lib:    Version Information API
    # winhttp.lib:    Windows HTTP Services
    # crypt32.lib:    Cryptography API
    # wintrust.lib:   WinTrust API
    # bcrypt.lib:     Cryptography API: Next Generation
    # ncrypt.lib:     Cryptography API: Next Generation
    # dnsapi.lib:     DNS Client API
    # iphlpapi.lib:   IP Helper API
    # wbemuuid.lib:   Windows Management Instrumentation
    # comctl32.lib:   Common Controls
    # msvcrt.lib:     Microsoft Visual C++ Runtime
    $systemLibs = @(
        "ws2_32.lib", "winmm.lib", "psapi.lib", "shlwapi.lib",
        "ole32.lib", "oleaut32.lib", "uuid.lib", "setupapi.lib",
        "advapi32.lib", "shell32.lib", "user32.lib", "kernel32.lib",
        "gdi32.lib", "dbghelp.lib", "version.lib", "winhttp.lib",
        "crypt32.lib", "wintrust.lib", "bcrypt.lib", "ncrypt.lib",
        "dnsapi.lib", "iphlpapi.lib", "wbemuuid.lib", "comctl32.lib",
        "msvcrt.lib"
    )

    ## Optimization and security flags
    # /O2:                 Maximize speed optimization
    # /GL:                 Whole program optimization
    # /LTCG:               Link-time code generation
    # /SUBSYSTEM:WINDOWS:  Target Windows subsystem
    # /DYNAMICBASE:        Enable ASLR (Address Space Layout Randomization)
    # /NXCOMPAT:           Compatible with Data Execution Prevention
    # /MANIFEST:NO:        Do not generate manifest
    # /INCREMENTAL:NO:     Disable incremental linking for smaller size
    # /OPT:REF:            Remove unreferenced functions and data
    # /OPT:ICF:            Enable COMDAT folding for smaller size
    $optimizationFlags = @(
        "/O2"
#        "/GL"      # TODO test
#        "/LTCG"    # TODO test
        "/SUBSYSTEM:WINDOWS"
        "/DYNAMICBASE"
        "/NXCOMPAT"
        "/MANIFEST:NO"
        "/INCREMENTAL:NO"
        "/OPT:REF"
        "/OPT:ICF"
    )
    ################################################################################

    # Build complete linker argument list
    $linkArgs = $coreFlags + $systemLibs + $optimizationFlags

    if ($defPath) {
        $linkArgs += "/DEF:$defPath"
    }

    try {
        Write-Host "Executing: link.exe $($linkArgs -join ' ')"
        & link.exe @linkArgs

        if ($LASTEXITCODE -ne 0) {
            throw "Link command failed with exit code $LASTEXITCODE"
        }

        Write-Host "Successfully created $OutputDLL"
    }
    catch {
        Write-Error "Failed to build DLL: $_"
        exit 1
    }
    finally {
        # Clean up DEF file
        if ($defPath -and (Test-Path $defPath)) {
            Remove-Item $defPath -Force
        }
    }
}

# Main script execution
Write-Host "Frida Windows Build Script (Microsoft Toolchain)"
Write-Host "================================================="

# Load configuration
Get-FridaConfig

# Prepare directory
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

Set-Location $TargetDir

# Detect current architecture
$CurrentArch = Get-Architecture

if ($CurrentArch -eq "unknown") {
    Write-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
    exit 1
}

Write-Host "Building for current architecture: $CurrentArch"

# Check if devkit already exists, otherwise download
$DevkitDir = "windows-$CurrentArch"
if (-not (Test-Path $DevkitDir)) {
    Write-Host "Windows $CurrentArch devkit not found. Proceeding to download..."
    Get-ArchDevkit -Arch $CurrentArch
}

# Find and initialize Visual Studio
$VSPath = Find-VSInstallation
Initialize-VSEnvironment -VSPath $VSPath -Arch $CurrentArch

# Build DLL
$LibPath = Join-Path $DevkitDir "frida-core.lib"
if (-not (Test-Path $LibPath)) {
    Write-Error "Static library not found: $LibPath"
    exit 1
}

Build-DLL -Arch $CurrentArch -LibPath $LibPath

# Verify the DLL was created
$OutputDLL = "libfrida-core-$CurrentArch.dll"
if (Test-Path $OutputDLL) {
    $fileInfo = Get-Item $OutputDLL
    Write-Host "Successfully created DLL: $OutputDLL ($($fileInfo.Length) bytes)"

    # Try to get file type information
    try {
        $fileOutput = & file.exe "$OutputDLL" 2>$null
        if ($fileOutput) {
            Write-Host "File type: $fileOutput"
        }
    }
    catch {
        # file.exe might not be available, that's ok
    }
} else {
    Write-Error "DLL creation failed - output file not found"
    exit 1
}

Write-Host "Build completed successfully!"
