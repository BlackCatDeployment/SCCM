<#
    .SYNOPSIS
    Windows 11 Readiness
    .DESCRIPTION
    Check if a device is Windows 11 readiness.
    This script can be used with SCCM or other tools for getting the registry key value created.
    .OUTPUTS
    Write a registry key "HKLM:\SOFTWARE\BlackCat" value "Win11Ready" with True or False data
    .AUTHOR
    Florian VALENTE
    .NOTES
    https://docs.microsoft.com/en-us/windows-hardware/design/minimum/minimum-hardware-requirements-overview
#>
#Requires -Version 5
#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

# Registry key to populate
$RegPath = "HKLM:\SOFTWARE\BlackCat"
$RegName = "Win11Ready"

# Custom definition for checking CPU family
$CPUDefinition = @"
using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

    public class CpuFamilyResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }

    public class CpuFamily
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public enum ProcessorFeature : uint
        {
            ARM_SUPPORTED_INSTRUCTIONS = 34
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsProcessorFeaturePresent(ProcessorFeature processorFeature);

        private const ushort PROCESSOR_ARCHITECTURE_X86 = 0;
        private const ushort PROCESSOR_ARCHITECTURE_ARM64 = 12;
        private const ushort PROCESSOR_ARCHITECTURE_X64 = 9;

        private const string INTEL_MANUFACTURER = "GenuineIntel";
        private const string AMD_MANUFACTURER = "AuthenticAMD";
        private const string QUALCOMM_MANUFACTURER = "Qualcomm Technologies Inc";

        public static CpuFamilyResult Validate(string manufacturer, ushort processorArchitecture)
        {
            CpuFamilyResult cpuFamilyResult = new CpuFamilyResult();

            if (string.IsNullOrWhiteSpace(manufacturer))
            {
                cpuFamilyResult.IsValid = false;
                cpuFamilyResult.Message = "Manufacturer is null or empty";
                return cpuFamilyResult;
            }

            string registryPath = "HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\CentralProcessor\\0";
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetNativeSystemInfo(ref sysInfo);

            switch (processorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_ARM64:

                    if (manufacturer.Equals(QUALCOMM_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isArmv81Supported = IsProcessorFeaturePresent(ProcessorFeature.ARM_SUPPORTED_INSTRUCTIONS);

                        if (!isArmv81Supported)
                        {
                            string registryName = "CP 4030";
                            long registryValue = (long)Registry.GetValue(registryPath, registryName, -1);
                            long atomicResult = (registryValue >> 20) & 0xF;

                            if (atomicResult >= 2)
                            {
                                isArmv81Supported = true;
                            }
                        }

                        cpuFamilyResult.IsValid = isArmv81Supported;
                        cpuFamilyResult.Message = isArmv81Supported ? "" : "Processor does not implement ARM v8.1 atomic instruction";
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "The processor isn't currently supported for Windows 11";
                    }

                    break;

                case PROCESSOR_ARCHITECTURE_X64:
                case PROCESSOR_ARCHITECTURE_X86:

                    int cpuFamily = sysInfo.ProcessorLevel;
                    int cpuModel = (sysInfo.ProcessorRevision >> 8) & 0xFF;
                    int cpuStepping = sysInfo.ProcessorRevision & 0xFF;

                    if (manufacturer.Equals(INTEL_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            cpuFamilyResult.IsValid = true;
                            cpuFamilyResult.Message = "";

                            if (cpuFamily == 6)
                            {
                                if (cpuModel <= 95 && cpuModel != 85)
                                {
                                    cpuFamilyResult.IsValid = false;
                                    cpuFamilyResult.Message = "";
                                }
                                else if ((cpuModel == 142 || cpuModel == 158) && cpuStepping == 9)
                                {
                                    string registryName = "Platform Specific Field 1";
                                    int registryValue = (int)Registry.GetValue(registryPath, registryName, -1);

                                    if ((cpuModel == 142 && registryValue != 16) || (cpuModel == 158 && registryValue != 8))
                                    {
                                        cpuFamilyResult.IsValid = false;
                                    }
                                    cpuFamilyResult.Message = "PlatformId " + registryValue;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            cpuFamilyResult.IsValid = false;
                            cpuFamilyResult.Message = "Exception:" + ex.GetType().Name;
                        }
                    }
                    else if (manufacturer.Equals(AMD_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        cpuFamilyResult.IsValid = true;
                        cpuFamilyResult.Message = "";

                        if (cpuFamily < 23 || (cpuFamily == 23 && (cpuModel == 1 || cpuModel == 17)))
                        {
                            cpuFamilyResult.IsValid = false;
                        }
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "Unsupported Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    }

                    break;

                default:
                    cpuFamilyResult.IsValid = false;
                    cpuFamilyResult.Message = "Unsupported CPU category. Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    break;
            }
            return cpuFamilyResult;
        }
    }
"@

# Define report columns
$ReportParams = @("BuildNumber", "CPUName", "CPUSpeed", "CPUCores", "RAMSize", `
    "FreeDiskSpace", "TPMVersion", "FirmwareType", "SecureBootEnabled", "GraphicsResolution")

#Windows 11 system requirements
Write-Host "Windows 11 requirements:"
$Win11Report = "" | Select-Object -Property $ReportParams
$Win11Report.'BuildNumber' = 19041 # Build 2004
$Win11Report.'CPUSpeed' = "1"
$Win11Report.'CPUCores' = "2"
$Win11Report.'RAMSize' = "4"
$Win11Report.'FreeDiskSpace' = "64"
$Win11Report.'FirmwareType' = "UEFI"
$Win11Report.'SecureBootEnabled' = "True"
$Win11Report.'TPMVersion' = "2.0"
$Win11Report.'GraphicsResolution' = "720"
$Win11Report


# Get computer data
$BuildNumber = (Get-WmiObject Win32_OperatingSystem).BuildNumber
If ($BuildNumber -ge 22000) {
    Write-Host "This device is already on Windows 11" -ForegroundColor Green
    Set-ItemProperty $RegPath -Name $RegName -Value $true -Force | Out-Null
    exit 0
}
$Processor = @(Get-WmiObject Win32_Processor)[0]
$MaxClockSpeed = $Processor.MaxClockSpeed
$CurrentClockSpeed = [math]::round(($Processor.CurrentClockSpeed)/1000, 1)
$NumberOfCores = $Processor.NumberOfCores
Add-Type -TypeDefinition $CPUDefinition
$ProcCompatible = [CpuFamily]::Validate([String]$Processor.Manufacturer, [uint16]$Processor.Architecture)
# Manage i7-7820hq CPU
$supportedDevices = @('surface studio 2', 'precision 5520')
$systemInfo = @(Get-WmiObject -Class Win32_ComputerSystem)[0]
if ($cpuDetails.Name -match 'i7-7820hq cpu @ 2.90ghz'){
    $modelOrSKUCheckLog = $systemInfo.Model.Trim()
    if ($supportedDevices -contains $modelOrSKUCheckLog){
        $ProcCompatible.IsValid = $true
    }
}
$RAMSize = [math]::round(((Get-WmiObject -Class win32_computersystem).TotalPhysicalMemory)/1GB, 0)
#The following commands gets the free space on the drive Windows 10 is installed
$OSInstallDrive = ($Env:windir -split ":")[0] + ":" #Retrieves current OS install path Drive
$FreeSpace = [math]::round(((Get-WmiObject -Class win32_logicaldisk | Where-Object {$_.DeviceID -like "$OSInstallDrive"}).FreeSpace)/1GB, 0)
$TPMVersion = (((Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Class win32_tpm -ErrorAction Stop).SpecVersion) -split (","))[0]  #This command requires PS to open as Administrator
$FirmwareType = $env:firmware_type
If ($FirmwareType -eq "UEFI") {
    $SecureBootState = Confirm-SecureBootUEFI -ErrorAction Stop #This command requires PS to open as Administrator
}
Else {
    $SecureBootState = $false
}
$GraphicsResolution = (Get-WmiObject win32_VideoController).CurrentVerticalResolution | Select-Object -First 1

Write-Host "System configuration:"
$Report = "" | Select-Object -Property $ReportParams
$Report.'BuildNumber' = $BuildNumber
$Report.'CPUName' = $Processor.Name
$Report.'CPUSpeed' = $CurrentClockSpeed
$Report.'CPUCores' = $NumberOfCores
$Report.'RAMSize' = $RAMSize
$Report.'FreeDiskSpace' = $FreeSpace
$Report.'FirmwareType' = $FirmwareType
$Report.'SecureBootEnabled' = $SecureBootState
$Report.'TPMVersion' = $TPMVersion
$Report.'GraphicsResolution' = $GraphicsResolution
$Report

# Get compatibility results
Write-Host "Results:"
$Results = [PSCustomObject]@{
    "Build Number"         = [bool]($Report.'BuildNumber' -ge $Win11Report.'BuildNumber')
    "CPU Speed"            = [bool]($Report.'CPUSpeed' -ge $Win11Report.'CPUSpeed')
    "CPU Cores"            = [bool]($Report.'CPUCores' -ge $Win11Report.'CPUCores')
    "CPU Family"           = [bool]$ProcCompatible.IsValid
    "RAM Size"             = [bool]($Report.'RAMSize' -ge $Win11Report.'RAMSize')
    "Free Disk Space"      = [bool]($Report.'FreeDiskSpace' -ge $Win11Report.'FreeDiskSpace')
    "Firmware Type"        = [bool]($Report.'FirmwareType' -eq $Win11Report.'FirmwareType')
    "Secure Boot"          = [bool]($Report.'SecureBootEnabled' -eq $Win11Report.'SecureBootEnabled')
    "TPM"                  = [bool]($Report.'TPMVersion' -ge $Win11Report.'TPMVersion')
    "Graphics Resolution"  = [bool]($Report.'GraphicsResolution' -ge $Win11Report.'GraphicsResolution')
}
$Results

# Display final result
if ($Results.psobject.properties.value -contains $false) {
    Write-Host "This device is not compatible with Windows 11" -ForegroundColor Red
    Set-ItemProperty $RegPath -Name $RegName -Value $false -Force | Out-Null
}
else {
    Write-Host "This device is compatible with Windows 11" -ForegroundColor Green
    Set-ItemProperty $RegPath -Name $RegName -Value $true -Force | Out-Null
}
