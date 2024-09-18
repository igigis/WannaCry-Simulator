<#
.SYNOPSIS
    Simulates WannaCry ransomware behavior for educational and testing purposes.

.DESCRIPTION
    This script emulates key behaviors of the WannaCry ransomware, including exploitation of vulnerabilities,
    execution via WMI, worm-like replication, and file encryption impact. It is intended for use in a controlled,
    isolated environment for cybersecurity training and testing.

.PARAMETER CleanUp
    If specified, the script will attempt to revert changes made during the simulation.

.PARAMETER MaxFiles
    Specifies the maximum number of files to simulate encryption on.

.EXAMPLE
    ./WannaCrySimulation.ps1

    Runs the simulation.

    ./WannaCrySimulation.ps1 -CleanUp

    Runs the cleanup process to revert changes.

    ./WannaCrySimulation.ps1 -MaxFiles 5

    Runs the simulation, encrypting up to 5 files.

.NOTES
    Run this script only in a secure, isolated environment (e.g., virtual machine).
    Do NOT run on production systems or with real data.

#>

[CmdletBinding()]
param (
    [switch]$CleanUp,
    [int]$MaxFiles = 10
)

# Global Variables
$LogFile = "simulation_log.txt"
$EncryptionKey = (1..16)  # Known key for reversible encryption (array of bytes)

# Function Definitions

Function Log-Action {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Function Check-TestEnvironment {
    [CmdletBinding()]
    param ()
    # Placeholder for environment checks
    $environmentOK = $true  # Change logic as needed
    if (-not $environmentOK) {
        Write-Warning "This script must be run in a designated test environment."
        exit
    }
}

Function Simulate-Exploit {
    <#
    .SYNOPSIS
        Simulates exploitation of a vulnerability.

    .DESCRIPTION
        Mocks the action of exploiting a vulnerability, such as EternalBlue.

    .NOTES
        MITRE ATT&CK Technique: T1190 - Exploit Public-Facing Application
    #>
    [CmdletBinding()]
    param ()
    try {
        Write-Verbose "Simulating exploitation of vulnerability..."
        Start-Sleep -Seconds 2
        Write-Host "Exploit simulation complete."
        Log-Action "Simulated exploitation of vulnerability. (MITRE ATT&CK: T1190)"
    } catch {
        Write-Error "Error during Exploit simulation: $_"
        Log-Action "Error during Exploit simulation: $_"
    }
}

Function Simulate-WMIExecution {
    <#
    .SYNOPSIS
        Simulates execution via Windows Management Instrumentation (WMI).

    .DESCRIPTION
        Mocks the action of executing commands via WMI.

    .NOTES
        MITRE ATT&CK Technique: T1047 - Windows Management Instrumentation
    #>
    [CmdletBinding()]
    param ()
    try {
        Write-Verbose "Simulating execution via WMI..."
        Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue | Out-Null
        Write-Host "WMI execution simulation complete."
        Log-Action "Simulated WMI execution. (MITRE ATT&CK: T1047)"
    } catch {
        Write-Error "Error during WMI execution simulation: $_"
        Log-Action "Error during WMI execution simulation: $_"
    }
}

Function Simulate-WormReplication {
    <#
    .SYNOPSIS
        Simulates worm-like behavior.

    .DESCRIPTION
        Mocks the action of scanning for network shares and attempting to replicate.

    .NOTES
        MITRE ATT&CK Techniques:
            - T1105: Ingress Tool Transfer
            - T1091: Replication Through Removable Media
    #>
    [CmdletBinding()]
    param ()
    try {
        Write-Verbose "Simulating worm-like replication..."
        $networkShares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue
        if ($networkShares) {
            foreach ($share in $networkShares) {
                Write-Host "Found network share: $($share.Name)"
                Log-Action "Simulated scanning network share: $($share.Name)"
            }
        } else {
            Write-Host "No network shares found."
        }
        Write-Host "Worm replication simulation complete."
        Log-Action "Simulated worm replication. (MITRE ATT&CK: T1105, T1091)"
    } catch {
        Write-Error "Error during Worm Replication simulation: $_"
        Log-Action "Error during Worm Replication simulation: $_"
    }
}

Function Simulate-FileEncryption {
    <#
    .SYNOPSIS
        Simulates file encryption impact.

    .DESCRIPTION
        Encrypts a limited number of files in the user's Documents directory, including hidden folders, using reversible encryption.

    .PARAMETER MaxFiles
        The maximum number of files to encrypt.

    .NOTES
        MITRE ATT&CK Technique: T1486 - Data Encrypted for Impact
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$MaxFiles
    )
    try {
        Write-Verbose "Simulating file encryption..."
        $documentsPath = [Environment]::GetFolderPath('MyDocuments')
        # Include hidden files and directories by using -Force
        $files = Get-ChildItem -Path $documentsPath -Include *.pdf, *.docx, *.xlsx, *.pptx, *.txt -Recurse -Force -ErrorAction SilentlyContinue
        $filesToEncrypt = $files | Select-Object -First $MaxFiles

        foreach ($file in $filesToEncrypt) {
            try {
                # Read file content
                $content = Get-Content -Path $file.FullName -ErrorAction Stop -Raw
                # Encrypt content (using reversible encryption)
                $secureString = ConvertTo-SecureString -String $content -AsPlainText -Force
                $encryptedContent = ConvertFrom-SecureString -SecureString $secureString -Key $EncryptionKey
                # Overwrite file with encrypted content
                Set-Content -Path $file.FullName -Value $encryptedContent -ErrorAction Stop
                # Rename file to indicate encryption
                Rename-Item -Path $file.FullName -NewName "$($file.Name).encrypted" -ErrorAction Stop
                Write-Host "Simulated encryption of: $($file.FullName)"
                Log-Action "Simulated encryption of: $($file.FullName)"
            } catch {
                Write-Warning "Failed to encrypt file: $($file.FullName) - $_"
                Log-Action "Failed to encrypt file: $($file.FullName) - $_"
            }
        }
        Write-Host "File encryption simulation complete."
        Log-Action "Completed file encryption simulation. (MITRE ATT&CK: T1486)"
    } catch {
        Write-Error "Error during File Encryption simulation: $_"
        Log-Action "Error during File Encryption simulation: $_"
    }
}

Function Cleanup-Simulation {
    <#
    .SYNOPSIS
        Cleans up the simulation by decrypting files and restoring original names.

    .DESCRIPTION
        Reverts changes made during the simulation.

    #>
    [CmdletBinding()]
    param ()
    try {
        Write-Verbose "Starting cleanup process..."
        $documentsPath = [Environment]::GetFolderPath('MyDocuments')
        $encryptedFiles = Get-ChildItem -Path $documentsPath -Filter "*.encrypted" -Recurse -Force -ErrorAction SilentlyContinue

        foreach ($file in $encryptedFiles) {
            try {
                # Decrypt content
                $encryptedContent = Get-Content -Path $file.FullName -ErrorAction Stop -Raw
                $secureString = ConvertTo-SecureString -String $encryptedContent -Key $EncryptionKey
                $decryptedContent = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
                )
                # Overwrite file with decrypted content
                Set-Content -Path $file.FullName -Value $decryptedContent -ErrorAction Stop
                # Rename file to original name
                $originalName = $file.FullName -replace '\.encrypted$', ''
                Rename-Item -Path $file.FullName -NewName $originalName -ErrorAction Stop
                Write-Host "Restored file: $originalName"
                Log-Action "Restored file: $originalName"
            } catch {
                Write-Warning "Failed to restore file: $($file.FullName) - $_"
                Log-Action "Failed to restore file: $($file.FullName) - $_"
            }
        }
        Write-Host "Cleanup process complete."
        Log-Action "Completed cleanup process."
    } catch {
        Write-Error "Error during Cleanup: $_"
        Log-Action "Error during Cleanup: $_"
    }
}

# Main Execution Logic

if ($CleanUp) {
    Cleanup-Simulation
    exit
} else {
    # Environment Safety Checks
    Check-TestEnvironment

    # User Confirmation
    Write-Host "This script simulates WannaCry ransomware behavior for educational and testing purposes only."
    Write-Host "Run this script in a controlled, isolated environment (e.g., virtual machine) only."
    $confirmation = Read-Host "Do you want to proceed? (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Exiting script."
        exit
    }

    # Run Simulation Functions
    Simulate-Exploit
    Simulate-WMIExecution
    Simulate-WormReplication
    Simulate-FileEncryption -MaxFiles $MaxFiles

    Write-Host "WannaCry ransomware simulation completed."
    Log-Action "Simulation completed."
}
