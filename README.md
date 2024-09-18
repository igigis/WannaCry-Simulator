# WannaCry Ransomware Simulation Script

## ⚠️ Disclaimer ⚠️
This script is intended for educational and testing purposes only. Use it exclusively in a controlled, isolated environment (e.g., a virtual machine). The author and contributors are not responsible for any misuse or damage caused by this script.

# Table of Contents

    Overview
    Features
    MITRE ATT&CK Framework Mapping
    Requirements
    Usage
        Running the Simulation
        Cleaning Up After the Simulation
    Parameters
    Logging
    EDR Testing
    Disclaimer
    License

# Overview

This PowerShell script simulates key behaviors of the WannaCry ransomware for educational and testing purposes. It is designed to help cybersecurity professionals test and validate the effectiveness of Endpoint Detection and Response (EDR) products and security controls in detecting and responding to ransomware-like activities.

Important: Run this script only in a secure, isolated environment (e.g., a virtual machine specifically set up for testing). Do not run on production systems or systems containing important or sensitive data.
Features

    Simulates exploitation of vulnerabilities (EternalBlue exploit).
    Demonstrates execution via Windows Management Instrumentation (WMI).
    Emulates worm-like behavior by scanning for network shares.
    Simulates file encryption impact on the user's Documents directory, including hidden folders.
    Includes a cleanup function to revert changes made during the simulation.
    Provides detailed logging of actions performed for analysis.

# MITRE ATT&CK Framework Mapping

The script's actions are mapped to the MITRE ATT&CK framework to align simulated behaviors with real-world tactics and techniques:

    Initial Access
        T1190 - Exploit Public-Facing Application
    Execution
        T1047 - Windows Management Instrumentation
    Lateral Movement
        T1105 - Ingress Tool Transfer
        T1091 - Replication Through Removable Media
    Impact
        T1486 - Data Encrypted for Impact

# Requirements

    Windows operating system
    PowerShell 5.0 or higher
    Run with administrative privileges (recommended for full simulation)

# Usage
Running the Simulation

    Ensure you are in a safe, isolated test environment.

    Open PowerShell with administrative privileges.

    Navigate to the directory containing the script.

    Run the script:

    powershell

        ./WannaCrySimulation.ps1

Optional parameters:

    To specify the maximum number of files to encrypt (default is 10):

    powershell

        ./WannaCrySimulation.ps1 -MaxFiles 5

    Follow the on-screen prompts to confirm execution.

# Cleaning Up After the Simulation

To revert the changes made by the simulation:

    powershell

        ./WannaCrySimulation.ps1 -CleanUp

Parameters

    -MaxFiles <int>: Specifies the maximum number of files to simulate encryption on. Default is 10.

    -CleanUp: Runs the cleanup process to decrypt files and restore them to their original state.

# Logging

The script generates a log file named simulation_log.txt in the directory where it is executed. The log includes timestamps and descriptions of actions performed, which can be used for analysis and reporting.
# EDR Testing

This script is designed to test the effectiveness of Endpoint Detection and Response (EDR) products and security monitoring solutions. By simulating ransomware-like behavior, it allows security teams to:

    Validate detection capabilities.
    Test alerting mechanisms.
    Assess response procedures.
    Identify gaps in security controls.

Note: Ensure that your EDR and security solutions are configured to monitor the test environment and that testing activities comply with your organization's policies.
Disclaimer

# Educational and Testing Purposes Only

This script is intended solely for educational and testing purposes within authorized environments. Unauthorized use or deployment in unauthorized environments is strictly prohibited.

# No Responsibility

The author and contributors of this script are not responsible for any direct or indirect damage, loss, or legal consequences resulting from the use or misuse of this script. Users are fully responsible for complying with all applicable laws and regulations.

# Use at Your Own Risk

By using this script, you acknowledge that you understand the risks involved and agree to use it responsibly and ethically.
# License

This project is licensed under the MIT License.
