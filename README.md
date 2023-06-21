# MEM_BitlockerKeyBackup

## Overview

PowerShell scripts designed to manage BitLocker key backup to Azure Active Directory (AAD) using Microsoft Intune's Proactive Remediations (now Remediations) feature. These scripts are particularly useful when managing BitLocker keys in a Microsoft Endpoint Manager (MEM) environment.

## Scripts

This repository contains the following scripts:

- `Detect_BitlockerKeyBackup.ps1`: This script retrieves the BitLocker key backup status of a Windows device. It checks the BitLocker Management event log for event ID 845 and checks if the level of the event is "Information". If the event is found and is specifically for the system drive, it means the BitLocker key backup to Azure AD was successful. If the script finds the event, it will exit with code 0, indicating a successful backup. If it doesn't find the event, it will exit with a non-zero code, indicating that the backup was not successful.

- `Fix_BitlockerKeyBackup.ps1`: This script retrieves the BitLocker recovery key of the local computer and then attempts to backup the key to Azure Active Directory. The script uses the BitLocker WMI interface to retrieve the recovery key and the AzureAD PowerShell module to backup the key to Azure AD.

## Usage

To use these scripts, clone the repository to your local machine or download the individual PS1 files. Run each script in a PowerShell environment with appropriate administrative privileges.

For usage via Microsoft Intune's Remediations feature, follow these steps:

1. Clone or download the scripts from this repository.
2. In the Microsoft Intune admin center, select Devices and then Remediations.
3. Click on "+ New Remediation" to create a new remediation.
4. In the new remediation, provide a name and description, and upload the PowerShell scripts from this repository. The `Detect_BitlockerKeyBackup.ps1` script will be used for detection and the `Fix_BitlockerKeyBackup.ps1` script will be used for remediation.
5. Assign the remediation to a group of devices in the Assignments section of the remediation.
6. Monitor the progress and success of the remediation in the Overview section.

In the context of Intune's Remediations feature, the `Fix_BitlockerKeyBackup.ps1` script will only run if the `Detect_BitlockerKeyBackup.ps1` script exits with a non-zero code, indicating that the BitLocker key backup to Azure AD was not successful.

## References and Inspiration

The scripts in this repository are based on and inspired by the following resources:

- [Using BitLocker recovery keys with Microsoft Endpoint Manager](https://techcommunity.microsoft.com/t5/intune-customer-success/using-bitlocker-recovery-keys-with-microsoft-endpoint-manager/ba-p/2255517)
- [How to force escrowing of Bitlocker recovery keys using Intune](https://rahuljindalmyit.blogspot.com/2021/06/how-to-force-escrowing-of-bitlocker.html)


## License

This project is licensed under the MIT License.

