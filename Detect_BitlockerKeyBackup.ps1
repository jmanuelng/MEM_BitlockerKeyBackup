#region Functions
function Test-DeviceJoinStatus {
    <#
    .SYNOPSIS
        Verifies the Azure AD and Domain join status of a device.

    .DESCRIPTION
        The function checks if the device is joined to Azure AD and/or a traditional AD domain.

    .NOTES
        The function returns a custom object with properties StatusCode and Summary. StatusCode is 0 if the device is Azure AD Joined, 1 if not. 
        Summary provides a summary string of the device's join status, including the hostname.
        - Function was added to get more detail on the device. For Main function, if device is not AADJ, then there is no way to backup Bitlocker keys to AADJ.
          So, in main script, if device is not AADJ then document details, but do Exit 0, since Fix becomes irrelevant, and a fail is just noise.
    #>
    [CmdletBinding()]
    param (
    )

    try {
        # Capture the output of the dsregcmd command, specifically looking for lines containing "AzureAdJoined" or "DomainJoined"
        $result = dsregcmd /status | findstr /i "AzureAdJoined DomainJoined"

        # If the command fails to execute, an exception is thrown
        if ($null -eq $result) {
            throw "Failed to execute dsregcmd command."
        }

        # Check the result for "AzureAdJoined : YES" - if it exists, the device is Azure AD joined
        $AzureAdJoined = if($result -match "AzureAdJoined : YES"){"Yes"} else {"No"}

        # Similarly, check the result for "DomainJoined : YES" - if it exists, the device is Domain joined
        $DomainJoined = if($result -match "DomainJoined : YES"){"Yes"} else {"No"}

        # Retrieve the hostname of the device
        $hostname = $env:COMPUTERNAME

        # Compile the findings into a summary string, now including the hostname
        $summary = "Hostname = $hostname - AADJ = $AzureAdJoined, ADJ = $DomainJoined. "

        # Define status code based on Azure AD join status
        $statusCode = if ($AzureAdJoined -eq "Yes") { 0 } else { 1 }

        # Return a custom object with properties StatusCode and Summary
        return New-Object PSObject -Property @{
            StatusCode = $statusCode
            Summary = $summary
        }
    }
    catch {
        # Catch any errors that occurred during execution
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }
}


function Test-AzureADBitLockerBackup {
    <#
    .SYNOPSIS
        Check the BitLocker Management event log for event ID 845 to confirm successful backup of BitLocker key to Azure AD for the system drive.

    .DESCRIPTION
        This function queries the BitLocker Management event log for event ID 845 and checks if the level of the event is "Information". 
        If the event is found and is specifically for the system drive, it means the BitLocker key backup to Azure AD was successful.

    .PARAMETER nDays
        The number of past days to check for the event. The default is 1.

    .NOTES
        Run this script as an administrator.

        Information and/or References:
            https://techcommunity.microsoft.com/t5/intune-customer-success/using-bitlocker-recovery-keys-with-microsoft-endpoint-manager/ba-p/2255517

    .EXAMPLE
        Test-AzureADBitLockerBackup -nDays 7
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [int]
        $nDays = 1
    )

    try {
        # Get the date nDays ago
        $pastDate = (Get-Date).AddDays(-$nDays)

        # Get the system drive from the environment variables
        $systemDrive = $env:SystemDrive

        # Get the BitLocker Management event log events with ID 845 and Level 4 (Information) from the past nDays
        $events = Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-BitLocker/BitLocker Management"; ID=845; Level=4; StartTime=$pastDate} -ErrorAction Stop

        # If events exist, check if any of them are for the system drive
        if ($events) {
            foreach ($event in $events) {
                $eventData = [xml]$event.ToXml()
                $volume = $eventData.Event.EventData.Data | Where-Object {$_.Name -eq 'VolumeMountPoint'} | Select-Object -ExpandProperty '#text'
                if ($volume -eq $systemDrive) {
                    Write-Host "BitLocker key backup to Azure AD for the system drive ($systemDrive) was successful in the past $nDays day(s)." -ForegroundColor Green
                    return 0
                }
            }

            Write-Host "No events found in the past $nDays day(s) indicating successful BitLocker key backup to Azure AD for the system drive ($systemDrive)." -ForegroundColor Yellow
            return 1
        } else {
            Write-Host "No events found in the past $nDays day(s) indicating successful BitLocker key backup to Azure AD." -ForegroundColor Yellow
            return 1
        }
    }
    catch {
        Write-Host "Failed to query BitLocker Management event log: $_" -ForegroundColor Red
        return 1
    }
}

function Test-OSBitLockerStatus {
    <#
    .SYNOPSIS
        Checks if the system drive is BitLocker encrypted.

    .DESCRIPTION
        The function checks if the system drive on a computer is BitLocker encrypted. It returns 0 if the system drive is encrypted, and 1 if it's not.

    .NOTES
        Run this script with administrator privileges.

        Original idea was to use this function, it is no longer used. Instead we use Test-AzureADBitLockerBackup as it confirms successful Key backup to AzureAD
    #>

    # Identify the system drive
    $systemDrive = [Environment]::GetFolderPath("System").Substring(0,2)

    # Get the BitLocker volume status for the system drive
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $systemDrive

    # Check if BitLocker protection is enabled for the system drive
    if ($BitLockerVolume.ProtectionStatus -eq 'On') {
        # System drive is encrypted with BitLocker
        return 0
    }
    else {
        # System drive is not encrypted with BitLocker
        return 1
    }
}


function Test-AllDrivesEncryption {
    <#
    .SYNOPSIS
        Checks all drives to see if they are encrypted with BitLocker.

    .DESCRIPTION
        The function iterates over all drives, checks each one for BitLocker encryption and builds a summary.

    .NOTES
        Returns a summary string of the encryption status of all drives.
    #>

    [CmdletBinding()]
    param ()

    # Initialize the summary string
    $summary = ""

    try {
        # Get all BitLocker volumes
        $BitLockerVolumes = Get-BitLockerVolume -ErrorAction Stop

        foreach ($BitLockerVolume in $BitLockerVolumes) {
            # Check the encryption status of the volume
            if ($BitLockerVolume.EncryptionMethod -eq "None") {
                $summary += "Drive $($BitLockerVolume.MountPoint) not encrypted. "
            }
            else {
                $summary += "Drive $($BitLockerVolume.MountPoint) encrypted. "
            }
        }
    }
    catch {
        # If an error occurred, add it to the summary
        $summary += "Failed to get BitLocker status: $($_.Exception.Message). "
    }

    # Return the summary string
    return $summary
}


function Get-BitLockerVolumeInfo {
    <#
    .SYNOPSIS
        Used to retrieve BitLocker volume information.

    .DESCRIPTION
        This script retrieves the BitLocker volume information of the local computer. For each volume, it presents volume type, mount point, volume status, encryption percentage, and key protector type.

    .NOTES
        Run this script as an administrator.
    #>
    [CmdletBinding()]
    param (
    )

    Begin {
        Write-Host "Starting BitLocker volume information retrieval process." -ForegroundColor Cyan
    }

    Process {
        try {
            # Get BitLocker volumes
            $BitLockerVolumes = Get-BitLockerVolume -ErrorAction Stop

            $volumeInfoArray = @()

            foreach ($BitLockerVolume in $BitLockerVolumes) {
                # Construct a single string that contains volume type, mount point, volume status, encryption percentage, and key protector type
                $volumeInfo = "Volume Type: $($BitLockerVolume.VolumeType), Mount Point: $($BitLockerVolume.MountPoint), Volume Status: $($BitLockerVolume.VolumeStatus), Encryption Percentage: $($BitLockerVolume.EncryptionPercentage), KeyProtector Type: $($BitLockerVolume.KeyProtector[0].KeyProtectorType)"

                # Add this volume information to the array
                $volumeInfoArray += $volumeInfo

                Write-Host "Successfully retrieved BitLocker volume information for $($BitLockerVolume.MountPoint)." -ForegroundColor Green
            }

            # Combine all volume information strings into a single string, separated by dots
            $volumeInfoString = $volumeInfoArray -join '. '

            # Output the single string that contains information for all volumes
            Write-Host $volumeInfoString
        }
        catch {
            Write-Host "Failed to retrieve BitLocker volume information: $_" -ForegroundColor Red
        }
    }

    End {
        Write-Host "BitLocker volume information retrieval process completed." -ForegroundColor Cyan
        return $volumeInfoString
    }
}

#endregion Functions

Write-Host "`n`n"

#region Main

$txtStatus = ""

# Call functions

$adJoined = Test-DeviceJoinStatus               
$txtStatus += "$($adJoined.Summary)"                        #Document domain join info. No matter the result, we want to upload info to Intune.

# Is device Azure AD Joined? if not, there's nothing to do here, can't backup bitlocker keys to AAD. Document drive status, send info to Intune.
if ($($adJoined.StatusCode) -eq 0) {
    $bitlockerBackupStatus = Test-AzureADBitLockerBackup -nDays 7     #Bitlocker keys have been sucessfully backed up to Azure AD?
}
else {
    $bitlockerBackupStatus = -2
}
$encryptedDrives = Test-AllDrivesEncryption                 #Check encryption status of device drives.
$bitlockerinfo = Get-BitLockerVolumeInfo                    #Get Bitlocker info for devices drives, info will get uploaded to Intune Remediation status.


# Build summary text of findings and status.
$txtStatus += "$encryptedDrives"
if ($bitlockerinfo -ne "") {
    $txtStatus += "[$bitlockerinfo]"                                #Add bitlocker detailed info, only if we were able to get it.
}


Write-Host "`n`n"

#Return result. Last line of script is automatically uploaded to Intune, can be seen in the "Output" columns of Remediation Device Status.
# If the BitLocker key has been successfully backed up to Azure AD ($bitlockerBackupStatus equals 0),
# it prints an OK message along with the current date and time, and the status text stored in $txtStatus.
# Then it exits the script with a success status code (0).
if ($bitlockerBackupStatus -eq 0) {
    Write-Host "OK $([datetime]::Now) : $txtStatus"
    Exit 0
}

# If the BitLocker key backup to Azure AD has failed ($bitlockerBackupStatus equals 1),
# it prints a FAIL message along with the current date and time, and the status text stored in $txtStatus.
# Then it exits the script with an error status code (1). This will call the Remediation script.
elseif ($bitlockerBackupStatus -eq 1) {
    Write-Host "FAIL $([datetime]::Now) : $txtStatus"
    Exit 1
}

# If the value of $bitlockerBackupStatus is anything other than 0 or 1,
# it prints a WARNING message along with the current date and time, and the status text stored in $txtStatus.
# Then it exits the script with a success status code (0). No need to execute Remediation script, 
#   but something is wrong, something that can't be fix with Remediation script.
else {
    Write-Host "WARNING $([datetime]::Now) : $txtStatus"
    Exit 0
}

#endregion Main