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

Write-Host "`n`n"

# Call functions
$encryptedDrives = Test-AllDrivesEncryption
$bitlockerinfo = Get-BitLockerVolumeInfo
$bitlockerOS = Test-AzureADBitLockerBackup

$txtStatus = "$encryptedDrives[$bitlockerinfo]"

Write-Host "`n`n"

#Return result
if ($bitlockerOS -eq 0) {
    Write-Host "OK $([datetime]::Now) : $txtStatus"
    Exit 0
}
elseif ($bitlockerOS -eq 1) {
    Write-Host "WARNING $([datetime]::Now) : $txtStatus"
    Exit 1
}
else {
    Write-Host "NOTE $([datetime]::Now) : $txtStatus"
    Exit 0
}
