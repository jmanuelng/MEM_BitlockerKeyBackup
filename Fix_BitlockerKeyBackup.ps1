

function Backup-BitLockerKeyToAAD {
    <#
    .SYNOPSIS
        Used to backup BitLocker recovery key to Azure Active Directory (AAD).

    .DESCRIPTION
        Script retrieves the BitLocker recovery key of the local computer and then attempts to backup the key to Azure Active Directory.

    .NOTES
        Run this script as an administrator.
    #>
    [CmdletBinding()]
    param (
    )

    Begin {
        Write-Host "Starting BitLocker Key Backup process to Azure AD." -ForegroundColor Cyan
    }

    Process {
        try {
            # Get BitLocker volumes
            $BitLockerVolumes = Get-BitLockerVolume -ErrorAction Stop

            $volumeInfoArray = @()

            foreach ($BitLockerVolume in $BitLockerVolumes) {
                # Construct a single string that contains volume type, mount point, volume status, encryption percentage, and key protector type
                $volumeInfo = "Volume Type: $($BitLockerVolume.VolumeType), Mount Point: $($BitLockerVolume.MountPoint), Volume Status: $($BitLockerVolume.VolumeStatus), Encryption Percentage: $($BitLockerVolume.EncryptionPercentage), KeyProtector Type: $($BitLockerVolume.KeyProtector[0].KeyProtectorType)"

                $volumeInfoArray += $volumeInfo

                # Get KeyProtector IDs for the BitLocker volume
                $KeyProtectorIds = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -ExpandProperty KeyProtectorID

                foreach ($KeyProtectorId in $KeyProtectorIds) {
                    # Backup the BitLocker Key to Azure AD
                    BackupToAAD-BitLockerKeyProtector -MountPoint $BitLockerVolume.MountPoint -KeyProtectorId $KeyProtectorId
                    Write-Host "Successfully backed up BitLocker Key for volume $($BitLockerVolume.MountPoint) to Azure AD." -ForegroundColor Green
                }
            }

            # Output all drive info as a single string, with each drive separated by a dot
            $driveInfoString = $volumeInfoArray -join '. '

        }
        catch {
            Write-Host "Failed to backup BitLocker Key to Azure AD: $_" -ForegroundColor Red
        }
    }

    End {
        Write-Host "`n`n"
        Write-Host "BitLocker Key Backup process to Azure AD completed." -ForegroundColor Cyan
        Write-Host $driveInfoString
    }
}


Write-Host "`n`n"

# Call the function
Backup-BitLockerKeyToAAD