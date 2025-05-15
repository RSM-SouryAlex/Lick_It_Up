<#
.SYNOPSIS
  To get all users that have O365 E1, O365 E3 and EOP P1, their last successful sign in date, and if they have signed in after a specific date.   

.DESCRIPTION
  This script will assess each user that is assigned the specified licenses and determine if they have signed in after a specific date.

.NOTES
  Version:        1.0
  Author:         Ben Seaba
  Creation Date:  12/12/2023
  Purpose/Change: Initial assessment accounts with specific licenses


#>
# Ensure Module Installed Function
Function Ensure-ModuleInstalled {
    Param(
        [string]$ModuleName,
        [string]$ModuleBetaName
    )
    foreach ($module in @($ModuleName, $ModuleBetaName)) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Install-Module $module -Force -AllowClobber
            Import-Module $module
        }
    }
}

# Check and install required modules
Ensure-ModuleInstalled -ModuleName "Microsoft.Graph" -ModuleBetaName "Microsoft.Graph.Beta"

# Connect to Microsoft Graph with necessary scopes
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "AuditLog.Read.All"

# Fetch License Details
#$licenseDetails = Get-MgSubscribedSku

# Define the SKUs for Office 365 E1, Office 365 E3, and Exchange Online Plan 1
#$e1Sku = $licenseDetails | Where-Object { $_.SkuPartNumber -eq "STANDARDPACK" } # Office 365 E1
#$e3Sku = $licenseDetails | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPACK" } # Office 365 E3
#$exchangeOnlinePlan1Sku = $licenseDetails | Where-Object { $_.SkuPartNumber -eq "EXCHANGESTANDARD" } # Exchange Online Plan 1

# Define the target date for comparison
$targetDate = [DateTime]::ParseExact("11/25/2023 12:00:00 AM", "MM/dd/yyyy h:mm:ss tt", [Globalization.CultureInfo]::InvariantCulture)

# Get all users with signInActivity
$users = Get-MgBetaUser -All -ConsistencyLevel eventual -Filter "UserType eq 'Member'" -Select id, displayName, UserPrincipalName, UserType, SignInActivity

# Define the path for the CSV file
$csvPath = "FilteredUsers.csv"

# Filter users with specific licenses and capture their last successful sign-in date
$filteredUsers = foreach ($user in $users) {
    if (($user.UserType -eq 'Member')) {
        
        $lastSignIn = $user.SignInActivity.LastSuccessfulSignInDateTime
        $lastNonInteractiveSignIn = $user.SignInActivity.LastNonInteractiveSignInDateTime
        $lastSignInDate = $null
        $lastNonInteractiveSignInDate = $null

        # Check if last sign-in date is not empty and is a valid date
        if (![string]::IsNullOrWhiteSpace($lastSignIn)) {
            try {
                # Adjust the date parsing to match the expected format from Graph API
                $lastSignInDate = [DateTime]::ParseExact($lastSignIn, "MM/dd/yyyy HH:mm:ss", [Globalization.CultureInfo]::InvariantCulture)
                $lastNonInteractiveSignInDate = [DateTime]::ParseExact($lastNonInteractiveSignIn, "MM/dd/yyyy HH:mm:ss", [Globalization.CultureInfo]::InvariantCulture)

            } catch {
                Write-Warning "Invalid date format for user $($user.DisplayName): $lastSignIn"
            }
        }

        [PSCustomObject]@{
            DisplayName = $user.DisplayName
            UserPrincipalname = $user.UserPrincipalName
            UserObjectID = $user.Id
            LastSuccessfulSignInDateTime = $lastSignInDate
            LastNonInteractiveSuccessfulSignIn = $lastNonInteractiveSignInDate
            SignedInSinceTargetDate = if ($lastSignInDate -and $lastSignInDate -gt $targetDate) { $True } else { $False }
            NonInteractiveSignedInSinceTargetDate = if ($lastNonInteractiveSignInDate -and $lastNonInteractiveSignInDate -gt $targetDate) { $True } else { $False }
        }
    }
}

# Export the filtered users to a CSV file
$filteredUsers | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "Data exported to $csvPath"

Disconnect-MgGraph