Connect-MgGraph -Scopes "RoleManagement.Read.Directory","User.Read.All","Policy.Read.All","Group.Read.All","Domain.Read.All","Directory.Read.All"
Connect-ExchangeOnline
Get-MgContext


$OutputDir = "C:\Users\e060080\OneDrive - RSM\M365Scan\ISPN"
$Domain = "ISPN"
New-OutputDir -OutputDir "C:\Users\e060080\OneDrive - RSM\M365Scan\ISPN" -Domain 'ISPN'

# Collect Data



$CISEVAL = Invoke-CISEvaluation -OutputDir $OutputDir -Domain $Domain
$CISEVAL |ft

$CISEVAL | epcsv $OutputDir\WarningList.csv -NoTypeInformation


Disconnect-MgGraph

Break


#region Microsoft Admin Center 1.x

<#
.Synopsis
   (L1) Ensure Administrative accounts are cloud-only (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.1.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $AllUsers = Get-MgUser -All -Property DisplayName,UserPrincipalName,AssignedLicenses,ProxyAddresses,RefreshTokensValidFromDateTime,LastPasswordChangeDateTime,OnPremisesImmutableId,Id | select DisplayName,UserPrincipalName,@{l='IsLicensed';e={if($_.AssignedLicenses){'Licensed'}}},@{l='Email';e={[string]::join(', ',$_.ProxyAddresses)}},RefreshTokensValidFromDateTime,@{l='PasswordLastSet';e={$_.LastPasswordChangeDateTime}},OnPremisesImmutableId,Id
    $AllUsers | epcsv $OutputDir\AllUsers-$Domain.csv -NoTypeInformation
    $PrivilegedUsers = Get-MgDirectoryRole | % {Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id} | Select-Object Id -Unique | % {Get-MgUser -UserId $_.Id -Property DisplayName,UserPrincipalName,AssignedLicenses,OnPremisesImmutableId,Id | select DisplayName,UserPrincipalName,@{l='Licenses';e={[string]::join(',',$_.AssignedLicenses.Skuid)}},OnPremisesImmutableId,Id}
    $PrivilegedUsers | epcsv -Path $OutputDir\PrivilegedUsers-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure that between two and four global admins are designated (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.1.3
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $PrivilegedUsers | ? DisplayName -NotLike "*Directory Sync*" | epcsv $OutputDir\SyncedAdmins-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure administrative accounts use licenses with a reduced application footprint (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.1.4
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $Licenses = foreach($PUser in $PrivilegedUsers)
    {
        $SkuPN = (Get-MgUserLicenseDetail -UserId $PUser.id).SkuPartNumber
        if($SkuPN)
        {
            $AssignedLicenses = [string]::join(",",$SkuPN)
        }
        else
        {
            $AssignedLicenses = 'n/a'
        }

        [pscustomobject]@{
            DisplayName = $PUser.DisplayName
            UserPrincipalName = $PUser.UserPrincipalName
            OnPremisesImmutableId = $PUser.OnPremisesImmutableId
            AssignedLicenses = $AssignedLicenses
        }
    }

    $Licenses | epcsv -Path $OutputDir\AdminAssignedLicenses-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L2) Ensure that only organizationally managed/approved public groups exist (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.2.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-mgGroup | Select DisplayName,@{l='Type';e={[string]::join(', ',$_.GroupTypes)}},Description,MailEnabled,OnPremisesSyncEnabled,Visibility | epcsv -Path $OutputDir\MgGroups-$Domain.csv -NoTypeInformation
}

function Get-CIS_SharedMailboxSignInStatus 
{
    <#
    .SYNOPSIS
        Retrieves all shared mailboxes and their sign-in status for CIS Benchmark 1.2.2.

    .DESCRIPTION
        Lists all shared mailboxes with their UserPrincipalName, DisplayName, and whether sign-in is allowed (AccountEnabled).
        You can filter the results manually for compliance checks.

    .OUTPUTS
        [PSCustomObject] with DisplayName, UserPrincipalName, and SignInAllowed fields.

    .EXAMPLE
        Get-CIS_SharedMailboxSignInStatus | Where-Object { $_.SignInAllowed -eq $true }
    #>

    [CmdletBinding()]
    param()

    if (-not (Get-Command Get-Mailbox -ErrorAction SilentlyContinue)) {
        Write-Error "ExchangeOnline PowerShell module not available or not connected. Run Connect-ExchangeOnline first."
        return
    }

    if (-not (Get-Command Get-MgUser -ErrorAction SilentlyContinue)) {
        Write-Error "Microsoft Graph module not available or not connected. Run Connect-MgGraph first."
        return
    }

    $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited

    $results = foreach ($mailbox in $sharedMailboxes) {
        $user = Get-MgUser -UserId $mailbox.UserPrincipalName -Property AccountEnabled -ErrorAction SilentlyContinue 
        if ($null -ne $user) {
            [PSCustomObject]@{
                DisplayName        = $mailbox.DisplayName
                UserPrincipalName  = $mailbox.UserPrincipalName
                SignInAllowed      = $user.AccountEnabled
            }
        } else {
            [PSCustomObject]@{
                DisplayName        = $mailbox.DisplayName
                UserPrincipalName  = $mailbox.UserPrincipalName
                SignInAllowed      = $null  # Unable to resolve user
            }
        }
    }

    return $results
}

<#
.Synopsis
   (L1) Ensure sign-in to shared mailboxes is blocked (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.2.2
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $SharedMailboxSignInStatus = Get-CIS_SharedMailboxSignInStatus 
    $SharedMailboxSignInStatus | epcsv $OutputDir\SharedMailboxSignInStatus-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)' (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.3.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-MgDomain | select id,PasswordValidityPeriodInDays | epcsv $OutputDir\PasswordExpirationPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L2) Ensure 'External sharing' of calendars is not available (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.3.3
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-SharingPolicy -Identity "Default Sharing Policy" | epcsv $OutputDir\DefaultSharingPolicy-$Domain.csv -NoTypeInformation
} 

<#
.Synopsis
   (L2) Ensure the customer lockbox feature is enabled (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Admin_1.3.6
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled | epcsv $OutputDir\CustomerLockBox-$Domain.csv -NoTypeInformation
}


#endregion


#region Microsoft 365 Defender 2.x

<#
.Synopsis
   (L2) Ensure Safe Links for Office Applications is Enabled (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-SafeLinksPolicy | Select Name,EnableSafe*,*click*,ScanUrls,EnableFor*,DeliverMessageAfterScan,DisableUrlRewrite | epcsv $OutputDir\SafeLinksPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure the Common Attachment Types Filter is enabled (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.2
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-MalwareFilterPolicy | epcsv $OutputDir\MalwareFilterPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L2) Ensure Safe Attachments policy is enabled (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.4
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-SafeAttachmentPolicy | select Name,enable | epcsv $OutputDir\SafeAttachmentPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L2) Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.5
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-AtpPolicyForO365 | Select Name,EnableATPForSPOTeamsODB,EnableSafeDocs,AllowSafeDocsOpen | epcsv $OutputDir\AtpPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure Exchange Online Spam Policies are set to notify administrators (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.6
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-HostedOutboundSpamFilterPolicy | epcsv $OutputDir\HostedOutboundSpamFilterPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L2) Ensure that an anti-phishing policy has been created (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.7
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $params = @(
        "name","Enabled","PhishThresholdLevel","EnableTargetedUserProtection"
        "EnableOrganizationDomainsProtection","EnableMailboxIntelligence"
        "EnableMailboxIntelligenceProtection","EnableSpoofIntelligence"
        "TargetedUserProtectionAction","TargetedDomainProtectionAction"
        "MailboxIntelligenceProtectionAction","EnableFirstContactSafetyTips"
        "EnableSimilarUsersSafetyTips","EnableSimilarDomainsSafetyTips"
        "EnableUnusualCharactersSafetyTips","TargetedUsersToProtect"
        "HonorDmarcPolicy"
    )
    Get-AntiPhishPolicy | Select $params | epcsv $OutputDir\AntiPhishPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure that DKIM is enabled for all Exchange Online Domains (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.9
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-DkimSigningConfig | epcsv $OutputDir\DKIMsigningConfig-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure the connection filter IP allow list is not used (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.12
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-HostedConnectionFilterPolicy | epcsv $OutputDir\HostedConnectionFilterPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure inbound anti-spam policies do not contain allowed domains (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-Defender_2.1.14
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-HostedContentFilterPolicy  | epcsv $OutputDir\HostedContentFilterPolicy-$Domain.csv -NoTypeInformation
}


#endregion


#region Microsoft Purview 3.x

<#
.Synopsis
   (L1) Ensure Microsoft 365 audit log search is Enabled (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-MSPurview_3.1.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-AdminAuditLogConfig | epcsv $OutputDir\AdminAuditLogConfig-$Domain.csv -NoTypeInformation
}


#endregion 


#region Microsoft Entra Admin Center

<#
.Synopsis
   (L2) Ensure third party integrated applications are not allowed (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-EntraAdmin_5.1.2.2
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | select Allowed*,@{l='PermissionGrantPoliciesAssigned';e={[string]::Join(', ',$_.PermissionGrantPoliciesAssigned)}} | epcsv $OutputDir\AuthorizationPolicy-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure a dynamic group for guest users is created (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-EntraAdmin_5.1.3.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $groups = Get-MgGroup 
    $groups | epcsv $OutputDir\MgGroups-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L2) Ensure user consent to apps accessing company data on their behalf is not allowed (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-EntraAdmin_5.1.5.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object -ExpandProperty PermissionGrantPoliciesAssigned | Out-File $OutputDir\AuthPolicyUserRolePerm-$Domain.txt 
}

<#
.Synopsis
   (L1) Ensure that guest user access is restricted (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function COllect-EntraAdmin_5.1.6.2
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $MgAuthorizationPolicy = Get-MgPolicyAuthorizationPolicy
    $MgAuthorizationPolicy | select GuestUserRoleId | epcsv $OutputDir\GuestUserRoleId-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L2) Ensure guest user invitations are limited to the Guest Inviter role (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-EntraAdmin_5.1.6.3
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $MgAuthorizationPolicy | select AllowInvitesFrom | epcsv $OutputDir\AllowInvitesFrom-$Domain.csv -NoTypeInformation
}

<#
.Synopsis
   (L1) Ensure that password hash sync is enabled for hybrid deployments (Automated)

.DESCRIPTION
   Long description

.EXAMPLE
   Example of how to use this cmdlet
#>
function Collect-EntraAdmin_5.1.8.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-MgOrganization | Select OnPremisesSyncEnabled | epcsv $OutputDir\OnPremisesSyncEnabled-$Domain.csv -NoTypeInformation
}



#endregion


#region Exchange Admin Center

Get-AcceptedDomain | epcsv $OutputDir\AcceptedDomain-$Domain.csv -NoTypeInformation


#  6.1.1 (L1) Ensure 'AuditDisabled' organizationally is set to 'False' (Automated)

function Collect-Exo_6.1.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-OrganizationConfig | epcsv $OutputDir\OrganizationConfig-$Domain.csv -NoTypeInformation
}



# 6.1.2 (L1) Ensure mailbox auditing for E3 users is Enabled (Automated)

function Collect-Exo_6.1.2
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $MailAudit = Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited | Select UserPrincipalName,AuditEnabled
    $MailAudit | epcsv $OutputDir\MailboxAudit-$Domain.csv -NoTypeInformation
}



# 6.1.4 (L1) Ensure 'AuditBypassEnabled' is not enabled on mailboxes (Automated)

function Collect-Exo_6.1.4
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $MBX = Get-MailboxAuditBypassAssociation -ResultSize unlimited
    $MBX | epcsv $OutputDir\MailboxAuditBypass-$Domain.csv -NoTypeInformation

}



# 6.2.1 (L1) Ensure all forms of mail forwarding are blocked and/or disabled (Automated)

function Collect-Exo_6.2.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $TransportRule = Get-TransportRule | Select Name,State,Priority,RedirectMessageTo,SenderDomainIs,setscl,Description 
    $TransportRule | epcsv $OutputDir\TransportRules-$Domain.csv -NoTypeInformation
}




# 6.2.2 (L1) Ensure mail transport rules do not whitelist specific domains (Automated)


# 6.2.3 (L1) Ensure email from external senders is identified (Automated)

function Collect-Exo_6.2.3
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-ExternalInOutlook | epcsv $OutputDir\ExternalInOutlook-$Domain.csv -NoTypeInformation
}




# 6.3.1 (L2) Ensure users installing Outlook add-ins is not allowed (Automated)

function Collect-Exo_6.3.1
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    $pol = Get-RoleAssignmentPolicy | Where-Object {$_.AssignedRoles -like "*Apps*"} | Select-Object Identity, @{Name="AssignedRoles"; Expression={
    Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | 
    ForEach-Object { 
        Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | 
        Select -ExpandProperty AssignedRoles}}}

    $pol | select Identity,@{l='AssignedRoles';e={[string]::join(',',$_.AssignedRoles)}} | epcsv $OutputDir\RoleAssignmentPolicy-$Domain.csv -NoTypeInformation
}



# 6.5.1 (L1) Ensure modern authentication for Exchange Online is enabled (Automated)


# 6.5.2 (L1) Ensure MailTips are enabled for end users (Automated)


# 6.5.3 (L2) Ensure additional storage providers are restricted in Outlook on the web (Automated)

function Collect-Exo_6.5.3
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-OwaMailboxPolicy | Select Name, AdditionalStorageProvidersAvailable | epcsv $OutputDir\OwaMailboxPolicy-$Domain.csv -NoTypeInformation
}


# 6.5.4 (L1) Ensure SMTP AUTH is disabled (Automated)

function Collect-Exo_6.5.4
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]$OutputDir,
        
        [parameter(Mandatory=$true)]
        [string]$Domain
    )

    Get-TransportConfig | select SmtpClientAuthenticationDisabled | epcsv $OutputDir\TransportConfig-$Domain.csv -NoTypeInformation
}

#endregion










#region Evaluation Functions

function Invoke-Eval_1.1.1
{
    $PrivilegedUsers = ipcsv -Path $OutputDir\PrivilegedUsers-$Domain.csv 
    [int]$Count = ($PrivilegedUsers | ? OnPremisesImmutableId -ne $null).count
    if($Count -gt 0)
    {
        [pscustomobject]@{
            RuleNumber = '1.1.1'     
            Level = 'L1'
            Category = 'Microsoft Admin Center'   
            Rating = 'Fail'
            Status = 'Privileged accounts are sycned from on-premeses environment.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '1.1.1'  
            Level = 'L1' 
            Category = 'Microsoft Admin Center'        
            Rating = 'Pass'
            Status = 'All Privileged accounts are cloud-only provisioned.'
        }

    }
}

function Invoke-Eval_1.1.3
{
    $AdminCount = (ipcsv $OutputDir\SyncedAdmins-$Domain.csv | measure).count

    if($AdminCount -gt 4)
    {
            [pscustomobject]@{
                RuleNumber = '1.1.3'  
                Level = 'L1'    
                Category = 'Microsoft Admin Center'     
                Rating = 'Fail'
                Status = 'There are more than 4 global administrators.'
            }
            return
    }

    if($AdminCount -lt 2)
    {
            [pscustomobject]@{
                RuleNumber = '1.1.3'  
                Level = 'L1'
                Category = 'Microsoft Admin Center'         
                Rating = 'Fail'
                Status = 'There is only 1 global administrator.'
            }
            return
    }
}

function Invoke-Eval_1.1.4
{
    $AdminLicenses = ipcsv $OutputDir\AdminAssignedLicenses-$Domain.csv
    [int]$Problematic = ($AdminLicenses | ? AssignedLicenses -ne 'n/a' | measure).Count

    if($Problematic -gt 0)
    {
        [pscustomobject]@{
            RuleNumber = '1.1.4'
            Level = 'L1'
            Category = 'Microsoft Admin Center'           
            Rating = 'Fail'
            Status = 'Privileged accounts are assinged licenses that expand the attack surface.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '1.1.4'
            Level = 'L1'
            Category = 'Microsoft Admin Center'           
            Rating = 'Pass'
            Status = 'Privileged accounts use licenses with a reduced application footprint.'
        }
    
    }
}

function Invoke-Eval_1.2.1
{
    $PublicGroups = ipcsv $OutputDir\MgGroups-$Domain.csv | ? Visibility -eq Public | select DisplayName,Visibility,Description
    
    if($PublicGroups)
    {
        [pscustomobject]@{
            RuleNumber = '1.2.1'
            Level = 'L2'
            Category = 'Microsoft Admin Center'           
            Rating = 'Fail'
            Status = 'Groups have a Public privacy status.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '1.2.1' 
            Level = 'L2'
            Category = 'Microsoft Admin Center'          
            Rating = 'Pass'
            Status = 'All groups visibility is set to Private.'
        }
    }
}

function Invoke-Eval_1.2.2
{
    $SharedMBX = ipcsv $OutputDir\SharedMailboxSignInStatus-$Domain.csv | ? SignInAllowed -eq $True
    
    if($SharedMBX)
    {
        [pscustomobject]@{
            RuleNumber = '1.2.2' 
            Level = 'L1'
            Category = 'Microsoft Admin Center'          
            Rating = 'Fail'
            Status = 'Sign-in to shared mailboxes is not blocked.'
        }
        $SharedMBX | epcsv $OutputDir\SharedMBX_SignInTrue.csv -NoTypeInformation
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '1.2.2'
            Level = 'L1'
            Category = 'Microsoft Admin Center'           
            Rating = 'Pass'
            Status = 'Sign-in to shared mailboxes is blocked.'
        }
    }
}

function Invoke-Eval_1.3.1
{
    $PasswordPolicy = ipcsv $OutputDir\PasswordExpirationPolicy-$Domain.csv | ? PasswordValidityPeriodInDays -ne '2147483647'
    
    if($PasswordPolicy)
    {
        [pscustomobject]@{
            RuleNumber = '1.3.1' 
            Level = 'L1'
            Category = 'Microsoft Admin Center'          
            Rating = 'Fail'
            Status = 'The Password expiration policy is set to expire passwords.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '1.3.1' 
            Level = 'L1'
            Category = 'Microsoft Admin Center'          
            Rating = 'Pass'
            Status = 'The Password expiration policy is set to Set passwords to never expire.'
        }
    }
}

function Invoke-Eval_1.3.3
{
    $DFSharingPol = ipcsv $OutputDir\DefaultSharingPolicy-$Domain.csv | ? Enabled -eq 'True'
    
    if($DFSharingPol)
    {
        [pscustomobject]@{
            RuleNumber = '1.3.3' 
            Level = 'L2'
            Category = 'Microsoft Admin Center'          
            Rating = 'Fail'
            Status = 'External sharing of calendars is enabled.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '1.3.3'  
            Level = 'L2'
            Category = 'Microsoft Admin Center'         
            Rating = 'Pass'
            Status = 'External sharing of calendars is not available.'
        }
    }
}

function Invoke-Eval_1.3.6
{
    $Lockbox = ipcsv $OutputDir\CustomerLockBox-$Domain.csv | ? CustomerLockboxEnabled -eq 'False'
    
    if($Lockbox)
    {
        [pscustomobject]@{
            RuleNumber = '1.3.6'  
            Level = 'L2'
            Category = 'Microsoft Admin Center'         
            Rating = 'Fail'
            Status = 'The customer lockbox feature is not enabled.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '1.3.6'   
            Level = 'L2'
            Category = 'Microsoft Admin Center'        
            Rating = 'Pass'
            Status = 'The customer lockbox feature is enabled.'
        }
    }
}

function Invoke-Eval_2.1.1
{
    #$SafeLinksOffice = ipcsv $OutputDir\SafeLinksPolicy-$Domain.csv | ? {$_.EnableSafeLinksForEmail -ne 'True' -or $_.EnableSafeLinksForTeams -ne 'True' -or $_.EnableSafeLinksforOffice -ne 'True' -or $_.TrackClicks -ne 'True' -or $_.AllowClickThrough -ne 'False' -or $_.ScanUrls -ne 'True' -or $_.EnableForInternalSenders -ne 'True' -or $_.DeliverMessageAfterScan -ne 'True' -or $_.DisableUrlRewrite -ne 'False'}
    
    $SafeLinks = ipcsv $OutputDir\SafeLinksPolicy-$Domain.csv
    $Result =foreach($pol in $SafeLinks)
    {
        $EnableSafeLinksForEmail  = ($pol | ? EnableSafeLinksForEmail -ne 'True')
        $EnableSafeLinksForTeams  = ($pol | ? EnableSafeLinksForTeams -ne 'True')
        $EnableSafeLinksForOffice = ($pol | ? EnableSafeLinksForOffice -ne 'True')
        $TrackClicks              = ($pol | ? TrackClicks -ne 'True')
        $AllowClickThrough        = ($pol | ? AllowClickThrough -ne 'False')
        $ScanUrls                 = ($pol | ? ScanUrls -ne 'True')
        $EnableForInternalSenders = ($pol | ? EnableForInternalSenders -ne 'True')
        $DeliverMessageAfterScan  = ($pol | ? DeliverMessageAfterScan -ne 'True')
        $DisableUrlRewrite        = ($pol | ? DisableUrlRewrite -ne 'False')

        [System.Collections.ArrayList]$Message = @()
        if($EnableSafeLinksForEmail)
        {
            $Message.Add('Enable safe link for email') | Out-Null
        }
        if($EnableSafeLinksForTeams)
        {
            $Message.Add('Enable safe link for Teams') | Out-Null
        }
        if($EnableSafeLinksForOffice)
        {
            $Message.Add('Enable safe link for Office') | Out-Null
        }
        if($TrackClicks)
        {
            $Message.Add('Track clicks') | Out-Null
        }
        if($AllowClickThrough)
        {
            $Message.Add('Allow click through') | Out-Null
        }
        if($ScanUrls)
        {
            $Message.Add('ScanUrls') | Out-Null
        }
        if($EnableForInternalSenders)
        {
            $Message.Add('Enable for internal senders') | Out-Null
        }
        if($DeliverMessageAfterScan)
        {
            $Message.Add('Deliver message after scan') | Out-Null
        }
        if($DisableUrlRewrite)
        {
            $Message.Add('Disable Url rewrite') | Out-Null
        }
        [pscustomobject]@{
            Identity = $pol.Name
            message = "$($Message -join ', ')"
            }            
    }
    $Fail = $Result | ? Message -ne ''
    $Fail | epcsv $OutputDir\SafeLinks_Failure.csv -NoTypeInformation

    if($Fail)
    {
        [pscustomobject]@{
            RuleNumber = '2.1.1'    
            Level = 'L2'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Fail'
            Status = 'Safe Links for Office applications is not Enabled.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '2.1.1'    
            Level = 'L2'
            Category = 'Microsoft 365 Defender'    
            Rating = 'Pass'
            Status = 'Safe Links for Office applications is enabled.'
        }
    }
}

function Invoke-Eval_2.1.2
{    
    $CommonAttachmentFilter = (ipcsv $OutputDir\MalwareFilterPolicy-$Domain.csv).EnableFileFilter

    if($CommonAttachmentFilter -ne 'True')
    {
        [pscustomobject]@{
            RuleNumber = '2.1.2'    
            Level = 'L1' 
            Category = 'Microsoft 365 Defender'   
            Rating = 'Fail'
            Status = 'Common attachement filter is not enabled.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '2.1.2' 
            Level = 'L1'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Pass'
            Status = 'Common attachment filter is enabled.'
        }
    }
}

function Invoke-Eval_2.1.3
{
    $SenderNotification = ipcsv $OutputDir\MalwareFilterPolicy-$Domain.csv | ? IsDefault -eq 'True' | select Identity,IsDefault,EnableInternalSenderAdminNotifications,InternalSenderAdminAddress

    if($SenderNotification.EnableInternalSenderAdminNotifications -eq 'True' -and $SenderNotification.InternalSenderAdminAddress -eq 'True')
    {
        [pscustomobject]@{
            RuleNumber = '2.1.3' 
            Level = 'L1'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Pass'
            Status = 'Notifications for internal users sending malware is enabled.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '2.1.3' 
            Level = 'L1'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Fail'
            Status = 'Notifications for internal users sending malware is NOT enabled.'
        }
    }
}

function Invoke-Eval_2.1.4
{
    $SafeAttchmentPol = ipcsv $OutputDir\SafeAttachmentPolicy-$Domain.csv

    if($SafeAttchmentPol.Enable -eq 'True')
    {
        [pscustomobject]@{
            RuleNumber = '2.1.4' 
            Level = 'L2'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Pass'
            Status = 'Safe Attachment policy is enabled.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '2.1.4' 
            Level = 'L2'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Fail'
            Status = 'Safe Attachment policy is NOT enabled.'
        }
    }
}

function Invoke-Eval_2.1.5
{
    $AtpPol = ipcsv $OutputDir\AtpPolicy-$Domain.csv

    if($AtpPol.EnableATPForSPOTeamsODB -eq 'True' -and $AtpPol.EnableSafeDocs -eq 'True' -and $AtpPol.AllowSafeDocsOpen -eq 'False')
    {
        [pscustomobject]@{
            RuleNumber = '2.1.5' 
            Level = 'L2'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Pass'
            Status = 'Safe Attachment for SharePoint, OneDrive, and Teams is enabled.'
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '2.1.5' 
            Level = 'L2'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Fail'
            Status = 'Safe Attachment for SharePoint, OneDrive, and/or Teams is NOT enabled.'
        }
    }
}

function Invoke-Eval_2.1.6
{
    $OBSpamFilterPolicy = ipcsv $OutputDir\HostedOutboundSpamFilterPolicy-$Domain.csv | select Name,Enabled,BccSuspiciousOutboundMail,NotifyOutboundSpam,NotifyOutboundSpamRecipients

    [System.Collections.ArrayList]$P = @()
    foreach($pol in $OBSpamFilterPolicy)
    {
    if($pol.enabled)
    {
        if($pol.BccSuspiciousOutboundMail -eq 'True' -and $pol.NotifyOutboundSpam -eq 'True' -and $pol.NotifyOutboundSpamRecipients -ne $null)
        {
            #$p.Add($pol.Name) | Out-Null
        }
        else
        {
            $p.Add($pol.Name) | Out-Null
        }
    }
    else
    {
        $p.Add($pol.Name) | Out-Null
    }
    }
    if($P)
    {
            [pscustomobject]@{
                RuleNumber = '2.1.6' 
                Level = 'L1'
                Category = 'Microsoft 365 Defender'       
                Rating = 'Fail'
                Status = "Exchange Online spam policies are NOT set to notify administrators: $($P -join ', ')"
            }
    }
    else
    {
            [pscustomobject]@{
                RuleNumber = '2.1.6' 
                Level = 'L1'
                Category = 'Microsoft 365 Defender'       
                Rating = 'Pass'
                Status = 'Exchange Online spam policies are set to notify administrators.'
            }

    }
}

function Invoke-Eval_2.1.7
{
    $AntiPhishPol = ipcsv $OutputDir\AntiPhishPolicy-$Domain.csv 

    [System.Collections.ArrayList]$P = @()
    foreach($pol in $AntiPhishPol)
    {
        if($pol.Enabled -eq 'True' -and $pol.PhishThresholdLevel -eq '3' -and $pol.EnableTargetedUserProtection -eq 'True' -and $pol.EnableOrganizationDomainsProtection -eq 'True' -and $pol.EnableMailboxIntelligence -eq 'True' -and $pol.EnableMailboxIntelligenceProtection -eq 'True' -and $pol.EnableSpoofIntelligence -eq 'True' -and $pol.TargetedDomainProtectionAction -eq 'Quarantine' -and $pol.TargetedUserProtectionAction -eq 'Quarantine' -and $pol.MailboxIntelligenceProtectionAction -eq 'Quarantine' -and $pol.EnableFirstContactSafetyTips -eq 'True' -and $pol.EnableSimilarUsersSafetyTips -eq 'True' -and $pol.EnableSimilarDomainsSafetyTips -eq 'True' -and $pol.EnableUnusualCharactersSafetyTips -eq 'True' -and $pol.TargetedUsersToProtect -ne '' -and $pol.HonorDmarcPolicy -eq 'True')
        {
            #pass
        }
        else
        {
            $P.Add($pol.Name) | Out-Null
        }
    }

    if($P)
    {
        [pscustomobject]@{
            RuleNumber = '2.1.7' 
            Level = 'L2'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Fail'
            Status = "Anti-phish policy has NOT been created or does NOT match desired configuration: $($P -join ', ')"
        }
    }
    else
    {
        [pscustomobject]@{
            RuleNumber = '2.1.7' 
            Level = 'L2'
            Category = 'Microsoft 365 Defender'       
            Rating = 'Pass'
            Status = 'Anti-phish policy has been created and matches desired configuration.'
        }
    }
}

function Invoke-Eval_2.1.8
{
    $AcceptedDomain = ipcsv $OutputDir\AcceptedDomain-$Domain.csv | ? DomainName -NotLike '*onmicrosoft.com'

    [System.Collections.ArrayList]$D = @()
    [System.Collections.ArrayList]$SF = @()
    foreach($Dom in $AcceptedDomain)
    {    
        $spf = Resolve-DnsName -Type TXT -Name $Dom.DomainName | Where-Object Strings -like "*spf*" | Select -ExpandProperty Strings

        if($spf -notlike "v=spf*")
        {
            $D.Add($Dom.DomainName) | Out-Null
        }

        if($spf -like "*~all*")
        {
            $SF.Add($Dom.DomainName) | Out-Null
        }
    }
    $NoSPF = [string]$($D -join ', ')
    $SoftF = [string]$($SF -join ', ')

    if($NoSPF)
    {
        $message = "All domains do NOT have a published SPF record: $NoSPF"
        $Rating = 'Fail'
    }

    if($SoftF)
    {
        $message = "SPF NOT optimally set. Soft Fail enabled: $SoftF"
        $Rating = 'Fail'
    }

    if(!($NoSPF -or $SoftF))
    {
        $message = "All domains have a publised SPF record."
        $Rating = 'Pass'
    }

    [pscustomobject]@{
        RuleNumber = '2.1.8' 
        Level = 'L2'
        Category = 'Microsoft 365 Defender'       
        Rating = $Rating
        Status = $message
    }
}

function Invoke-Eval_2.1.9
{
    $NoDKIM = ipcsv $OutputDir\DKIMsigningConfig-$Domain.csv | ? {$_.Domain -notlike "*onmicrosoft.com" -and $_.Enabled -eq 'False'} | select Domain,Enabled

    [System.Collections.ArrayList]$DKIM = @()
    foreach($Dom in $NoDKIM)
    {
        $DKIM.Add($Dom.Domain) | Out-Null
    }

    $FailedDKIM = [string]$($DKIM -join ', ')

    if($FailedDKIM)
    {
        $message = "DKIM is NOT enabled for all domains: $FailedDKIM"
        $Rating = 'Fail'
    }
    else
    {
        $message = "DKIM is enabled for all domains."
        $Rating = 'Pass'
    }

    [pscustomobject]@{
        RuleNumber = '2.1.9' 
        Level = 'L1'
        Category = 'Microsoft 365 Defender'       
        Rating = $Rating
        Status = $message
    }
}

#endregion










function Invoke-CISEvaluation
{
    Invoke-Eval_1.1.1
    Invoke-Eval_1.1.3
    Invoke-Eval_1.1.4
    Invoke-Eval_1.2.1
    Invoke-Eval_1.2.2
    Invoke-Eval_1.3.1
    Invoke-Eval_1.3.3
    Invoke-Eval_1.3.6
    Invoke-Eval_2.1.1
    Invoke-Eval_2.1.2
    Invoke-Eval_2.1.3
    Invoke-Eval_2.1.4
    Invoke-Eval_2.1.5
    Invoke-Eval_2.1.6
    Invoke-Eval_2.1.7
    Invoke-Eval_2.1.8
    Invoke-Eval_2.1.9
}

$CISEVAL = Invoke-CISEvaluation

Write-Host 'Level 1'
$CISEVAL | ? {$_.Level -eq 'L1' -and $_.Rating -ne 'pass'} | ft

Write-Host 'Level 2'
$CISEVAL | ? {$_.Level -eq 'L2' -and $_.Rating -ne 'pass'} | ft




break

$CISEVAL | ? Rating -ne 'pass' | ft
$CISEVAL | ? {$_.RuleNumber -like "1.*" -and $_.Rating -ne 'pass'} | sort Level | ft


$CISEVAL | epcsv $OutputDir\WarningList.csv -NoTypeInformation