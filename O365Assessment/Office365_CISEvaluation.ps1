# Office 365 CIS Benchmark Evaluation

#region Functions

function Get-AdminMFAConfig
{
    [CmdletBinding()]
    Param()

    Write-Verbose "1.1 (L1) Ensure multifactor authentication is enabled for all users in administrative roles (Scored)"
    
    [System.Collections.ArrayList]$ArrayList = @()

    $Roles = Get-MsolRole
    
    foreach($Role in $Roles)
    {
        if((Get-MsolRoleMember -RoleObjectId $Role.ObjectId).count -ne 0)
        {
            #(Get-MsolRoleMember -RoleObjectId $Role.ObjectId).count
            $members = Get-MsolRoleMember -RoleObjectId $Role.ObjectId

            foreach ($member in $members)
            {
                $obj = "" | select 'DisplayName','IsLicensed','Emailaddress','RoleName','StrongAuthenticationRequirements'
                
                $obj.DisplayName = $member.DisplayName
                $obj.IsLicensed = $member.IsLicensed
                $obj.Emailaddress = $member.emailaddress
                $obj.RoleName = $Role.Name
                $obj.StrongAuthenticationRequirements = $member.StrongAuthenticationRequirements.state

                $ArrayList += $obj 
                $obj = $null
            }
        }
    }
         
    $ArrayList | select DisplayName,Islicensed,Emailaddress,RoleName,Strong* -Unique                                                                    
}

function Get-NumberofAdmins
{
    [CmdletBinding()]
    Param()

    Write-Verbose "1.3 (L1) Ensure that between two and four global admins are designated (Scored)"
    
    $role = Get-MsolRole -RoleName 'Company Administrator'
    $Admins = Get-MsolRoleMember -RoleObjectId $role.objectid
    $AdminCount = $Admins.count
    $props =[ordered]@{
        GlobalAdmins = $AdminCount
    }

    $obj = New-Object -TypeName PSObject -Property $props

    Write-Output $obj
}

function Get-ModernAuthExchange
{
    [CmdletBinding()]
    Param()

    $OrgConfig = Get-OrganizationConfig

    [pscustomobject]@{
        Name = $OrgConfig.Name
        ExoModernAuthEnabled = $OrgConfig.OAuth2ClientProfileEnabled
    }      
}

function Get-Office365PaasswordExpiry
{
    [CmdletBinding()]
    Param()

    Write-Verbose "1.8 (L1) Ensure that Office 365 Passwords Are Not Set to Expire (Scored)"

    $DN = (Get-OrganizationConfig).Identity
    $passpol = Get-MsolPasswordPolicy -DomainName $DN | ft ValidityPeriod
    if($passpol.ValidityPeriod -eq $null)
    {
        Write-Verbose 'PASS: Office 365 passwords are set to not expire' 
        [pscustomobject]@{
            O365PwdPolicyExpiry = 'False'
            ValidityPeriod = '0'
        }
    }
    else
    {
        $number = $passpol.ValidityPeriod
        Write-Verbose "WARNING: Office 365 passwords are set to expire in $number days"
        [pscustomobject]@{
            O365PwdPolicyExpiry = 'True'
            ValidityPeriod = $number
        }

    }
}

function Get-ExoSpamPolicy
{
    [CmdletBinding()]
    Param()

    Write-Verbose "4.2 (L1) Ensure Exchange Online Spam Policies are set correctly (Scored)"

    $policy = Get-HostedOutboundSpamFilterPolicy 

    if($policy.BccSuspiciousOutboundMail -ne $True -or $policy.NotifyOutboundSpam -ne $True)
    {
        Write-Warning "Exchange Online spam policies are not correctly set." 
        Write-Warning "You should set your Exchange Online Spam Policies to copy emails and notify someone when a sender in your tenant has been blocked for sending spam emails."
        [pscustomobject]@{
            Name = $policy.Name
            BccSuspiciousOutboundMail = $policy.BccSuspiciousOutboundMail
            NotifyOutboundSpam = $policy.NotifyOutboundSpam
        }
    }
    else
    {
        Write-Verbose "Exchange Online spam policies are set correctly."

        [pscustomobject]@{
            Name = $policy.Name
            BccSuspiciousOutboundMail = $policy.BccSuspiciousOutboundMail
            NotifyOutboundSpam = $policy.NotifyOutboundSpam
        }
    }
}

function Get-ForwardTransportRule
{
    [CmdletBinding()]
    Param()

    [System.Collections.ArrayList]$ArrayList = @()

    Write-Verbose "4.3 (L1) Ensure mail transport rules do not forward email to external domains (Scored)"
    Write-Verbose "Verify that none of the addresses are going to external domains."

    $Transport = Get-TransportRule

    foreach ($rule in $Transport)
    {
        $obj = "" | select 'RuleName','RedirectMessageTo'
        
        if($rule.RedirectMessageTo -ne $null)
        {
            $obj.Rulename = $rule.Name
            $obj.RedirectMessageTo = $rule.RedirectMessageTo -join ', '

            $ArrayList += $obj
            $obj = $null
        }
    }
    $ArrayList
}

function Get-TransportRuleWhitelistDomains
{
    [CmdletBinding()]
    Param()

    Write-Verbose "4.4 (L1) Ensure mail transport rules do not whitelist specific domains (Scored)"

    [System.Collections.ArrayList]$ArrayList = @()

    $TRules = Get-TransportRule | select Name,State,Mode,Priority,Setscl,SenderDomainIs 

    foreach ($rule in $TRules)
    {
        $obj = "" | select 'RuleName','SenderDomain'

        if($rule.setscl -eq -1 -and $rule.SenderDomainIs -ne $null)
        {
            $obj.rulename = $rule.name
            $obj.SenderDomain = $rule.SenderDomainIs -join ','

            $ArrayList += $obj 
            $obj = $null
        }
    }
    $ArrayList 
}


function Get-Office365SPFRecords
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $DomainName
    )

    Write-Verbose "4.11 (L1) Ensure that SPF records are published for all Exchange Domains (Not Scored)"

    $txt = Resolve-DnsName -Type TXT -Name $DomainName

    [pscustomobject]@{
        DomainName = $DomainName
        SPFRecord = [string]::join(', ',$txt.strings)
    }
}

function Get-Office365DMARCRecords
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $DomainName
    )

    Write-Verbose "4.12 (L1) Ensure DMARC Records for all Exchange Online domains are published (Not Scored)"

    [System.Collections.ArrayList]$ArrayList = @()

    $obj = "" | select 'Name','Strings'

    $name = '_dmarc.' + $DomainName
        
    $txt = Resolve-DnsName -Type TXT -Name $name -ErrorAction SilentlyContinue 

    if($txt.strings -ne $null)
    {
        [pscustomobject]@{
            DomainName = $DomainName
            DMARC = [string]::join(', ',$txt.strings)
        }
    }
    else
    {
        [pscustomobject]@{
            DomainName = $DomainName
            DMARC = $txt.strings
        }
    }
}

function Get-Office365AuditLog
{
    [CmdletBinding()]
    Param()

    Write-Verbose "5.1 (L1) Ensure Microsoft 365 audit log search is Enabled (Scored)"

    $AALog = Get-AdminAuditLogConfig 

    [pscustomobject]@{
        Name = $AALog.name
        UnifiedAuditLogIngestionEnabled = $AALog.UnifiedAuditLogIngestionEnabled
        UnifiedAuditLogFirstOptInDate = $AALog.UnifiedAuditLogFirstOptInDate

    }
}

function Get-MailboxAuditing
{
    [CmdletBinding()]
    Param()

    Write-Verbose "5.2 (L1) Ensure mailbox auditing for all users is Enabled (Scored)"

    Write-Verbose 'Checking all mailboxes..' 
    $MBX = Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox"} 
    $AuditDisabled = $mbx | ? AuditEnabled -eq $False | measure

    Write-Output 'WARNING: Not all mailboxes have auditing enabled'
    [pscustomobject]@{
        UserMailboxCount = ($MBX | Measure).count
        AuditDisabled = $AuditDisabled.count
    }   
}

function Get-SPOLegacyAuthProtocol
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )
    Write-Verbose "1.61.6 (L1) Ensure modern authentication for SharePoint applications is required (Scored)"

    $cred = Get-Credential -Message 'Enter credentials for SharePoint Online'
    Connect-SPOService -Url https://Fujitec-admin.sharepoint.com -Credential $cred 

    $tenant = Get-SPOTenant -ErrorAction SilentlyContinue

    if($tenant.LegacyAuthProtocolenabled -eq $true)
    {
        Write-Output "PASS: SharePoint modern authentication is enabled."
    }
    else
    {
        Write-Output "WARNING: SharePoint modern authentication is not enabled"
    }
    
}

function Get-ExoCalendarSharing
{
    $SharingPolicy = Get-SharingPolicy | ? {$_.Domains -like '*CalendarSharing*'} 

    foreach($policy in $SharingPolicy)
    {
        [pscustomobject]@{
            PolicyName = $policy.Name
            Domains = [string]::join(', ',[string]$policy.Domains)
            Enabled = $policy.enabled
            Default = $policy.Default
        }
    }
}

function Get-MFAStatus
{
    [cmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $false)]
        [switch]$AdminOnly
    )


    [System.Collections.ArrayList]$array = @()
    $UserCount=0
    $PrintedUser=0

    #Loop through each user
    $AllMSOLUsers = Get-MsolUser -All 

    foreach($MsolUser in $AllMSOLUsers)
    {
        $obj = $null
        $obj = "" | select "DisplayName","UserPrincipalName","MFAStatus","ActivationStatus","DefaultMFAMethod","AllMFAMethods","MFAPhone","MFAEmail","LicenseStatus","IsAdmin","AdminRoles","SignInStatus","LastDirSyncTime"
        # $obj = "" | select "DisplayName","UserPrincipalName","MFAStatus","ActivationStatus","AllMFAMethods","LicenseStatus","IsAdmin","AdminRoles","SignInStatus"

        $UserCount++
        $DisplayName = $MsolUser.DisplayName
        $Upn = $MsolUser.UserPrincipalName
        $MFAStatus = $MsolUser.StrongAuthenticationRequirements.State
        $MethodTypes = $MsolUser.StrongAuthenticationMethods
        $RolesAssigned = ""

 
        Write-Progress -Activity "`n     Processed user count: $UserCount "`n"  Currently Processing: $DisplayName"
        
        if($MsolUser.BlockCredential -eq "True")
        {
            $SignInStatus = "False"
            $SignInStat = "Denied"
        }
        else
        {
            $SignInStatus = "True"
            $SignInStat = "Allowed"
        }

        if($MsolUser.IsLicensed -eq $true)
        {
            $LicenseStat = "Licensed"
        }
        else
        {
            $LicenseStat = "Unlicensed"
        }

         #Check for user's Admin role
         $Roles = (Get-MsolUserRole -UserPrincipalName $upn).Name
         if($Roles.count -eq 0)
         {
            $RolesAssigned = "No roles"
            $IsAdmin = "False"
         }
         else
         {
            $IsAdmin = "True"
            foreach($Role in $Roles)
            {
                $RolesAssigned=$RolesAssigned+$Role
                
                if($Roles.indexof($role) -lt (($Roles.count)-1))
                {
                    $RolesAssigned=$RolesAssigned+","
                }
            }
         }

        #Check for MFA enabled user
        if(($MethodTypes -ne $Null) -or ($MFAStatus -ne $Null))
        {
            #Check for Conditional Access
            if($MFAStatus -eq $null)
            {
                $MFAStatus='Enabled via Conditional Access'
            }

            $Methods = $null
            $MethodTypes = $null
            $MFAEmail = $null
            $MFAPhone = $null
            $MethodTypes = $MsolUser.StrongAuthenticationMethods.MethodType
            $DefaultMFAMethod = ($MsolUser.StrongAuthenticationMethods | where{$_.IsDefault -eq "True"}).MethodType
            $MFAPhone = $MsolUser.StrongAuthenticationUserDetails.PhoneNumber
            $MFAEmail = $MsolUser.StrongAuthenticationUserDetails.Email

            if($MFAPhone -eq $Null)
            { 
                $MFAPhone = ""
            }
          
            if($MFAEmail -eq $Null)
            { 
                $MFAEmail = ""
            }

            if($MethodTypes -ne $Null)
            {
                $ActivationStatus="Yes"
                foreach($MethodType in $MethodTypes)
                {
                    if($Methods -ne "")
                    {
                        $Methods=$Methods+","
                    }
            
                    $Methods=$Methods+$MethodType
                }
            }

            else
            {
                $ActivationStatus="No"
                $Methods=""
                $DefaultMFAMethod=""
                $MFAPhone=""
                $MFAEmail=""
            }
        }
                      
            $obj.DisplayName = $DisplayName
            $obj.UserPrincipalName = $Upn
            $obj.MFAStatus = $MFAStatus
            $obj.ActivationStatus = $ActivationStatus
            #$obj.DefaultMFAMethod = $DefaultMFAMethod
            $obj.AllMFAMethods = $Methods
            $obj.MFAPhone = $MsolUser.StrongAuthenticationUserDetails.PhoneNumber
            $obj.MFAEmail = $MsolUser.StrongAuthenticationUserDetails.Email
            $obj.LicenseStatus = $LicenseStat
            $obj.SignInStatus = $SignInStat
            $obj.IsAdmin = $IsAdmin
            $obj.AdminRoles = $RolesAssigned
            $obj.LastDirSyncTime = $MsolUser.LastDirSyncTime

            $array += $obj
            $obj = $null

    }#EndForeach

    if($AdminOnly.IsPresent)
    {
        $array | Where IsAdmin -eq 'True'
    }
    else
    {
        $array
    }

}


#endregion


$Banner = @"

         ___       ______                      __         ______        
        /   |     / ____/________ _      __   / /   ___  / __/ /_       
       / /| |    / /   / ___/ __ \ | /| / /  / /   / _ \/ /_/ __/       
      / ___ |   / /___/ /  / /_/ / |/ |/ /  / /___/  __/ __/ /_         
     /_/  |_| __\____/_/ __\____/|__/|__/  /_____/\___/_/  \__/         
       ____  / __/  / /_/ /_  ___     /  |/  /_  ___________/ /__  _____
      / __ \/ /_   / __/ __ \/ _ \   / /|_/ / / / / ___/ __  / _ \/ ___/
     / /_/ / __/  / /_/ / / /  __/  / /  / / /_/ / /  / /_/ /  __/ /    
     \____/_/     \__/_/ /_/\___/  /_/  /_/\__,_/_/   \__,_/\___/_/     
                                                                                                                                    
================================================================================

              An Office 365/ Azure AD Security and Health 
                           Check Analyzer
            
"@

$Darkcolor = 'DarkGray'
$DarkColor2 = 'DarkCyan'
$LightColor = 'Cyan'
$DataColor = 'Magenta'
$Version = ' v2023.1.00'


function Connectto-Services
{
    Connect-MsolService
    Connect-ExchangeOnline
    Connect-AzureAD
    $GraphScopes = "SecurityEvents.Read.All", "Policy.Read.All", "Group.Read.All"
    Connect-Graph -Scopes $GraphScopes 
    Connect-MgGraph -Scopes Directory.AccessAsUser.All, Directory.ReadWrite.All, User.ReadWrite.All, AuditLog.Read.All, Group.Read.All, Policy.Read.All, SecurityEvents.Read.All
}

function Disconnect-Services
{
    Disconnect-AzureAD
    Disconnect-ExchangeOnline 
    Disconnect-Graph 
    [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState() 
}


function Invoke-365DataCollection
{
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        $OutputDir,

        [parameter(Mandatory=$true)]
        $Domain
    )

    # Params
     $OutputDir = "C:\Users\e060080\OneDrive - RSM\CR3\AngelOak"
     $Domain = 'AngelOak'

    $opdir = Join-Path -Path $OutputDir -ChildPath ($Domain + '-M365Data')
    $OutputDir = $opdir

    if(!(Test-Path $OutputDir))
    {
        Write-Host "$(Get-Date -Format "[hh:mm:ss tt]")" -ForegroundColor $Darkcolor -NoNewline
        Write-Host " Creating Report Output Directories..." -ForegroundColor $LightColor
        New-Item -Path "$OutputDir" -Name $Domain-M365Data -ItemType Directory | Out-Null
    }
    if(!(Test-Path $opdir))
    {
        Write-Host "$(Get-Date -Format "[hh:mm:ss tt]")" -ForegroundColor $Darkcolor -NoNewline
        Write-Host " Creating Report Output Directories..." -ForegroundColor $LightColor
        New-Item -Path "$OutputDir" -Name $Domain-M365Data -ItemType Directory | Out-Null
    }

    #region Secure Score

    $SecureScore = Get-MgSecuritySecureScore | select -First 1
    $ControlScore = $SecureScore.ControlScores
    $EnabledServices = $SecureScore.EnabledServices
    $ControlScore | select ControlCategory,ControlName,Score,Description | epcsv $OutputDir\SecureScore-$Domain.csv -NoTypeInformation

    #endregion

    # Imap POP enabled mailboxes
    Get-CASMailbox -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" }  | Select @{n="Identity";e= {$_.primarysmtpaddress}},ImapEnabled,PopEnabled,SmtpClientAuthenticationDisabled | epcsv $OutputDir\ImapPopEnabled-$Domain.csv -NoTypeInformation
    Get-CASMailbox | Select-Object @{n="Identity";e= {$_.primarysmtpaddress}},ImapEnabled,PopEnabled,SmtpClientAuthenticationDisabled | epcsv $OutputDir\AllImapPopMBX-$Domain.csv -NoTypeInformation
    
    Get-ModernAuthExchange | epcsv $OutputDir\ExoModernAuth-$Domain.csv -NoTypeInformation
    
    Get-Office365AuditLog | epcsv $OutputDir\O365AuditLog-$Domain.csv -NoTypeInformation
    Get-MailboxAuditing | epcsv $OutputDir\ExoMailboxAuditing-$Domain.csv -NoTypeInformation


    #region 1. Azure Active Directory
    
    $AdminRoles = Get-MsolRole | % {$role = $_.name; Get-MsolRoleMember -RoleObjectId $_.objectid} | select @{Name="Role"; Expression = {$role}}, DisplayName, EmailAddress,islicensed,StrongAuthenticationRequirements
    $AdminRoles | epcsv $OutputDir\MSOL-AdminRoles-$Domain.csv -NoTypeInformation

    # 1.1.1 (L1) Ensure multifactor authentication is enabled for all users in administrative roles
    Get-AdminMFAConfig | epcsv $OutputDir\1.1.1_AdminMFAConfig-$Domain.csv -NoTypeInformation

    # 1.1.2 (L2) Ensure multifactor authentication is enabled for all users in all roles
    Get-MFAStatus | epcsv $OutputDir\1.1.2_AllUserMFAStatus-$Domain.csv -NoTypeInformation

    # 1.1.3 (L1) Ensure that between two and four global admins are designated
    Get-NumberofAdmins | epcsv $OutputDir\1.1.3_GlobalAdminCount-$Domain.csv -NoTypeInformation

    # 1.1.4 (L1) Ensure self-service password reset is enabled
    $ControlScore | ? ControlName -eq 'SelfServicePasswordReset' | Select ControlCategory,ControlName,Score | epcsv $OutputDir\ScoredItems-$Domain.csv -NoTypeInformation

    # 1.1.5 (L1) Ensure that password protection is enabled for Active Directory
    $ControlScore | ? ControlName -eq 'aad_password_protection' | Select ControlCategory,ControlName,Score | epcsv $OutputDir\ScoredItems-$Domain.csv -NoTypeInformation -Append

    # 1.1.6 (L1) Enable Conditional Access policies to block legacy authentication
    $ControlScore | ? ControlName -eq 'BlockLegacyAuthentication' | Select ControlCategory,ControlName,Score | epcsv $OutputDir\ScoredItems-$Domain.csv -NoTypeInformation -Append
    Get-OrganizationConfig | select -ExpandProperty DefaultAuthenticationPolicy | % {Get-AuthenticationPolicy $_ | Select AllowBasicAuth* } | epcsv $OutputDir\1.1.6_AllowBasicAuth-$Domain.csv

    # 1.1.7 (L1) Ensure that password hash sync is enabled for resiliency and leaked credential detection
    $ControlScore | ? ControlName -eq 'PasswordHashSync' | Select ControlCategory,ControlName,Score | epcsv $OutputDir\ScoredItems-$Domain.csv -NoTypeInformation -Append

    # 1.1.8 (L1) Enabled Identity Protection to identify anomalous logon behavior
    
    # 1.1.8 (L2) Enable Azure AD Identity Protection sign-in risk policies
    $ControlScore | ? ControlName -eq 'SigninRiskPolicy' | Select ControlCategory,ControlName,Score | epcsv $OutputDir\ScoredItems-$Domain.csv -NoTypeInformation -Append

    # 1.1.9 (L2) Enable Azure AD Identity Protection user risk policies
    $ControlScore | ? ControlName -eq 'UserRiskPolicy' | Select ControlCategory,ControlName,Score | epcsv $OutputDir\ScoredItems-$Domain.csv -NoTypeInformation -Append
    
    # 1.1.10 (L2) Use Just In Time privileged access to Office 365 roles
    
    # 1.1.11 (L1) Ensure Security Defaults is disabled on Azure Active Directory

    # 1.1.12 (L2) Ensure that only organizationally managed/approved public groups exist
    Get-MgGroup | where {$_.Visibility -eq "Public"} | select DisplayName,Visibility | epcsv $OutputDir\1.1.12_PublicGroups-$Domain.csv -NoTypeInformation
    
    # 1.2 (L1) Ensure modern authentication for Exchange Online is enabled
    Get-ModernAuthExchange | epcsv $OutputDir\1.2_ExchangeModernAuth-$Domain.csv -NoTypeInformation
    
    # 1.3 (L1) Ensure modern authentication for Skype for Business Online is enabled
    
    # 1.4 (L1) Ensure modern authentication for SharePoint applications is required
    
    # 1.5 (L1) Ensure that Office 365 Passwords Are Not Set to Expire
     Get-Office365PaasswordExpiry | epcsv $OutputDir\1.5_O365PasswordExpiry-$Domain.csv -NoTypeInformation
    
    #endregion

    #region 2. Application Permission

    # 2.1 (L2) Ensure third party integrated applications are not allowed

    # 2.2 - (L2) Ensure calendar details sharing with external users is disabled
    Get-ExoCalendarSharing | epcsv $OutputDir\ExoCalendarSharing-$Domain.csv -NoTypeInformation

    # 2.3 (L2) Ensure Safe Links for Office Applications is Enabled

    # 2.4 (L2) Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled 

    # 2.5 (L2) Ensure Office 365 SharePoint infected files are disallowed for download

    # 2.6 - (L2) Ensure user consent to apps accessing company data on their behalf is not allowed"
    Get-MsolCompanyInformation | epcsv $OutputDir\MSOLCompanyInformation-$Domain.csv -NoTypeInformation

    ipcsv $OutputDir\MSOLCompanyInformation-$Domain.csv | select UsersPermissionToUserConsent* 
    ipcsv $OutputDir\MSOLCompanyInformation-$Domain.csv | select UsersPermission*

    # 2.7 - (L2) Ensure the admin consent workflow is enabled
    #Connect-MgGraph -Scopes "DelegatedPermissionGrant.ReadWrite.All Directory.AccessAsUser.All Directory.Read.All"
    #Import-Module Microsoft.Graph.Identity.SignIns
    Get-MgPolicyAdminConsentRequestPolicy | epcsv $OutputDir\AdminConsentRequestPolicy-$Domain.csv -NoTypeInformation

    # 2.8 (L2) - Ensure users installing Outlook add-ins is not allowed
    # https://learn.microsoft.com/en-us/exchange/manage-user-access-to-add-ins-exchange-2013-help
    Get-App -OrganizationApp | select DisplayName,AppId,Enabled,DefaultStateForUser,ProvidedTo,UserList | epcsv $OutputDir\2.8_OutlookAddIns-$Domain.csv -NoTypeInformation

    # 2.9 (L1) - Ensure users installing Word, Excel, and PowerPoint add-ins is not allowed 

    # 2.10 (L1) Ensure internal phishing protection for Forms is enabled 

    # 2.11 (L1) Ensure that Sways cannot be shared with people outside of your organization 
    
    #endregion

    #region 3. Data Management
    
    # 3.1 (L2) Ensure the customer lockbox feature is enabled

    # 3.2 (L2) Ensure SharePoint Online Information Protection policies are setup and used

    # 3.3 (L2) Ensure external domains are not allowed in Skype or Teams

    # 3.4 (L1) Ensure DLP policies are enabled

    # 3.5 (L1) Ensure DLP policies are enabled for Microsoft Teams

    # 3.6 (L2) Ensure that external users cannot share files, folders, and sites they do not own

    # 3.7 (L2) Ensure external file sharing in Teams is enabled for only approved cloud storage services

    #endregion

    #region 4. Email Security / Exchange Online

    Get-MsolDomain | select Name,Status,Authentication | epcsv $OutputDir\MsolDomain-$Domain.csv -NoTypeInformation

    # 4.1 (L1) Ensure the Common Attachment Types Filter is enabled
    Get-MalwareFilterPolicy | Select-Object Identity,EnableFileFilter | epcsv $OutputDir\4.1_MalwareFilterPolicy-$Domain.csv -NoTypeInformation

    # 4.2 (L1) Ensure Exchange Online Spam Policies are set correctly 
    Get-ExoSpamPolicy | epcsv $OutputDir\4.2_ExoSpamFilterPolicy-$Domain.csv -NoTypeInformation

    # 4.3 (L1) Ensure all forms of mail forwarding are blocked and/or disabled 
    Get-ForwardTransportRule | epcsv $OutputDir\4.3_ForwardTransportRule-$Domain.csv -NoTypeInformation
    Get-RemoteDomain Default | select Name,DomainName,AllowedOOFType,AutoForwardEnabled | epcsv $OutputDir\4.3_AutoForwardEnabled-$Domain.csv -NoTypeInformation

    # 4.4 (L1) Ensure mail transport rules do not whitelist specific domains
    Get-TransportRuleWhitelistDomains | epcsv $OutputDir\4.4_TransportRuleWhitelist-$Domain.csv -NoTypeInformation

    # 4.5 (L2) Ensure the Safe Links policy is enabled
    Get-SafeLinksPolicy | Select-Object Name, IsEnabled,ScanUrls,EnableForInternalSenders,AllowClickThrough | epcsv $OutputDir\4.5_SafeLinksPolicy-$Domain.csv -NoTypeInformation

    # 4.6 (L2) Ensure Safe Attachments policy is enabled 
    Get-SafeAttachmentPolicy | select @{l='SafeAttachmentPolicyName';e={$_.Name}},Enabled,IsDefault,IsBuiltInProtection,action,admindisplayname,RedirectAddress | epcsv $OutputDir\4.6_SafeAttachmentPolicy-$Domain.csv -NoTypeInformation

    # 4.7 (L1) Ensure that an anti-phishing policy has been created 
    Get-AntiPhishPolicy | select Name,enabled,@{l='TargetedDomainsToProtect';e={[string]::join(', ',[string]$_.TargetedDomainsToProtect)}} | epcsv $OutputDir\4.7_AntiPhishingPolicy-$Domain.csv -NoTypeInformation
    # 4.8 (L1) Ensure that DKIM is enabled for all Exchange Online Domains 
    Get-DkimSigningConfig | select @{l='DomainName';e={$_.Domain}},@{l='DkimEnabled';e={$_.Enabled}} | epcsv $OutputDir\4.8_DkimEnabled-$Domain.csv -NoTypeInformation

    $MSOLDomains = ipcsv $OutputDir\MsolDomain-$Domain.csv
    # 4.9 (L1) Ensure that SPF records are published for all Exchange Domains
    $MSOLDomains | % {Get-Office365SPFRecords -DomainName $_.Name} | epcsv $OutputDir\4.9_SPFRecords-$Domain.csv -NoTypeInformation

    # 4.10 (L1) Ensure DMARC Records for all Exchange Online domains are published 
    $MSOLDomains | % {Get-Office365DMARCRecords -DomainName $_.Name} | epcsv $OutputDir\4.10_DmarcRecords-$Domain.csv -NoTypeInformation

    # 4.11 (L1) Ensure notifications for internal users sending malware is Enabled
    Get-MalwareFilterPolicy | select Identity,EnableInternalSenderAdminNotifications, InternalSenderAdminAddress | epcsv $OutputDir\4.11_MalwareNotification-$Domain.csv -NoTypeInformation

    # 4.12 (L2) Ensure MailTips are enabled for end users
    Get-OrganizationConfig |Select-Object id*,MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled,MailTipsLargeAudienceThreshold | epcsv $OutputDir\4.12_MailTips-$Domain.csv -NoTypeInformation
    #endregion
}


function Invoke-365Analyzer
{

    #region Email Security / Exchange Online

    # 4.1 (L1) Ensure the Common Attachment Types Filter is enabled 
    function Invoke-4.1_CommonAttachmentFilter
    {
        $continue = $true
        $filepath = "$OutputDir\4.1_MalwareFilterPolicy-$Domain.csv"
        if(!(Test-Path  $filepath -ErrorAction stop))
        {
            $continue = $false
            Write-Warning " Missing file: 4.1_MalwareFilterPolicy"

            $props = [ordered]@{
                RuleId = '4.1_CommonAttachmentFilter'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            if(ipcsv $filepath | ? EnableFileFilter -ne 'True')
            {
                [pscustomobject]@{
                    RuleId = '4.1_CommonAttachmentFilter'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "Common Attachment Types Filter is not enabled"                
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.1_CommonAttachmentFilter'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "Common Attachment Types Filter is enabled"                
                }
            }            
        }
    }   

    # 4.2 (L1) Ensure Exchange Online Spam Policies are set correctly 
    function Invoke-4.2_ExoSpamPolicy
    {
        $continue = $true
        $filepath = "$OutputDir\4.2_ExoSpamFilterPolicy-$Domain.csv"
        if(!(Test-Path  $filepath -ErrorAction stop))
        {
            $continue = $false
            Write-Warning " Missing file: 4.2_ExoSpamPolicy"

            $props = [ordered]@{
                RuleId = '4.2_ExoSpamPolicy'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            if(ipcsv $filepath | ? {$_.BccSuspiciousOutboundMail -eq 'True' -and $_.NotifyOutboundSpam -eq 'True'})
            {
                [pscustomobject]@{
                    RuleId = '4.2_ExoSpamPolicy'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "Exchange Online Spam Policies are set correctly"                
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.2_ExoSpamPolicy'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "Exchange Online Spam Policies are not set correctly"                
                }
            }            
        }
    }   

    # 4.3 (L1) Ensure all forms of mail forwarding are blocked and/or disabled 
    function Invoke-4.3_MailForwardingDisabled
    {
        $continue = $true
        $pass = 0
        $fail = 0
        $filepath1 = "$OutputDir\4.3_AutoForwardEnabled-$Domain.csv"
        $filepath2 = "$OutputDir\4.3_ForwardTransportRule-$Domain.csv"
        if((Test-Path $filepath1 -ErrorAction stop) -ne $True -or (Test-Path $filepath2 -ErrorAction Stop) -ne $true)
        {
            $continue = $false
            Write-Warning " Missing file: 4.3_MailForwardingDisabled"

            $props = [ordered]@{
                RuleId = '4.3_MailForwardingDisabled'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            if((ipcsv $filepath1).AutoForwardEnabled -ne 'True')
            {
                $pass = 1
            }
            else
            {
                $fail = 1
                [pscustomobject]@{
                    RuleId = '4.3_MailForwardDisabled'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "Auto forward is enabled"                
                }
            }

            $MSOLDomains = ipcsv $OutputDir\MsolDomain-$Domain.csv
            $SafeDomains = $MSOLDomains.Name -join '|'
            if((ipcsv $filepath2).RedirectMessageto.split(',') -notmatch $SafeDomains)
            {
                $fail = 1
                [pscustomobject]@{
                    RuleId = '4.3_MailForwardDisabled'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "Transport rule forwards to an outside domain"                
                }
            }
            else
            {
                $pass = 1
            } 
            
            if($pass -eq 1 -and $fail -eq 0)
            {
                [pscustomobject]@{
                    RuleId = '4.3_MailForwardDisabled'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "All forms of mail forwarding are blocked and/or disabled"                
                }
            
            }           
        }
    }   

    # 4.4 (L1) Ensure mail transport rules do not whitelist specific domains
    function Invoke-4.4_WhitelistTransportRule
    {
        $continue = $true
        $filepath = "$OutputDir\4.4_TransportRuleWhitelist-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.4_WhitelistTransportRule"

            $props = [ordered]@{
                RuleId = '4.4_WhitelistTransportRule'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            if((ipcsv $filepath | measure).count -gt 0)
            {
                $Rules = ipcsv $filepath

                [pscustomobject]@{
                    RuleId = '4.4_WhitelistTransportRule'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "Transport rule whitelist external domains: $([string]::join(', ',$Rules.senderdomain))"                
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.4_WhitelistTransportRule'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "No whitelisted domains in transport rules."                                
                }
            }
           
        }
    }   

    # 4.5 (L2) Ensure the Safe Links policy is enabled
    # Verify the values for IsEnabled and ScanUrls are set to True, and AllowClickThrough is set to False.    function Invoke-4.5_SafeLinksPolicy
    {
        $continue = $true
        $filepath = "$OutputDir\4.5_SafeLinksPolicy-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.5_SafeLinksPolicy"

            $props = [ordered]@{
                RuleId = '4.5_SafeLinksPolicy'
                Level = 'L2'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $Policies = ipcsv $filepath | ? {$_.IsEnabled -ne 'True' -or $_.ScanUrls -ne 'True' -or $_.AllowClickThrough -eq 'False'}

            if(($Policies).count -gt 0)
            {
                [pscustomobject]@{
                    RuleId = '4.5_SafeLinksPolicy'
                    Level = 'L2'
                    Rating = 'Fail'
                    Description = "Safe Link Policy is not enabled or properly configured."
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.5_SafeLinksPolicy'
                    Level = 'L2'
                    Rating = 'Pass'
                    Description = "Safe Link Policy enabled."
                }
            }
           
        }
    }   

    # 4.6 (L2) Ensure Safe Attachments policy is enabled 
    function Invoke-4.6_SafeAttachmentsPolicy
    {
        $continue = $true
        $filepath = "$OutputDir\4.6_SafeAttachmentPolicy-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.6_SafeAttachmentsPolicy"

            $props = [ordered]@{
                RuleId = '4.6_SafeAttachmentsPolicy'
                Level = 'L2'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $SafeAttachments = ipcsv $filepath | ? Enabled -ne 'True'

            if(($SafeAttachments).count -gt 0)
            {
                [pscustomobject]@{
                    RuleId = '4.6_SafeAttachmentsPolicy'
                    Level = 'L2'
                    Rating = 'Fail'
                    Description = "Safe attachment policy is not enabled."
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.6_SafeAttachmentsPolicy'
                    Level = 'L2'
                    Rating = 'Pass'
                    Description = "Safe attachment policy is enabled."
                }
            }
           
        }
    }   

    # 4.7 (L1) Ensure that an anti-phishing policy has been created 
    function Invoke-4.7_AntiPhishingPolicy
    {
        $continue = $true
        $filepath = "$OutputDir\4.7_AntiPhishingPolicy-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.7_AntiPhishingPolicy"

            $props = [ordered]@{
                RuleId = '4.7_AntiPhishingPolicy'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $AntiPhishing = ipcsv $filepath | ? {$_.Name -eq 'Office365 AntiPhish Default' -and $_.Enabled -eq 'True'}

            if($AntiPhishing)
            {
                [pscustomobject]@{
                    RuleId = '4.7_AntiPhishingPolicy'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "The default Anti-phishing policy is enabled."
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.7_AntiPhishingPolicy'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "The default Anti-phishing policy is not enabled."
                }
            }
           
        }
    }   

    # 4.8 (L1) Ensure that DKIM is enabled for all Exchange Online Domains 
    function Invoke-4.8_DKIM
    {
        $continue = $true
        $filepath = "$OutputDir\4.8_DkimEnabled-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.8_DKIM"

            $props = [ordered]@{
                RuleId = '4.8_DKIM'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $DKIM = ipcsv $filepath | ? DkimEnabled -ne 'True'

            if($DKIM)
            {
                [pscustomobject]@{
                    RuleId = '4.8_DKIM'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "DKIM is not enabled for all Exchange Online domains."
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.8_DKIM'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "DKIM is enabled for all Exchange Online domains"
                }
            }           
        }
    }   

    # 4.9 (L1) Ensure that SPF records are published for all Exchange Domains
    function Invoke-4.9_SPF
    {
        $continue = $true
        $filepath = "$OutputDir\4.9_SPFRecords-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.9_SPF"

            $props = [ordered]@{
                RuleId = '4.9_SPF'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $SPF = ipcsv $filepath | ? SPFRecord -eq $null

            if($SPF)
            {
                [pscustomobject]@{
                    RuleId = '4.9_SPF'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "SPF records not published for all Exchange Online domains."
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.9_SPF'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "SPF records are published for all Exchange Online domains."
                }
            }           
        }
    }   

    # 4.10 (L1) Ensure DMARC Records for all Exchange Online domains are published 
    function Invoke-4.10_DMARC
    {
        $continue = $true
        $filepath = "$OutputDir\4.10_DMARCRecords-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.10_DMARC"

            $props = [ordered]@{
                RuleId = '4.10_DMARC'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $DMARC = ipcsv $filepath | ? DMARC -eq ''

            if($DMARC)
            {
                [pscustomobject]@{
                    RuleId = '4.10_DMARC'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "DMARC records not published for all Exchange Online domains: $([string]::join(', ',$DMARC.DomainName))"
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.10_DMARC'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "DMARC records are published for all Exchange Online domains."
                }
            }           
        }
    }   

    # 4.11 (L1) Ensure notifications for internal users sending malware is Enabled
    function Invoke-4.11_MalwareNotification
    {
        $continue = $true
        $filepath = "$OutputDir\4.11_MalwareNotification-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.11_MalwareNotification"

            $props = [ordered]@{
                RuleId = '4.11_MalwareNotification'
                Level = 'L1'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $MalwareNotification = ipcsv $filepath | ? {$_.EnableInternalSenderAdminNotifications -ne 'True' -or $_.InternalSenderAdminAddress -eq ''}

            if($MalwareNotification)
            {
                [pscustomobject]@{
                    RuleId = '4.11_MalwareNotification'
                    Level = 'L1'
                    Rating = 'Fail'
                    Description = "Notifications for internal users sending malware is not Enabled."
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.11_MalwareNotification'
                    Level = 'L1'
                    Rating = 'Pass'
                    Description = "Notifications for internal users sending malware is Enabled."
                }
            }           
        }
    }   

    # 4.12 (L2) Ensure MailTips are enabled for end users
    function Invoke-4.12_MailTips
    {
        $continue = $true
        $filepath = "$OutputDir\4.12_MailTips-$Domain.csv"
        if((Test-Path $filepath -ErrorAction stop) -ne $True)
        {
            $continue = $false
            Write-Warning " Missing file:  4.12_MailTips"

            $props = [ordered]@{
                RuleId = '4.12_MailTips'
                Level = 'L2'
                Rating = 'Error'
                Description = "Unable to evaluate checkpoint."
            }
            New-Object -TypeName psobject -Property $props 
        }
        
        if($continue)
        {
            $MailTips = ipcsv $filepath

            if($MailTips.MailTipsAllTipsEnabled -eq 'True' -and $MailTips.MailTipsExternalRecipientsTipsEnabled -eq 'True' -and $MailTips.MailTipsGroupMetricsEnabled -eq 'True')            
            {
                [pscustomobject]@{
                    RuleId = '4.12_MailTips'
                    Level = 'L2'
                    Rating = 'Pass'
                    Description = "MailTips are enabled for end users."
                }
            }
            else
            {
                [pscustomobject]@{
                    RuleId = '4.12_MailTips'
                    Level = 'L2'
                    Rating = 'Fail'
                    Description = "MailTips are not enabled for end users."
                }
            }           
        }
    }   


    #endregion

     #region Call Evaluation functions
    $IssueList = Join-Path -Path $OutputDir -ChildPath WarningList-$Domain.csv

    if(Test-Path $IssueList)
    {
        Remove-Item $IssueList -Force 
    }

    Invoke-4.1_CommonAttachmentFilter | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.2_ExoSpamPolicy | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.3_MailForwardingDisabled | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.4_WhitelistTransportRule | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.5_SafeLinksPolicy | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.6_SafeAttachmentsPolicy | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.7_AntiPhishingPolicy | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.8_DKIM | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.9_SPF | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.10_DMARC | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.11_MalwareNotification | epcsv $IssueList -NoTypeInformation -Append
    Invoke-4.12_MailTips | epcsv $IssueList -NoTypeInformation -Append

    #endregion

}


function Write-365HTMLReport
{
    [cmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True)]
        [string]$Path,

        [parameter(Mandatory=$true)]
        $Domain,

        [parameter(Mandatory=$true)]
        $ClientName,

        [Parameter()]
        [switch]$ShowReport
    )

    Write-Host "$(Get-Date -Format "[hh:mm:ss tt]") Creating Report for $ClientName..." -ForegroundColor Cyan

    #$ClientName = (ipcsv (Get-ChildItem -Path $path -Filter 'ADDomainReport*').FullName).NetBIOSName

    function ConvertTo-EnhancedHTMLFragment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [object[]]$InputObject,


        [string]$EvenRowCssClass,
        [string]$OddRowCssClass,
        [string]$TableCssID,
        [string]$DivCssID,
        [string]$DivCssClass,
        [string]$TableCssClass,


        [ValidateSet('List','Table')]
        [string]$As = 'Table',


        [object[]]$Properties = '*',


        [string]$PreContent,


        [switch]$MakeHiddenSection,


        [switch]$MakeTableDynamic,


        [string]$PostContent
    )
    BEGIN {
        <#
            Accumulate output in a variable so that we don't
            produce an array of strings to the pipeline, but
            instead produce a single string.
        #>
        $out = ''


        <#
            Add the section header (pre-content). If asked to
            make this section of the report hidden, set the
            appropriate code on the section header to toggle
            the underlying table. Note that we generate a GUID
            to use as an additional ID on the <div>, so that
            we can uniquely refer to it without relying on the
            user supplying us with a unique ID.
        #>
        Write-Verbose "Precontent"
        if ($PSBoundParameters.ContainsKey('PreContent')) {
            if ($PSBoundParameters.ContainsKey('MakeHiddenSection')) {
               [string]$tempid = [System.Guid]::NewGuid()
               $out += "<span class=`"sectionheader`" onclick=`"`$('#$tempid').toggle(500);`">$PreContent</span>`n"
            } else {
                $out += $PreContent
                $tempid = ''
            }
        }


        <#
            The table will be wrapped in a <div> tag for styling
            purposes. Note that THIS, not the table per se, is what
            we hide for -MakeHiddenSection. So we will hide the section
            if asked to do so.
        #>
        Write-Verbose "DIV"
        if ($PSBoundParameters.ContainsKey('DivCSSClass')) {
            $temp = " class=`"$DivCSSClass`""
        } else {
            $temp = ""
        }
        if ($PSBoundParameters.ContainsKey('MakeHiddenSection')) {
            $temp += " id=`"$tempid`" style=`"display:none;`""
        } else {
            $tempid = ''
        }
        if ($PSBoundParameters.ContainsKey('DivCSSID')) {
            $temp += " id=`"$DivCSSID`""
        }
        $out += "<div $temp>"


        <#
            Create the table header. If asked to make the table dynamic,
            we add the CSS style that ConvertTo-EnhancedHTML will look for
            to dynamic-ize tables.
        #>
        Write-Verbose "TABLE"
        $_TableCssClass = ''
        if ($PSBoundParameters.ContainsKey('MakeTableDynamic') -and $As -eq 'Table') {
            $_TableCssClass += 'enhancedhtml-dynamic-table '
        }
        if ($PSBoundParameters.ContainsKey('TableCssClass')) {
            $_TableCssClass += $TableCssClass
        }
        if ($_TableCssClass -ne '') {
            $css = "class=`"$_TableCSSClass`""
        } else {
            $css = ""
        }
        if ($PSBoundParameters.ContainsKey('TableCSSID')) {
            $css += "id=`"$TableCSSID`""
        } else {
            if ($tempid -ne '') {
                $css += "id=`"$tempid`""
            }
        }
        $out += "<table $css>"


        <#
            We're now setting up to run through our input objects
            and create the table rows
        #>
        $fragment = ''
        $wrote_first_line = $false
        $even_row = $false


        if ($properties -eq '*') {
            $all_properties = $true
        } else {
            $all_properties = $false
        }


    }
    PROCESS {


        foreach ($object in $inputobject) {
            Write-Verbose "Processing object"
            $datarow = ''
            $headerrow = ''


            <#
                Apply even/odd row class. Note that this will mess up the output
                if the table is made dynamic. That's noted in the help.
            #>
            if ($PSBoundParameters.ContainsKey('EvenRowCSSClass') -and $PSBoundParameters.ContainsKey('OddRowCssClass')) {
                if ($even_row) {
                    $row_css = $OddRowCSSClass
                    $even_row = $false
                    Write-Verbose "Even row"
                } else {
                    $row_css = $EvenRowCSSClass
                    $even_row = $true
                    Write-Verbose "Odd row"
                }
            } else {
                $row_css = ''
                Write-Verbose "No row CSS class"
            }


            <#
                If asked to include all object properties, get them.
            #>
            if ($all_properties) {
                $properties = $object | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
            }


            <#
                We either have a list of all properties, or a hashtable of
                properties to play with. Process the list.
            #>
            foreach ($prop in $properties) {
                Write-Verbose "Processing property"
                $name = $null
                $value = $null
                $cell_css = ''


                <#
                    $prop is a simple string if we are doing "all properties,"
                    otherwise it is a hashtable. If it's a string, then we
                    can easily get the name (it's the string) and the value.
                #>
                if ($prop -is [string]) {
                    Write-Verbose "Property $prop"
                    $name = $Prop
                    $value = $object.($prop)
                } elseif ($prop -is [hashtable]) {
                    Write-Verbose "Property hashtable"
                    <#
                        For key "css" or "cssclass," execute the supplied script block.
                        It's expected to output a class name; we embed that in the "class"
                        attribute later.
                    #>
                    if ($prop.ContainsKey('cssclass')) { $cell_css = $Object | ForEach-Object $prop['cssclass'] }
                    if ($prop.ContainsKey('css')) { $cell_css = $Object | ForEach-Object $prop['css'] }


                    <#
                        Get the current property name.
                    #>
                    if ($prop.ContainsKey('n')) { $name = $prop['n'] }
                    if ($prop.ContainsKey('name')) { $name = $prop['name'] }
                    if ($prop.ContainsKey('label')) { $name = $prop['label'] }
                    if ($prop.ContainsKey('l')) { $name = $prop['l'] }


                    <#
                        Execute the "expression" or "e" key to get the value of the property.
                    #>
                    if ($prop.ContainsKey('e')) { $value = $Object | ForEach-Object $prop['e'] }
                    if ($prop.ContainsKey('expression')) { $value = $tObject | ForEach-Object $prop['expression'] }


                    <#
                        Make sure we have a name and a value at this point.
                    #>
                    if ($name -eq $null -or $value -eq $null) {
                        Write-Error "Hashtable missing Name and/or Expression key"
                    }
                } else {
                    <#
                        We got a property list that wasn't strings and
                        wasn't hashtables. Bad input.
                    #>
                    Write-Warning "Unhandled property $prop"
                }


                <#
                    When constructing a table, we have to remember the
                    property names so that we can build the table header.
                    In a list, it's easier - we output the property name
                    and the value at the same time, since they both live
                    on the same row of the output.
                #>
                if ($As -eq 'table') {
                    Write-Verbose "Adding $name to header and $value to row"
                    $headerrow += "<th>$name</th>"
                    $datarow += "<td$(if ($cell_css -ne '') { ' class="'+$cell_css+'"' })>$value</td>"
                } else {
                    $wrote_first_line = $true
                    $headerrow = ""
                    $datarow = "<td$(if ($cell_css -ne '') { ' class="'+$cell_css+'"' })>$name :</td><td$(if ($cell_css -ne '') { ' class="'+$cell_css+'"' })>$value</td>"
                    $out += "<tr$(if ($row_css -ne '') { ' class="'+$row_css+'"' })>$datarow</tr>"
                }
            }


            <#
                Write the table header, if we're doing a table.
            #>
            if (-not $wrote_first_line -and $as -eq 'Table') {
                Write-Verbose "Writing header row"
                $out += "<tr>$headerrow</tr><tbody>"
                $wrote_first_line = $true
            }


            <#
                In table mode, write the data row.
            #>
            if ($as -eq 'table') {
                Write-Verbose "Writing data row"
                $out += "<tr$(if ($row_css -ne '') { ' class="'+$row_css+'"' })>$datarow</tr>"
            }
        }
    }
    END {
        <#
            Finally, post-content code, the end of the table,
            the end of the <div>, and write the final string.
        #>
        Write-Verbose "PostContent"
        if ($PSBoundParameters.ContainsKey('PostContent')) {
            $out += "`n$PostContent"
        }
        Write-Verbose "Done"
        $out += "</tbody></table></div>"
        Write-Output $out
    }
}

    function New-HTMLTabsFragment
    {
        [cmdletBinding()]
        Param
        (
            [parameter(Mandatory=$true)]
            [int]$TabCount
        )

        [int]$x = '0'

        $TabNames = @{
            1 = 'Assessment Results'
            2 = 'Privileged Accounts'
            3 = 'Service Accounts'
            4 = 'Active Directory'
            5 = 'Domain Controllers'
            6 = 'OU Permissions'
            7 = 'GPO Details'
            8 = 'GPO Permission'
            9 = 'Inactive GPOs'
           10 = 'GPO Firewall Rules'           
        }

        do
        {
            $x++
            if($x -eq '1')
            {
                [string]$code = '<input type="radio" name="tabs" id="' + "tab$x" + '" checked /><label for="' + "tab$x" + '">' + $TabNames[$x] + '</label>'
            }
            else
            {
                [string]$code = '<input type="radio" name="tabs" id="' + "tab$x" + '"><label for="' + "tab$x" + '">' + $TabNames[$x] + '</label>'
            }
            $code
        }
        until ($x -eq $TabCount)
    }

    function New-TabsHTMLDocument
    {
        [cmdletBinding()]
        Param
        (
            [parameter()]
            $Title,

            [parameter()]
            $Tabs,

            [parameter()]
            $StyleSheet,

            [parameter()]
            $Tab1Content,

            [parameter()]
            $Tab2Content,

            [parameter()]
            $Tab3Content,

            [parameter()]
            $Tab4Content,

            [parameter()]
            $Tab5Content,

            [parameter()]
            $Tab6Content,

            [parameter()]
            $Tab7Content,

            [parameter()]
            $Tab8Content,

            [parameter()]
            $Tab9Content,

            [parameter()]
            $Tab10Content

        )
    
        #Define tags
        [string]$start = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">'
        [string]$OpenHtmlTag = '<html xmlns="http://www.w3.org/1999/xhtml">'
        [string]$CloseHtmlTag = '</html>'
        [string]$OpenHeadTag = '<head>'
        [string]$CloseHeadTag = '</head>'
        [string]$OpenStyleTag = '<style>'
        [string]$CloseStyleTag = '</style>'
        [string]$OpenBodyTag = '<body>'
        [string]$CloseBodyTag = '</body>'
        [string]$OpenTitleTag = '<title>'
        [string]$CloseTitleTag = '</title>'

        #Buid document
        $Document = $start
        $Document += $OpenHtmlTag
        $Document += $OpenHeadTag
        $Document += $OpenStyleTag
        $Document += $StyleSheet
        $Document += $CloseStyleTag
    
        $Document += $OpenTitleTag
        $Document += $Title
        $Document += $CloseTitleTag
    
        $Document += $CloseHeadTag
    
        $Document += $OpenBodyTag
    
        $Document += $Tabs
        $Document += $Tab1Content
        $Document += $Tab2Content
        $Document += $Tab3Content
        $Document += $Tab4Content
        $Document += $Tab5Content
        $Document += $Tab6Content
        $Document += $Tab7Content
        $Document += $Tab8Content
        $Document += $Tab9Content
        $Document += $Tab10Content

        $Document += $CloseBodyTag
    
        $Document += $CloseHtmlTag
        $Document
    }

$css = @"
input { display: none; }
input + label { display: inline-block }

input ~ .tab { display: none }
#tab1:checked ~ .tab.content1,
#tab2:checked ~ .tab.content2,
#tab3:checked ~ .tab.content3,
#tab4:checked ~ .tab.content4,
#tab5:checked ~ .tab.content5,
#tab6:checked ~ .tab.content6,
#tab7:checked ~ .tab.content7,
#tab8:checked ~ .tab.content8,
#tab9:checked ~ .tab.content9,
#tab10:checked ~ .tab.content10 { display: block; }

input + label {
  border: 1px solid #999;
  background: #EEE;
  padding: 4px 12px;
  border-radius: 4px 4px 0 0;
  position: relative;
  top: 1px;
}

input:checked + label {
  background: #f8f9fa;
  border-bottom: 1px solid transparent;
}

input ~ .tab {
  border-top: 1px solid #999;
  padding: 12px;
}



body {
    font-family:Segoe UI;
    font-size:10pt;
    font-weight: normal;
    background-color:#f8f9fa;
    margin-right: auto;
    margin-left: auto;
    width: 70%;	  
}

.container {
    display: grid;    
    grid-template-columns: repeat(2, 1fr);
    gap: 1 rem;
    padding: 5px;
    box-sizing: border-box;
}

.container div {
    padding: 8px;
    #border: 1px solid #000000;
}

.header {
    grid-column-start: 1;
    grid-column-end: span 3; 
    #background-color: pink
}

.content-small1{
    grid-row-start: 2;
    grid-row-end: 3;
    grid-column-start: 1;
    grid-column-end: 2;
    #background-color:orange;
}

.content-small2{
    grid-row-start: 2;
    grid-row-end: 3;
    grid-column-start: 2;
    grid-column-end: 4;
    #background-color:orange;
}

.content-large1 {
    grid-row-start: 3;
    grid-row-end: 4;
    grid-column-start: 1;
    grid-column-end: 4;
    #background-color: lightblue
}

.content-large2 {
    grid-column: 1 / span 3;
    grid-column-start: 1;
    grid-column-end: span 3;
    background-color: hotpink;
}

table.TABLEFRAG { 
    border-collapse: collapse;
    #border-style: hidden;    
    width:100%;
}

table.TABLEFRAG tr td {
    border-bottom: 1px solid #1976D2;
    padding: 5px;
    #background-color:#f8f9fa;
}

table.TABLEFRAG td:first-child {
    width: 13%;
}

h1 {
    color:#0D47A1;
    border-bottom: 3px solid #0D47A1;
    padding:5px;
    width:100%;
}

h2 {
    border-bottom: 2px solid #0D47A1;
    margin-top:0px;
    margin-bottom:5px;
    color:#0D47A1;
    padding:3px;
    width:100%;
    text-transform: uppercase;
    text-align:left;
    font-size:14pt;
}

p {
    margin-bottom: 2px;
    margin-top: 2px;
    margin-left: 2px;
}

th {
    font-weight:bold;
    color:#f8f9fa;
    background-color:#0D47A1;
    text-align:left;
    text-transform: uppercase;
    padding:4px;
}

tr {
    font-family:Segoe UI;
    font-size:10pt;
    font-weight: normal;
}

td {
    padding:5px;
}


.cell-pass {
    color:#DCEDC8;
    background-color:#4CAF50;
    #font-weight: bold;
}

.cell-warning {
    background-color:#FFEB3B;
    color: #4D4719;
}

.cell-dangerous {
    background-color:#FB9E00;
    color: #FFECB3;
}

.cell-severe {
    background-color:#E64A19;
    color: #FFCCBC;
}

.cell-critical {
    background-color:#BA68C8;
    color: #E5D4E8;
}

.cell-informational {
    background-color:#2196F3;
}

.cell-error {
    background-color:black;
    color: red;
}

.cell-flagrant {
    background-color: hotpink;
    color: white;
}



table.INFOTABLEFRAG {
    border-collapse: collapse;
    border-style: hidden;
    width: 100%
}

table.INFOTABLEFRAG tr td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.INFOTABLEFRAG tf:first-child {
    width: 18%;
}


table.RISKTABLEFRAG {
    border-collapse: collapse;
    border-style: hidden;
    width: 100%
}

table.RISKTABLEFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:$f8f9fa;
    width:18%;
}

table.RISKTABLEFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:$f8f9fa;
}



table.SUMTABLEFRAG { 
    border-collapse: collapse;
    border-style: hidden;    
    width:100%;
}

table.SUMTABLEFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
    width: 18%;
}

table.SUMTABLEFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.GRMEMTABLEFRAG { 
    border-collapse: collapse;
    #border-style: hidden;    
    width:100%;
}

table.GRMEMTABLEFRAG tr td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.GRMEMTABLEFRAG td:first-child {
    width: 18%;
}


table.SCAVTABLEFRAG { 
    border-collapse: collapse;
    #border-style: hidden;    
    width:100%;
}

table.SCAVTABLEFRAG tr td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.SCAVTABLEFRAG td:first-child {
    width: 33%;
}


table.PSUMTABLEFRAG { 
    border-collapse: collapse;
    #border-style: hidden;    
    width:100%;
}

table.PSUMTABLEFRAG tr td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.PSUMTABLEFRAG td:first-child {
    width: 40%;
}



table.PRIVSPNTABLE { 
    border-collapse: collapse;
    border-style: hidden;    
    width:100%;
}

table.PRIVSPNTABLEFRAG tr td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color: #f8f9fa;
}

table.PRIVSPNTABLEFRAG td:first-child {
    width: 12%;
}

table.PRIVSPNTABLEFRAG tr td:nth-child(2) {
    word-wrap: break-all;
}

table.AUDITTABLEFRAG { 
    border-collapse: collapse;
    broder-style: hidden;    
    width:100%;
}

table.AUDITTABLEFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
    width: 33%;
}

table.AUDITTABLEFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.DCTABLEFRAG { 
    border-collapse: collapse;
    broder-style: hidden;    
    width:100%;
}

table.DCTABLEFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
    width: 15%;
}

table.DCTABLEFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.COMPREPFRAG { 
    border-collapse: collapse;
    broder-style: hidden;    
    width:100%;
}

table.COMPREPFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
    width: 25%;
}

table.COMPREPFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

table.GPOPRTABLEFRAG { 
    border-collapse: collapse;
    #border-style: hidden;    
    width:100%;
}

table.GPOPRTABLEFRAG tr td {
    border-bottom: 1px solid #1976D2;
    padding: 5px;
    #background-color:#f8f9fa;
}


table.GPOPRTABLEFRAG td:nth-child(2) {
    width: 15%;
}

table.GPOPRTABLEFRAG td:nth-child(3) {
    width: 15%;
}

table.GPOPRTABLEFRAG td:nth-child(4) {
    width: 15%;
}

table.PERMTABLEFRAG { 
    border-collapse: collapse;
    broder-style: hidden;    
    width:100%;
}

table.PERMTABLEFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
    width: 50%;
}

table.PERMTABLEFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}



table.GPOPERMTABLEFRAG { 
    border-collapse: collapse;
    broder-style: hidden;    
    width:100%;
}

table.GPOPERMTABLEFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
    width: 25%;
}

table.GPOPERMTABLEFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}




table.GPLGRPTABLEFRAG { 
    border-collapse: collapse;
    broder-style: hidden;    
    width:100%;
}

table.GPLGRPTABLEFRAG td:first-child {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
    width: 25%;
}

table.GPLGRPTABLEFRAG td {
    border-bottom: 1px solid #1976D2;
    padding: 4px;
    background-color:#f8f9fa;
}

"@

    $Tabs = New-HTMLTabsFragment -TabCount 10

    $lwt = gci -Path $path -Filter * -File | select -First 1


#region Tab 1 Content: Assessment Report

#region Domain Info
$DomainInfo = (gci -Path $path -Filter ADDomainReport*).FullName

$DomainInfoTable_ = Import-Csv -Path $DomainInfo | select NetBIOSName,DNSRoot,WhenCreated,DCCount,GlobalCatalogCount,ForestMode,DomainMode | `
ConvertTo-EnhancedHTMLFragment -TableCssID INFOTABLE `
                        -TableCssClass INFOTABLEFRAG `
                        -DivCssID DIV `
                        -DivCssClass DIV `
                        -As List `
                        -MakeTableDynamic `
                        -EvenRowCssClass 'even' `
                        -OddRowCssClass 'odd' `
                        -Properties 'NetBIOSName','DNSRoot','WhenCreated','DCCount' `
                        -PreContent '<h2>Domain Information</h2>' | Out-String

$DomainInfoTable_1 = $DomainInfoTable_ -replace "<td>NetBIOSName :</td>", "<td style='width:15%'>NetBIOS Name :</td>"
$DomainInfoTable_2 = $DomainInfoTable_1 -replace "<td>DNSRoot :</td>", "<td>DNS Root :</td>"
$DomainInfoTable_3 = $DomainInfoTable_2 -replace "<td>WhenCreated :</td>", "<td>When Created :</td>"
$DomainInfoTable_4 = $DomainInfoTable_3 -replace "<td>DCCount :</td>", "<td>Domain Controller Count :</td>"
                
#endregion

#region Domain risk level

$FilePath = (gci -Path $path -Filter WarningList*).FullName
$lwt = gci -Path $path -Filter * -File | select -First 1
#$lwt = gci -Path $FilePath

$Critical = $(ipcsv $FilePath | ? Rating -eq 'Critical' | measure | select -ExpandProperty Count)
$Severe = $(ipcsv $FilePath | ? Rating -eq 'Severe' | measure | select -ExpandProperty Count)
$Dangerous = $(ipcsv $FilePath | ? Rating -eq 'Dangerous' | measure | select -ExpandProperty Count)
$Warning = $(ipcsv $FilePath | ? Rating -eq 'Warning' | measure | select -ExpandProperty Count)

if($Critical -gt '0')
{
    $DomainRiskLevel = 'Critical'
    $DomainRiskLevelDetail = "Active Directory presents critical configuration issues that immediately endangers all hosted resources. Corrective actions must be taken as soon as possible."
}
else
{
    if($severe -gt '0')
    {
        $DomainRiskLevel = 'Severe'
        $DomainRiskLevelDetail = "Active Directory has sufficient configuration and management deficiencies to jeopardize all hosted resources. Corrective actions are to be taken in the short term."
    }
    else
    {
        if($Dangerous -gt '0')
        {
            $DomainRiskLevel = 'Dangerous'
            $DomainRiskLevelDetail = "Active Directory has had an unsupported level of basic security since its installation."
        }
        else
        {
            if($Warning -gt '0')
            {
                $DomainRiskLevel = 'Warning'
                $DomainRiskLevelDetail = "Active Directory has a good level of security but some improvements are needed."
            }
            else
            {
                $DomainRiskLevel = 'State of the art'
                $DomainRiskLevelDetail = 'Active Directory has a state-of-the-art security level.'
            }
        }
    }
}

$props = [ordered]@{
    'Domain Risk Level' = $DomainRiskLevel
    'Detail' = $DomainRiskLevelDetail
}
$Risk = New-Object -TypeName psobject -Property $props

$Risk_ = $Risk | ConvertTo-EnhancedHTMLFragment -TableCssID RISKTABLE `
                                    -TableCssClass RISKTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As List `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'Domain Risk Level','Detail' `
                                    -PreContent '<h2>Domain Risk Level</h2>' | Out-String

        
$Risk_1 = $Risk_ -replace "<td>Domain Risk Level :</td>", "<td style='width:10%'>Domain Risk Level :</td>"
$Risk_2 = $Risk_1 -replace "<td>Critical</td>", "<td style='Color:#DF3CE4; font-weight:bold'>CRITICAL</td>"
$Risk_3 = $Risk_2 -replace "<td>Severe</td>", "<td style='Color:#FF2B2B; font-weight:bold'>SEVERE</td>"
$Risk_4 = $Risk_3 -replace "<td>Dangerous</td>", "<td style='Color:#ECC72C; font-weight:bold'>DANGEROUS</td>"
$Risk_5 = $Risk_4 -replace "<td>Warning</td>", "<td style='Color:#EAEC4A; font-weight:bold'>WARNING</td>"
$Risk_6 = $Risk_5 -replace "<td>State of the art</td>", "<td style='Color:#00AC46; font-weight:bold'>STATE OF THE ART</td>"

#endregion

#region Sum Table

$ADCfg_Rules = @(    
    'AD_AdminSDHolderAcls',
    'AD_AdminSDInheritance',
    'AD_AdminSDProtection',
    'AD_Backup',
    'AD_DomainPermissions',
    'AD_DupSPN',
    'AD_EmptySites',
    'AD_FunctionalLevel',
    'AD_MachineQuota',
    'AD_ManualRepConnection',
    'AD_MissingSubnets',
    'AD_RecycleBin',
    'AD_RIDcheck',
    'AD_SIDFiltering',
    'AD_Subnets',
    'AD_SysvolRep',
    'AD_Tombstone',
    'AD_UserCNOwner',
    'Dns_Scavenging',
    'Dns_ZoneSec',
    'Priv_AcctSPN')
$DCcfg_Rules = @('DC_FreeSpace',
    'DC_FSMO',
    'DC_GlobalCat',
    'DC_KrbSupEncryption',
    'DC_Owner',
    'DC_Redundancy',
    'DC_SPN',
    'DC_InstalledAV',
    'DC_LDAPCHBIND',
    'DC_NonEssRole',
    'DC_OS',
    'DC_Patching45',
    'DC_PDCTime',
    'DC_PendRB',
    'DC_ResDelegation',
    'DC_Spooler',
    'DC_SysvolPerm',
    'DC_TimeSource',
    'DC_UAC',
    'DC_UserRights',
    'DC_VulnEB',
    'DC_VulnKrb',
    'DC_WellReg')
$GroupPolicyCfg_Rules = @('DC_AuditPol',
    'GP_Autologon',
    'GP_LAPS',
    'GP_LDAPSigningDC',
    'GP_LocalGroupMbr',
    'GP_Owners',
    'GP_Permission',
    'GP_PSLangMode',
    'GP_PSLogging',
    'GP_TieredIsolation',
    'GP_GPOWithPwdPolicy')
$LegacyCfg_Rules = @('DC_SMBv1',
    'DC_TcpNetBios',
    'GP_LLMNR',
    'GP_NetCease',
    'GP_NoLMHash',
    'GP_NTLMv1',
    'GP_NullSessionEnum',
    'GP_SMBSigning',
    'GP_WDigest',
    'GP_WPAD',
    'GP_WSH')
$Pwd_Rules = @('Ac_PwCommonProp',
    'Ac_PwdNotRequired',
    'Ac_RevPwdEn',
    'AD_FGPwdPolicy',
    'AD_InvalidFGPPGroup',
    'AD_PwPolicy',
    'C_PwdLastSet90',
    'DC_AcctPwdAge',
    'GP_Passwords',
    'GP_RevPwEncryption',
    'Priv_krbtgt',
    'Priv_NoPwdExpiry',
    'Priv_PwdAge',
    'Priv_PwdNotRequired')
$PrivAccess_Rules = @('Dns_Admins',
    'Priv_AcctOwner',
    'Priv_AcctSep',
    'Priv_BAGroup',
    'Priv_DisabledAcct',
    'Priv_DomAdminUse',
    'Priv_EAGroup',
    'Priv_GPCOGroup',
    'Priv_InactiveAcct',
    'Priv_Members',
    'Priv_OrphanAccts',
    'Priv_ProtectedDelegation',
    'Priv_ProtectedUsers',
    'Priv_SAGroup',
    'Priv_ServiceAccounts',
    'Priv_ShortLivedAdmins')
$UsersComps_Rules = @(
    'Ac_DelegateToDc',    
    'Ac_DESEncr',
    'Ac_DisabledUsers',
    'Ac_KrbPreAuth',
    'Ac_PreWin2kComp',
    'Ac_GuestAcct',
    'Ac_HiddenUser',
    'Ac_Inactive180',
    'Ac_PrimaryGroupId',
    'Ac_RC4Kerberoast',
    'C_FullDelegation')


$WarningList = (Get-ChildItem -Path $OutputDir -Filter WarningList*).FullName

$ADcfg_Total = (Import-Csv $WarningList | ? RuleId -in $ADCfg_Rules ).count
$ADcfg_Match = (Import-Csv $WarningList | ? RuleId -in $ADCfg_Rules | ? Rating -eq 'Pass' | measure).count    
           
$DCcfg_Total = (Import-Csv $WarningList | ? RuleId -in $DCcfg_Rules ).count
$DCcfg_Match = (Import-Csv $WarningList | ? RuleId -in $DCcfg_Rules | ? Rating -eq 'Pass' | measure).count

$GroupPolicyCfg_Total = (Import-Csv $WarningList | ? {$_.RuleId -in $GroupPolicyCfg_Rules} ).count
$GroupPolicyCfg_Match = (Import-Csv $WarningList | ? {$_.RuleId -in $GroupPolicyCfg_Rules} | ? {$_.Rating -eq 'Pass'} | measure).count

$Legacy_Total = (Import-Csv $WarningList | ? RuleId -in $LegacyCfg_Rules ).count
$Legacy_Match = (Import-Csv $WarningList | ? RuleId -in $LegacyCfg_Rules | ? Rating -eq 'Pass' | measure).count

$Pwd_Total = (Import-Csv $WarningList | ? RuleId -in $Pwd_Rules ).count
$Pwd_Match = (Import-Csv $WarningList | ? RuleId -in $Pwd_Rules | ? Rating -eq 'Pass' | measure).count

$PrivAccess_Total = (Import-Csv $WarningList | ? RuleId -in $PrivAccess_Rules ).count
$PrivAccess_Match = (Import-Csv $WarningList | ? RuleId -in $PrivAccess_Rules | ? Rating -eq 'Pass' | measure).count

$UsersComps_Total = (Import-Csv $WarningList | ? RuleId -in $UsersComps_Rules ).count
$UsersComps_Match = (Import-Csv $WarningList | ? RuleId -in $UsersComps_Rules | ? {$_.Rating -eq 'Pass'} | measure).count


$ADCfg_Percent = "{0:P0}" -f ($ADcfg_Match/$ADcfg_Total)
$DCcfg_Percent = "{0:P0}" -f ($DCcfg_Match/$DCcfg_Total)
$GroupPolicyCfg_Percent = "{0:P0}" -f ($GroupPolicyCfg_Match/$GroupPolicyCfg_Total)
$LegacyCfg_Percent = "{0:P0}" -f ($Legacy_Match/$Legacy_Total)
$Pwd_Percent = "{0:P0}" -f ($Pwd_Match/$Pwd_Total)
$PrivAccess_Percent = "{0:P0}" -f ($PrivAccess_Match/$PrivAccess_Total)
$UsersComps_Percent = "{0:P0}" -f ($UsersComps_Match/$UsersComps_Total)


#Score Table
$Cat1 = "Active Directory Configuration"
$Cat2 = "Domain Controller Configuration"
$Cat3 = "Group Policy Configuration"
$Cat4 = "Legacy Protocols and Features"
$Cat5 = "Passwords"
$Cat6 = "Privileged Access"
$Cat7 = "Users and Computers"

$Cat1_Score = "$($ADCfg_Percent)"
$Cat2_Score = "$($DCcfg_Percent)"
$Cat3_Score = "$($GroupPolicyCfg_Percent)"
$Cat4_Score = "$($LegacyCfg_Percent)"
$Cat5_Score = "$($Pwd_Percent)"
$Cat6_Score = "$($PrivAccess_Percent)"
$Cat7_Score = "$($UsersComps_Percent)"


$Cat1_Result = "$($ADcfg_Match) rules pass of $($ADcfg_Total)"
$Cat2_Result = "$($DCcfg_Match) rules pass of $($DCcfg_Total)"
$Cat3_Result = "$($GroupPolicyCfg_Match) rules pass of $($GroupPolicyCfg_Total)"
$Cat4_Result = "$($Legacy_Match) rules pass of $($Legacy_Total)"
$Cat5_Result = "$($Pwd_Match) rules pass of $($Pwd_Total)"
$Cat6_Result = "$($PrivAccess_Match) rules pass of $($PrivAccess_Total)"
$Cat7_Result = "$($UsersComps_Match) rules pass of $($UsersComps_Total)"


$ScoreTable = @(
    [pscustomobject]@{Category=$Cat1;Score=$Cat1_Score;Result=$Cat1_Result}
    [pscustomobject]@{Category=$Cat2;Score=$Cat2_Score;Result=$Cat2_Result}
    [pscustomobject]@{Category=$Cat3;Score=$Cat3_Score;Result=$Cat3_Result}
    [pscustomobject]@{Category=$Cat4;Score=$Cat4_Score;Result=$Cat4_Result}
    [pscustomobject]@{Category=$Cat5;Score=$Cat5_Score;Result=$Cat5_Result}
    [pscustomobject]@{Category=$Cat6;Score=$Cat6_Score;Result=$Cat6_Result}
    [pscustomobject]@{Category=$Cat7;Score=$Cat7_Score;Result=$Cat7_Result}
)


$ScoreTable_Frag = $ScoreTable | ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'Category','Score','Result' `
                                    -PreContent '<br>' | Out-String
            
$ScoreFrag_w = $ScoreTable_Frag -replace "<th>Score</th>", "<th style='width:10%'>Score</th>"
$ScoreFrag_ww = $ScoreFrag_w -replace "<th>Category</th>", "<th style='width:20%'>Category</th>"

if([int]$Cat1_Score.TrimEnd('%') -le 10)
{
    $ScoreFrag_1 = $ScoreFrag_ww -replace "<td>Active Directory Configuration</td><td>$Cat1_Score</td>", "<td>Active Directory Configuration</td><td class='cell-critical'>$Cat1_Score</td>"
}
if([int]$Cat1_Score.TrimEnd('%') -in 11..30)
{
    $ScoreFrag_1 = $ScoreFrag_ww -replace "<td>Active Directory Configuration</td><td>$Cat1_Score</td>", "<td>Active Directory Configuration</td><td class='cell-severe'>$Cat1_Score</td>"
}
if([int]$Cat1_Score.TrimEnd('%') -in 31..50)
{
    $ScoreFrag_1 = $ScoreFrag_ww -replace "<td>Active Directory Configuration</td><td>$Cat1_Score</td>", "<td>Active Directory Configuration</td><td class='cell-dangerous'>$Cat1_Score</td>"
}
if([int]$Cat1_Score.TrimEnd('%') -in 51..85)
{
    $ScoreFrag_1 = $ScoreFrag_ww -replace "<td>Active Directory Configuration</td><td>$Cat1_Score</td>", "<td>Active Directory Configuration</td><td class='cell-warning'>$Cat1_Score</td>"
}
if([int]$Cat1_Score.TrimEnd('%') -gt 85)
{
    $ScoreFrag_1 = $ScoreFrag_ww -replace "<td>Active Directory Configuration</td><td>$Cat1_Score</td>", "<td>Active Directory Configuration</td><td class='cell-pass'>$Cat1_Score</td>"
}

if([int]$Cat3_Score.TrimEnd('%') -le 10)
{
    $ScoreFrag_2 = $ScoreFrag_1 -replace "<td>Domain Controller Configuration</td><td>$Cat2_Score</td>", "<td>Domain Controller Configuration</td><td class='cell-critical'>$Cat2_Score</td>"
}
if([int]$Cat2_Score.TrimEnd('%') -in 11..30)
{
    $ScoreFrag_2 = $ScoreFrag_1 -replace "<td>Domain Controller Configuration</td><td>$Cat2_Score</td>", "<td>Domain Controller Configuration</td><td class='cell-severe'>$Cat2_Score</td>"
}
if([int]$Cat2_Score.TrimEnd('%') -in 31..50)
{
    $ScoreFrag_2 = $ScoreFrag_1 -replace "<td>Domain Controller Configuration</td><td>$Cat2_Score</td>", "<td>Domain Controller Configuration</td><td class='cell-dangerous'>$Cat2_Score</td>"
}
if([int]$Cat2_Score.TrimEnd('%') -in 51..85)
{
    $ScoreFrag_2 = $ScoreFrag_1 -replace "<td>Domain Controller Configuration</td><td>$Cat2_Score</td>", "<td>Domain Controller Configuration</td><td class='cell-warning'>$Cat2_Score</td>"
}
if([int]$Cat2_Score.TrimEnd('%') -gt 85)
{
    $ScoreFrag_2 = $ScoreFrag_1 -replace "<td>Domain Controller Configuration</td><td>$Cat2_Score</td>", "<td>Domain Controller Configuration</td><td class='cell-pass'>$Cat2_Score</td>"
}

if([int]$Cat3_Score.TrimEnd('%') -le 10)
{
    $ScoreFrag_3 = $ScoreFrag_2 -replace "<td>Group Policy Configuration</td><td>$Cat3_Score</td>", "<td>Group Policy Configuration</td><td class='cell-critical'>$Cat3_Score</td>"
}
if([int]$Cat3_Score.TrimEnd('%') -in 11..30)
{
    $ScoreFrag_3 = $ScoreFrag_2 -replace "<td>Group Policy Configuration</td><td>$Cat3_Score</td>", "<td>Group Policy Configuration</td><td class='cell-severe'>$Cat3_Score</td>"
}
if([int]$Cat3_Score.TrimEnd('%') -in 31..50)
{
    $ScoreFrag_3 = $ScoreFrag_2 -replace "<td>Group Policy Configuration</td><td>$Cat3_Score</td>", "<td>Group Policy Configuration</td><td class='cell-dangerous'>$Cat3_Score</td>"
}
if([int]$Cat3_Score.TrimEnd('%') -in 51..85)
{
    $ScoreFrag_3 = $ScoreFrag_2 -replace "<td>Group Policy Configuration</td><td>$Cat3_Score</td>", "<td>Group Policy Configuration</td><td class='cell-warning'>$Cat3_Score</td>"
}
if([int]$Cat3_Score.TrimEnd('%') -gt 85)
{
    $ScoreFrag_3 = $ScoreFrag_2 -replace "<td>Group Policy Configuration</td><td>$Cat3_Score</td>", "<td>Group Policy Configuration</td><td class='cell-pass'>$Cat3_Score</td>"
}


if([int]$Cat4_Score.TrimEnd('%') -le 10)
{
    $ScoreFrag_4 = $ScoreFrag_3 -replace "<td>Legacy Protocols and Features</td><td>$Cat4_Score</td>", "<td>Legacy Protocols and Features</td><td class='cell-critical'>$Cat4_Score</td>"
}
if([int]$Cat4_Score.TrimEnd('%') -in 11..30)
{
    $ScoreFrag_4 = $ScoreFrag_3 -replace "<td>Legacy Protocols and Features</td><td>$Cat4_Score</td>", "<td>Legacy Protocols and Features</td><td class='cell-severe'>$Cat4_Score</td>"
}
if([int]$Cat4_Score.TrimEnd('%') -in 31..50)
{
    $ScoreFrag_4 = $ScoreFrag_3 -replace "<td>Legacy Protocols and Features</td><td>$Cat4_Score</td>", "<td>Legacy Protocols and Features</td><td class='cell-dangerous'>$Cat4_Score</td>"
}
if([int]$Cat4_Score.TrimEnd('%') -in 51..85)
{
    $ScoreFrag_4 = $ScoreFrag_3 -replace "<td>Legacy Protocols and Features</td><td>$Cat4_Score</td>", "<td>Legacy Protocols and Features</td><td class='cell-warning'>$Cat4_Score</td>"
}
if([int]$Cat4_Score.TrimEnd('%') -gt 85)
{
    $ScoreFrag_4 = $ScoreFrag_3 -replace "<td>Legacy Protocols and Features</td><td>$Cat4_Score</td>", "<td>Legacy Protocols and Features</td><td class='cell-pass'>$Cat4_Score</td>"
}

if([int]$Cat5_Score.TrimEnd('%') -le 10)
{
    $ScoreFrag_5 = $ScoreFrag_4 -replace "<td>Passwords</td><td>$Cat5_Score</td>", "<td>Passwords</td><td class='cell-critical'>$Cat5_Score</td>"
}
if([int]$Cat5_Score.TrimEnd('%') -in 11..30)
{
    $ScoreFrag_5 = $ScoreFrag_4 -replace "<td>Passwords</td><td>$Cat5_Score</td>", "<td>Passwords</td><td class='cell-severe'>$Cat5_Score</td>"
}
if([int]$Cat5_Score.TrimEnd('%') -in 31..50)
{
    $ScoreFrag_5 = $ScoreFrag_4 -replace "<td>Passwords</td><td>$Cat5_Score</td>", "<td>Passwords</td><td class='cell-dangerous'>$Cat5_Score</td>"
}
if([int]$Cat5_Score.TrimEnd('%') -in 51..85)
{
    $ScoreFrag_5 = $ScoreFrag_4 -replace "<td>Passwords</td><td>$Cat5_Score</td>", "<td>Passwords</td><td class='cell-warning'>$Cat5_Score</td>"
}
if([int]$Cat5_Score.TrimEnd('%') -gt 85)
{
    $ScoreFrag_5 = $ScoreFrag_4 -replace "<td>Passwords</td><td>$Cat5_Score</td>", "<td>Passwords</td><td class='cell-pass'>$Cat5_Score</td>"
}

if([int]$Cat6_Score.TrimEnd('%') -le 10)
{
    $ScoreFrag_6 = $ScoreFrag_5 -replace "<td>Privileged Access</td><td>$Cat6_Score</td>", "<td>Privileged Access</td><td class='cell-critical'>$Cat6_Score</td>"
}
if([int]$Cat6_Score.TrimEnd('%') -in 11..30)
{
    $ScoreFrag_6 = $ScoreFrag_5 -replace "<td>Privileged Access</td><td>$Cat6_Score</td>", "<td>Privileged Access</td><td class='cell-severe'>$Cat6_Score</td>"
}
if([int]$Cat6_Score.TrimEnd('%') -in 31..50)
{
    $ScoreFrag_6 = $ScoreFrag_5 -replace "<td>Privileged Access</td><td>$Cat6_Score</td>", "<td>Privileged Access</td><td class='cell-dangerous'>$Cat6_Score</td>"
}
if([int]$Cat6_Score.TrimEnd('%') -in 51..85)
{
    $ScoreFrag_6 = $ScoreFrag_5 -replace "<td>Privileged Access</td><td>$Cat6_Score</td>", "<td>Privileged Access</td><td class='cell-warning'>$Cat6_Score</td>"
}
if([int]$Cat6_Score.TrimEnd('%') -gt 85)
{
    $ScoreFrag_6 = $ScoreFrag_5 -replace "<td>Privileged Access</td><td>$Cat6_Score</td>", "<td>Privileged Access</td><td class='cell-pass'>$Cat6_Score</td>"
}

if([int]$Cat7_Score.TrimEnd('%') -le 10)
{
    $ScoreFrag_7 = $ScoreFrag_6 -replace "<td>Users and Computers</td><td>$Cat7_Score</td>", "<td>Users and Computers</td><td class='cell-critical'>$Cat7_Score</td>"
}
if([int]$Cat7_Score.TrimEnd('%') -in 11..30)
{
    $ScoreFrag_7 = $ScoreFrag_6 -replace "<td>Users and Computers</td><td>$Cat7_Score</td>", "<td>Users and Computers</td><td class='cell-severe'>$Cat7_Score</td>"
}
if([int]$Cat7_Score.TrimEnd('%') -in 31..50)
{
    $ScoreFrag_7 = $ScoreFrag_6 -replace "<td>Users and Computers</td><td>$Cat7_Score</td>", "<td>Users and Computers</td><td class='cell-dangerous'>$Cat7_Score</td>"
}
if([int]$Cat7_Score.TrimEnd('%') -in 51..85)
{
    $ScoreFrag_7 = $ScoreFrag_6 -replace "<td>Users and Computers</td><td>$Cat7_Score</td>", "<td>Users and Computers</td><td class='cell-warning'>$Cat7_Score</td>"
}
if([int]$Cat7_Score.TrimEnd('%') -gt 85)
{
    $ScoreFrag_7 = $ScoreFrag_6 -replace "<td>Users and Computers</td><td>$Cat7_Score</td>", "<td>Users and Computers</td><td class='cell-pass'>$Cat7_Score</td>"
}

#endregion

#region Active Directory Configuration Table
$ADCfg_Frag = Import-Csv $FilePath | ? RuleId -in $ADCfg_Rules  | sort RuleId | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'RuleId','Rating','Description' `
                                    -PostContent 'Active Directory is considered the backbone of identity and access management. It acts as the gatekeeper to the corporate network, granting authorized access to critical resources and applications.
                                    In recent years, the threat of cyberattacks, particularly ransomware, has significantly escalated. Adversaries are using increasingly sophisticated methods to penetrate corporate networks, often leveraging misconfigurations or legacy configurations to gain access.<br /><br />' `
                                    -PreContent '<h2>Active Directory Configuration</h2>' | Out-String
            
# Update HTML to color code cells   
$adcfg_1 = $ADCfg_Frag -replace "<td>Pass</td>", "<td class='cell-pass'>Pass</td>"
$adcfg_2 = $adcfg_1 -replace "<td>Critical</td>", "<td class='cell-critical'>Critical</td>"
$adcfg_3 = $adcfg_2  -replace "<td>Severe</td>", "<td class='cell-severe'>Severe</td>"
$adcfg_4 = $adcfg_3 -replace "<td>Dangerous</td>", "<td class='cell-dangerous'>Dangerous</td>"
$adcfg_5 = $adcfg_4 -replace "<td>Warning</td>", "<td class='cell-warning'>Warning</td>"
$adcfg_6 = $adcfg_5 -replace "<td>Informational</td>", "<td class='cell-informational'>Informational</td>"
$adcfg_7 = $adcfg_6 -replace "<th>RuleId</th>", "<th style='width:10%'>RuleId</th>"
$adcfg_8 = $adcfg_7 -replace "<th>Rating</th>", "<th style='width:10%'>Rating</th>"
$adcfg_9 = $adcfg_8 -replace "<th>Description</th>", "<th style='width:80%'>Description</th>"
$adcfg_10 = $adcfg_9 -replace "<td>Error</td>", "<td class='cell-error'>Error</td>"

#endregion

#region Domain Controller Configuration Table   

$DCcfg_Frag = Import-Csv $FilePath | ? RuleId -in $DCcfg_Rules  | sort RuleId | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'RuleId','Rating','Description' `
                                    -PostContent 'Domain controllers provide the physical storage for the Active Directory database, in addition to providing the services and data that allow enterprises to effectively manage their server, workstations, users, and applications.<br /><br />' `
                                    -PreContent '<h2>Domain Controller Configuration</h2>' | Out-String
            
# Update HTML to color code cells   
$DCcfg_1 = $DCcfg_Frag -replace "<td>Pass</td>", "<td class='cell-pass'>Pass</td>"
$DCcfg_2 = $DCcfg_1 -replace "<td>Critical</td>", "<td class='cell-critical'>Critical</td>"
$DCcfg_3 = $DCcfg_2  -replace "<td>Severe</td>", "<td class='cell-severe'>Severe</td>"
$DCcfg_4 = $DCcfg_3 -replace "<td>Dangerous</td>", "<td class='cell-dangerous'>Dangerous</td>"
$DCcfg_5 = $DCcfg_4 -replace "<td>Warning</td>", "<td class='cell-warning'>Warning</td>"
$DCcfg_6 = $DCcfg_5 -replace "<td>Flagrant</td>", "<td class='cell-flagrant'>Flagrant</td>"
$DCcfg_7 = $DCcfg_6 -replace "<td>Informational</td>", "<td class='cell-informational'>Informational</td>"
$DCcfg_8 = $DCcfg_7 -replace "<th>RuleId</th>", "<th style='width:10%'>RuleId</th>"
$DCcfg_9 = $DCcfg_8 -replace "<th>Rating</th>", "<th style='width:10%'>Rating</th>"
$DCcfg_10 = $DCcfg_9 -replace "<th>Description</th>", "<th style='width:80%'>Description</th>"
$DCcfg_11 = $DCcfg_10 -replace "<td>Error</td>", "<td class='cell-error'>Error</td>"

#endregion

#region Group Policy Configuration Table 

$GroupPolicyCfg_Frag = Import-Csv $FilePath | ? RuleId -in $GroupPolicyCfg_Rules  | sort RuleId | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'RuleId','Rating','Description' `
                                    -PostContent 'The process of exploiting a vulnerability or misconfiguration to gain elevated access to sensitive information or perform unauthorized actions. This is often used to gain administrative-level access to a system, allowing them to steal sensitive data, install malware, or cause damage.<br /><br />' `
                                    -PreContent '<h2>Group Policy Configuration</h2>' | Out-String
            
# Update HTML to color code cells   
$GPcfg_1 = $GroupPolicyCfg_Frag -replace "<td>Pass</td>", "<td class='cell-pass'>Pass</td>"
$GPcfg_2 = $GPcfg_1 -replace "<td>Critical</td>", "<td class='cell-critical'>Critical</td>"
$GPcfg_3 = $GPcfg_2  -replace "<td>Severe</td>", "<td class='cell-severe'>Severe</td>"
$GPcfg_4 = $GPcfg_3 -replace "<td>Dangerous</td>", "<td class='cell-dangerous'>Dangerous</td>"
$GPcfg_5 = $GPcfg_4 -replace "<td>Warning</td>", "<td class='cell-warning'>Warning</td>"
$GPcfg_6 = $GPcfg_5 -replace "<td>Informational</td>", "<td class='cell-informational'>Informational</td>"
$GPcfg_7 = $GPcfg_6 -replace "<th>RuleId</th>", "<th style='width:10%'>RuleId</th>"
$GPcfg_8 = $GPcfg_7 -replace "<th>Rating</th>", "<th style='width:10%'>Rating</th>"
$GPcfg_9 = $GPcfg_8 -replace "<th>Description</th>", "<th style='width:80%'>Description</th>"
$GPcfg_10 = $GPcfg_9 -replace "<td>Error</td>", "<td class='cell-error'>Error</td>"

#endregion

#region Legacy Protocols and Features Table 

$LegacyCfg_Frag = Import-Csv $FilePath | ? RuleId -in $LegacyCfg_Rules  | sort RuleId | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'RuleId','Rating','Description' `
                                    -PostContent 'Legacy protocols and features are outdated communication standards that were designed before the security needs of todays modern enterprise. These protocols often remain active within the environment resulting in vulnerabilities that an attacker can exploit to gain or elevate unauthorized access.<br /><br />' `
                                    -PreContent '<h2>Legacy Protocols and Features</h2>' | Out-String
            
# Update HTML to color code cells   
$Legacy_1 = $LegacyCfg_Frag -replace "<td>Pass</td>", "<td class='cell-pass'>Pass</td>"
$Legacy_2 = $Legacy_1 -replace "<td>Critical</td>", "<td class='cell-critical'>Critical</td>"
$Legacy_3 = $Legacy_2  -replace "<td>Severe</td>", "<td class='cell-severe'>Severe</td>"
$Legacy_4 = $Legacy_3 -replace "<td>Dangerous</td>", "<td class='cell-dangerous'>Dangerous</td>"
$Legacy_5 = $Legacy_4 -replace "<td>Warning</td>", "<td class='cell-warning'>Warning</td>"
$Legacy_6 = $Legacy_5 -replace "<td>Informational</td>", "<td class='cell-informational'>Informational</td>"
$Legacy_7 = $Legacy_6 -replace "<th>RuleId</th>", "<th style='width:10%'>RuleId</th>"
$Legacy_8 = $Legacy_7 -replace "<th>Rating</th>", "<th style='width:10%'>Rating</th>"
$Legacy_9 = $Legacy_8 -replace "<th>Description</th>", "<th style='width:80%'>Description</th>"
$Legacy_10 = $Legacy_9 -replace "<td>Error</td>", "<td class='cell-error'>Error</td>"


#endregion

#region Passwords Table  

$Pwd_Frag = Import-Csv $FilePath | ? RuleId -in $Pwd_Rules  | sort RuleId | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'RuleId','Rating','Description' `
                                    -PostContent 'A security concept that states that a user or system should only have the minimum level of access necessary to perform its intended functions. The idea is to reduce the risk of security breaches by limiting the potential damage that can be done by a user or system that has been compromised.<br /><br />' `
                                    -PreContent '<h2>Passwords</h2>' | Out-String
            
# Update HTML to color code cells   
$Pwd_1 = $Pwd_Frag -replace "<td>Pass</td>", "<td class='cell-pass'>Pass</td>"
$Pwd_2 = $Pwd_1 -replace "<td>Critical</td>", "<td class='cell-critical'>Critical</td>"
$Pwd_3 = $Pwd_2  -replace "<td>Severe</td>", "<td class='cell-severe'>Severe</td>"
$Pwd_4 = $Pwd_3 -replace "<td>Dangerous</td>", "<td class='cell-dangerous'>Dangerous</td>"
$Pwd_5 = $Pwd_4 -replace "<td>Warning</td>", "<td class='cell-warning'>Warning</td>"
$Pwd_6 = $Pwd_5 -replace "<td>Informational</td>", "<td class='cell-informational'>Informational</td>"
$Pwd_7 = $Pwd_6 -replace "<th>RuleId</th>", "<th style='width:10%'>RuleId</th>"
$Pwd_8 = $Pwd_7 -replace "<th>Rating</th>", "<th style='width:10%'>Rating</th>"
$Pwd_9 = $Pwd_8 -replace "<th>Description</th>", "<th style='width:80%'>Description</th>"
$Pwd_10 = $Pwd_9 -replace "<td>Error</td>", "<td class='cell-error'>Error</td>"

#endregion

#region Privileged Access Table

$PrivAccess_Frag = Import-Csv $FilePath | ? RuleId -in $PrivAccess_Rules  | sort RuleId | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'RuleId','Rating','Description' `
                                    -PostContent "Active Directory administrtion is typically performed by a small number of people. The number of privileged accounts typically exeeds the number of actual AD admins. Domain Admins members have FULL administrative rights to all workstations, servers, domain controllers, Active Directory, Group Policy, etc. by default. This is too much power for any one account in today's modern enterprise.<br /><br />" `
                                    -PreContent '<h2>Privileged Access</h2>' | Out-String
            
# Update HTML to color code cells   
$PrivAcc_1 = $PrivAccess_Frag -replace "<td>Pass</td>", "<td class='cell-pass'>Pass</td>"
$PrivAcc_2 = $PrivAcc_1 -replace "<td>Critical</td>", "<td class='cell-critical'>Critical</td>"
$PrivAcc_3 = $PrivAcc_2  -replace "<td>Severe</td>", "<td class='cell-severe'>Severe</td>"
$PrivAcc_4 = $PrivAcc_3 -replace "<td>Dangerous</td>", "<td class='cell-dangerous'>Dangerous</td>"
$PrivAcc_5 = $PrivAcc_4 -replace "<td>Warning</td>", "<td class='cell-warning'>Warning</td>"
$PrivAcc_6 = $PrivAcc_5 -replace "<td>Informational</td>", "<td class='cell-informational'>Informational</td>"
$PrivAcc_7 = $PrivAcc_6 -replace "<th>RuleId</th>", "<th style='width:10%'>RuleId</th>"
$PrivAcc_8 = $PrivAcc_7 -replace "<th>Rating</th>", "<th style='width:10%'>Rating</th>"
$PrivAcc_9 = $PrivAcc_8 -replace "<th>Description</th>", "<th style='width:80%'>Description</th>"
$PrivAcc_10 = $PrivAcc_9 -replace "<td>Error</td>", "<td class='cell-error'>Error</td>"

#endregion

#region Users and Computers Table     
$UsersComps_Frag = Import-Csv $FilePath | ? RuleId -in $UsersComps_Rules  | sort RuleId | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                    -TableCssClass TABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties 'RuleId','Rating','Description' `
                                    -PostContent 'The process of minimizing the potential entry points that attackers can use to compromise a system or network. This is achieved by removing or reducing access to unnecessary systems, applications, and data, as well as implementing security controls to prevent or detect malicious activity.<br \><br \>' `
                                    -PreContent '<h2>Users and Computers</h2>' | Out-String
            
# Update HTML to color code cells   
$UsersComps_1 = $UsersComps_Frag -replace "<td>Pass</td>", "<td class='cell-pass'>Pass</td>"
$UsersComps_2 = $UsersComps_1 -replace "<td>Critical</td>", "<td class='cell-critical'>Critical</td>"
$UsersComps_3 = $UsersComps_2  -replace "<td>Severe</td>", "<td class='cell-severe'>Severe</td>"
$UsersComps_4 = $UsersComps_3 -replace "<td>Dangerous</td>", "<td class='cell-dangerous'>Dangerous</td>"
$UsersComps_5 = $UsersComps_4 -replace "<td>Warning</td>", "<td class='cell-warning'>Warning</td>"
$UsersComps_6 = $UsersComps_5 -replace "<td>Informational</td>", "<td style='background-color:#2BBFFF'>Informational</td>"
$UsersComps_7 = $UsersComps_6 -replace "<th>RuleId</th>", "<th style='width:10%'>RuleId</th>"
$UsersComps_8 = $UsersComps_7 -replace "<th>Rating</th>", "<th style='width:10%'>Rating</th>"
$UsersComps_9 = $UsersComps_8 -replace "<th>Description</th>", "<th style='width:80%'>Description</th>"
$UsersComps_10 = $UsersComps_9 -replace "<td>Error</td>", "<td class='cell-error'>Error</td>"

#endregion

$t1 = @"
<div class="tab content1">
<h1>Active Directory Assessment- $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString()) </p> `
<br>Active Directory is the security center of Microsoft's information system. It is a critical element for the centralized management of accounts, resources, and permissions. Obtaining high-level privileges in this directory can result in an instantaneous and complete takeover of the forest.`
<br><br>Analysis of recent attacks reveals an increase in Active Directory targeting, given its role as the cornerstone of most information systems. An attacker who has obtained privileged rights in the directory can then deploy malicious software to the entire information system, especially by GPO or by using direct connections(WinRM, psexec, wmiexec). The lack of directory security endangers information systems as a whole and places a systemic risk on organizations. `
<br /><br />

$DomainInfoTable_4 
<br>
$Risk_6
$ScoreFrag_7
<br><br><br>
$adcfg_10
<br><br>
$DCcfg_10
<br><br>
$GPcfg_10
<br><br>
$Legacy_10
<br><br>
$Pwd_10
<br><br>
$PrivAcc_10
<br><br>
$UsersComps_10

<br><br><hr />copyright RSM 2022<br><br>

</div>


"@
#endregion


#region Tab 2 Content: Privileged Accounts

#region Group Count
$PrivilegedAccountsFile = (Get-ChildItem -Path "$path" -Filter 'PrivilegedAccounts-*').FullName
$PrivilegedAccounts = Import-Csv $PrivilegedAccountsFile
$GroupNames = Import-Csv $PrivilegedAccountsFile | Group GroupName
$GroupCountArray = @()

foreach($group in $GroupNames)
{
    $obj = "" | select GroupName,Users,Groups,Computers

    $objectClass = $PrivilegedAccounts | Where GroupName -eq $group.Name | group ObjectClass
    $users = $objectClass | Where Name -eq user
    $computers = $objectClass | Where Name -eq computer 
    $groups = $objectClass | Where Name -eq group

    $obj.GroupName = $group.Name
    $obj.Users = $users.count
    $obj.groups = $groups.count
    $obj.Computers = $computers.count
    $GroupCountArray += $obj
    $obj = $null
}

$GroupCount = $GroupCountArray | `
ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties 'GroupName','Users','Groups','Computers' `
                                -PostContent 'All privileged groups and their memeber count.<br /><br />'`
                                -PreContent '<h2>Group Member Count</h2>' | Out-String
                        
#endregion

#region Privileged Members

$Priv = (Get-ChildItem -Path "$path\findings" -Filter Priv_Members2*).FullName
$PrivMembers = Import-Csv -Path $Priv | select MemberName,SamAccountName,Enabled,LastLogonAge,PasswordAge,GroupMembership | `
ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                        -TableCssClass TABLEFRAG `
                        -DivCssID DIV `
                        -DivCssClass DIV `
                        -As Table `
                        -MakeTableDynamic `
                        -EvenRowCssClass 'even' `
                        -OddRowCssClass 'odd' `
                        -Properties 'MemberName','SamAccountName','Enabled','LastLogonAge','PasswordAge','GroupMembership' `
                        -PostContent "Accounts that have privilege in the domain and the groups they are a member of.<br /><br />" `
                        -PreContent '<h2>Privileged Accounts</h2>' | Out-String        
#endregion

#region Administrators Group

$BAGroup = (Get-ChildItem -Path "$Path\findings" -Filter Priv_BAGroup*).FullName
if((Get-ChildItem -Path "$Path\findings" -Filter Priv_BAGroup*).Length -gt '0')
{
    $Administrators = Import-Csv -Path $BAGroup | select MemberName,SamAccountName,enabled,LastLogonAge,PasswordAge,IsProtected,AccountNotDelegated | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'MemberName','SamAccountName','enabled','LastLogonAge','PasswordAge','IsProtected','AccountNotDelegated' `
                            -PostContent 'Membership in the Built-In Administrators group should be required only in build or disaster recovery scenarios. 
                                            There should be no day-to-day user accounts in the Administrators group with the exception of the Built-In Administrator account for the domain.<br /><br />' `
                            -PreContent '<h2>Administrators Group</h2>' | Out-String        
}
#endregion

#region Domain Admins

$DAGroup = (Get-ChildItem -Path "$Path" -Filter PrivilegedAccounts-*).FullName
$DAMembers = Import-Csv -Path $DAGroup | ? {$_.GroupName -eq 'Domain Admins'} | select MemberName,SamAccountName,enabled,LastLogonAge,PasswordAge,IsProtected,AccountNotDelegated | `
ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                        -TableCssClass TABLEFRAG `
                        -DivCssID DIV `
                        -DivCssClass DIV `
                        -As Table `
                        -MakeTableDynamic `
                        -EvenRowCssClass 'even' `
                        -OddRowCssClass 'odd' `
                        -Properties 'MemberName','SamAccountName','enabled','LastLogonAge','PasswordAge','IsProtected','AccountNotDelegated' `
                        -PostContent 'Each domain is a forest has its own Domain Admins group, which is a member of that domains Built-in Administrators groupas well as a member of the local Administrators group on every machine that is joined to the doamin. Domain Admins are all powerfull within their domains.<br /><br />' `
                        -PreContent '<h2>Domain Admins Group</h2>' | Out-String        
#endregion

#region Enterprise Administrators Group

$EAGroup = (Get-ChildItem -Path "$Path\findings" -Filter Priv_EAGroup*).FullName
$EnterpriseAdmins = Import-Csv -Path $EAGroup | select MemberName,SamAccountName,enabled,LastLogonAge,PasswordAge,IsProtected,AccountNotDelegated | `
ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                        -TableCssClass TABLEFRAG `
                        -DivCssID DIV `
                        -DivCssClass DIV `
                        -As Table `
                        -MakeTableDynamic `
                        -EvenRowCssClass 'even' `
                        -OddRowCssClass 'odd' `
                        -Properties 'MemberName','SamAccountName','enabled','LastLogonAge','PasswordAge','IsProtected','AccountNotDelegated' `
                        -PostContent 'Membership in the Enterprise Administrators group should be required only in build or disaster recovery scenarios. 
                                        There should be no day-to-day user accounts in the Enterprise Administrators group with the exception of the Built-In Administrator account for the domain.<br /><br />' `
                        -PreContent '<h2>Enterprise Administrators Group</h2>' | Out-String
#endregion

#region Schema Administrators

$SAGroup = (Get-ChildItem -Path "$Path\findings" -Filter Priv_SAGroup*).FullName
if($SAGroup -ne $null)
{
    $SchemaAdmins = Import-Csv -Path $SAGroup | select MemberName,SamAccountName,enabled,LastLogonAge,PasswordAge,IsProtected,AccountNotDelegated | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'MemberName','SamAccountName','enabled','LastLogonAge','PasswordAge','IsProtected','AccountNotDelegated' `
                            -PostContent 'Membership in the Schema Administrators group should be required only in build or disaster recovery scenarios. 
                                            There should be no day-to-day user accounts in the Schema Administrators group with the exception of the Built-In Administrator account for the domain.<br /><br />' `
                            -PreContent '<h2>Schema Administrators Group</h2>' | Out-String
    }
#endregion

#region Operator Group Members

$PrivAccts = (Get-ChildItem -Path "$Path" -Filter PrivilegedAccounts-*).FullName
$Operators = Import-Csv -Path $PrivAccts | Where {$_.GroupName -eq "Account Operators" -or $_.GroupName -eq "Server Operators" -or $_.GroupName -eq "Print Operators" -or $_.GroupName -eq "Backup Operators"} | select GroupName,MemberName,SamAccountName,enabled,LastLogonAge,PasswordAge,IsProtected | `
ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                        -TableCssClass TABLEFRAG `
                        -DivCssID DIV `
                        -DivCssClass DIV `
                        -As Table `
                        -MakeTableDynamic `
                        -EvenRowCssClass 'even' `
                        -OddRowCssClass 'odd' `
                        -Properties 'GroupName','MemberName','SamAccountName','enabled','LastLogonAge','PasswordAge','IsProtected' `
                        -PostContent 'The default Operator groups (Account Operators, Server Operators, Backup Operators, and Print Operators) have excessive rights; many more than required. 
                                        These groups have elevated rights on domain controllers and should be considered effectively domain controller admins.<br /><br />' `
                        -PreContent '<h2>BUILTIN Operator Groups</h2>' | Out-String
#endregion

#region DNS Admins

$DnsAdmins = (Get-ChildItem -Path "$Path\findings" -Filter Priv_DNSAdmins*).FullName
if((Get-ChildItem -Path "$Path\findings" -Filter Priv_DNSAdmins*).Length -gt '0')
{
    $DnsAdmins_frag = Import-Csv -Path $DnsAdmins | select  | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'MemberName','SamAccountName','enabled','LastLogonAge','PasswordAge','IsProtected','AccountNotDelegated' `
                            -PostContent 'Members of the DnsAdmins group have the right to manage the Microsoft DNS service. Among these rights is the ability to have arbitrary code executed by the DNS server which is usually the domain controller.<br /><br />' `
                            -PreContent '<h2>DNS Admins</h2>' | Out-String
}
#endregion

#region Pre-Windows 2000 Compatible Access Group

$PreWin2k = (Get-ChildItem -Path "$Path" -Filter PreWindows2000*).FullName
if((Get-ChildItem -Path "$Path" -Filter PreWindows2000*).Length -gt '0')
{
    $PreWin2k_frag = Import-Csv -Path $PreWin2k | select  | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "name","objectClass","SamAccountName","distinguishedName" `
                            -PostContent 'The Pre-Windows 2000 Compatible Access (PreWin2k) group is a legacy group that was created to allow interoperability with Windows NT domains.<br /><br />' `
                            -PreContent '<h2>Pre-Windows 2000 Compatible Access</h2>' | Out-String
}
#endregion

#region Password Not Required

$PwdNotReq = (Get-ChildItem -Path "$Path\findings" -Filter Ac_PwdNotReq*).FullName
if((Get-ChildItem -Path "$Path\findings" -Filter Ac_PwdNotReq*).length -gt '0')
{
    $PwdNotReq_frag = Import-Csv -Path $PwdNotReq | select "Name","SAMAccountname","Enabled","PasswordNotRequired" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PasswordNotRequired" `
                            -PostContent 'Accounts with the PASSWORD_NOTREQD flag may not have to have a password. It also means that any password will be acceptable - a short one, a non-compliant one, or an empty one. Accounts should not have this flag set.<br /><br />' `
                            -PreContent '<h2>Password Not Required</h2>' | Out-String
}
else
{
    $PwdNotReq_frag = [pscustomobject]@{Name='';SAMAccountname='';Enabled='';PasswordNotRequired=''} | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PasswordNotRequired" `
                            -PostContent 'Accounts with the PASSWORD_NOTREQD flag may not have to have a password. It also means that any password will be acceptable - a short one, a non-compliant one, or an empty one. Accounts should not have this flag set.<br /><br />' `
                            -PreContent '<h2>Password Not Required</h2>' | Out-String

}
#endregion

#region Privilege Password Not Required

$PrivPwdNotReq = (Get-ChildItem -Path "$Path\findings" -Filter Priv_PwdNotReq*).FullName
if((Get-ChildItem -Path "$Path\findings" -Filter Priv_PwdNotReq*).length -gt '0')
{
    $PrivPwdNotReq_frag = Import-Csv -Path $PrivPwdNotReq | select "Name","SAMAccountname","Enabled","PasswordNotRequired" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PasswordNotRequired" `
                            -PostContent 'Accounts with the PASSWORD_NOTREQD flag may not have to have a password. It also means that any password will be acceptable - a short one, a non-compliant one, or an empty one. Accounts should not have this flag set.<br /><br />' `
                            -PreContent '<h2>Privileged Accounts Password Not Required</h2>' | Out-String
}

#endregion

#region Non Default Groups
$continue = $true
$NDFGroupFile = (Get-ChildItem -Path "$Path\findings" -Filter Priv_NDf*).FullName

try{Test-Path $NDFGroupFile -ErrorAction stop | Out-Null}
catch{$continue = $false}

if($continue)
{
    $NDfGroups = Import-Csv -Path $NDFGroupFile | Select GroupName -Unique
    $PrivAcctsFile = (Get-ChildItem -Path "$Path" -Filter PrivilegedAccounts-*).FullName
    foreach($group in $NDFGroups)
    {
        $GroupName = $group.Groupname
        $Members = Import-Csv -Path $PrivAcctsFile | ? GroupName -like $group.GroupName | select MemberName,SamAccountName,enabled,LastLogonAge,PasswordAge,IsProtected,AccountNotDelegated | `
        ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                -TableCssClass TABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties 'MemberName','SamAccountName','enabled','LastLogonAge','PasswordAge','IsProtected','AccountNotDelegated' `
                                -PostContent 'Non-default privileged groups. These groups are a member of one or more highly-privileged groups. Members of these groups have elevated rights on the domain.<br /><br />'  `
                                -PreContent "<h2>$groupName</h2>" | Out-String                                            
    }
}
#endregion

#region Group Policy Creator Owners

if((Get-ChildItem -Path "$Path" -Filter Priv_GPCO*).length -gt '0')
{
    $GPCOFile = (Get-ChildItem -Path "$Path" -Filter Priv_GPCO* ).FullName
    $GPCO = Import-Csv -Path $GPCOFile | select "distinguishedName","name","objectClass","objectGUID","SamAccountName","SID" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "name","SamAccountName","objectClass" `
                            -PostContent "Membership in the Group Policy Creator Owners assigns a high privilege level for AD functions. This group is authorized to create, edit, or delete Group Policy Objects in the domain. Membership increases the risk from compromise or unintended updates. By default, the only member of the group is the domain Administrator..<br /><br />" `
                            -PreContent '<h2>Group Policy Creator Owners</h2>' | Out-String
}
else
{
    $GPCOFile = [pscustomobject]@{Name='';SamAccountName='';ObjectClass=''}
    $GPCO = $GPCOFile | select "distinguishedName","name","objectClass","objectGUID","SamAccountName","SID" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "name","SamAccountName","objectClass" `
                            -PostContent "Membership in the Group Policy Creator Owners assigns a high privilege level for AD functions. This group is authorized to create, edit, or delete Group Policy Objects in the domain. Membership increases the risk from compromise or unintended updates. By default, the only member of the group is the domain Administrator..<br /><br />" `
                            -PreContent '<h2>Group Policy Creator Owners</h2>' | Out-String
}
#endregion

#region Incoming Forest Trust Builders

if((Get-ChildItem -Path "$Path" -Filter Priv_IFTB*).length -gt '0')
{
    $IFTBFile = (Get-ChildItem -Path "$Path" -Filter Priv_GPCO* ).FullName
    $IFTB = Import-Csv -Path $IFTBFile | select "distinguishedName","name","objectClass","objectGUID","SamAccountName","SID" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "name","SamAccountName","objectClass" `
                            -PostContent "Grants members permission to Create Inbound Forest Trusts.<br /><br />" `
                            -PreContent '<h2>Incoming Forest Trust Builders</h2>' | Out-String
}
else
{
    $IFTBFile = [pscustomobject]@{Name='';SamAccountName='';ObjectClass=''}
    $IFTB = $IFTBFile | select "distinguishedName","name","objectClass","objectGUID","SamAccountName","SID" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "name","SamAccountName","objectClass" `
                            -PostContent "Grants members permission to Create Inbound Forest Trusts.<br /><br />" `
                            -PreContent '<h2>Incoming Forest Trust Builders</h2>' | Out-String
}
#endregion

#region Privileged Account SPNs

if((Get-ChildItem -Path "$Path\findings" -Filter Priv_AcctSPN*).length -gt '0')
{
    $SPNs = (Get-ChildItem -Path "$Path\findings" -Filter Priv_AcctSPN*).FullName
    $PrivAcctSPN = Import-Csv -Path $SPNs | select UserId,@{l='SPNServers';e={ $_.SPNServers -replace ",",", "}},@{l="SPNs";e={$_.SPNs -replace ",",", "}} | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'UserId','SPNServers','SPNs' `
                            -PostContent "Warning: SPN for a privileged account poses a severe security risk. As a result the password for these accounts are vulnerable to discovery.<br /><br />" `
                            -PreContent '<h2>Privileged Accounts With An SPN</h2>' | Out-String
}
else
{
    $SPNs = [pscustomobject]@{UserId='';SPNServers='';SPNs=''}
    $PrivAcctSPN = $SPNs | select UserId,@{l='SPNServers';e={ $_.SPNServers -replace ",",", "}},@{l="SPNs";e={$_.SPNs -replace ",",", "}} | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'UserId','SPNServers','SPNs' `
                            -PostContent "Warning: SPN for a privileged account poses a severe security risk. As a result the password for these accounts are vulnerable to discovery.<br /><br />" `
                            -PreContent '<h2>Privileged Accounts With An SPN</h2>' | Out-String
}

#endregion

#region Service Account Password Info

if((Get-ChildItem -Path "$Path" -Filter ServiceAccountPasswordInfo*).length -gt '0')
{
    $SvcPwd = (Get-ChildItem -Path $Path -Filter ServiceAccountPasswordInfo*).FullName
    $SvcPwd_frag = Import-Csv -Path $SvcPwd | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "SamAccountName","LastLogonDate","PasswordAgeYears","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired","PasswordExpired","AdminCount" `
                            -PostContent "Passwords for accounts with an SPN are vulnerable to discovery through Kerberoasting. Since service account passwords rarely change, it is important to know the password age. What was the password policy at the time it was set? What OS version were the domain controllers at that time? Could these accounts have a weak password? Are they stored with LMHash encryption?<br /><br />" `
                            -PreContent '<h2>Service Account Passwords</h2>' | Out-String
}
else
{
    $SvcPwd = [pscustomobject]@{SamAccountName='';LastLogonDate='';PasswordAgeYears='';PasswordLastSet='';PasswordNeverExpires='';PasswordNotRequired='';PasswordExpired='';AdminCount=''}
    $SvcPwd_frag = $SvcPwd | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "SamAccountName","LastLogonDate","PasswordAgeYears","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired","PasswordExpired","AdminCount" `
                            -PostContent "Passwords for accounts with an SPN are vulnerable to discovery through Kerberoasting. Since service account passwords rarely change, it is important to know the password age. What was the password policy at the time it was set? What OS version were the domain controllers at that time? Could these accounts have a weak password? Are they stored with LMHash encryption?<br /><br />" `
                            -PreContent '<h2>Service Account Passwords</h2>' | Out-String
}

#endregion

#region Privileged Account Owner
if((Get-ChildItem -Path "$Path" -Filter Priv_Owners*).length -gt '0')
{
    $PrivOwner = (Get-ChildItem -Path "$Path" -Filter Priv_Owners-*).FullName
    if((Import-Csv -Path $PrivOwner | Where Owner -NotLike "*Domain Admins").count -gt 0)
    {
        $PrivOwner_frag = Import-Csv -Path $PrivOwner | Where Owner -NotLike "*Domain Admins" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                -TableCssClass TABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties 'Account','Owner' `
                                -PostContent "If a privileged account is owned by an unprivileged account. Compromise of an unprivileged account could result in a privileged object’s delegation being modified. The following are privileged account that are not owned by the Domain Admins group.<br /><br />" `
                                -PreContent '<h2>Privileged Account Owners</h2>' | Out-String
    }
    else
    {
        $PrivOwner = [pscustomobject]@{Account='';Owner=''}
        $PrivOwner_frag = $PrivOwner | `
        ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                                -TableCssClass TABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties 'Account','Owner' `
                                -PostContent "If a privileged account is owned by an unprivileged account. Compromise of an unprivileged account could result in a privileged object’s delegation being modified.<br /><br />" `
                                -PreContent '<h2>Privileged Account Owners</h2>' | Out-String    
    }
}
else
{
    $PrivOwner = [pscustomobject]@{Account='';Owner=''}
    $PrivOwner_frag = $PrivOwner | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Account','Owner' `
                            -PostContent "If a privileged account is owned by an unprivileged account. Compromise of an unprivileged account could result in a privileged object’s delegation being modified.<br /><br />" `
                            -PreContent '<h2>Privileged Account Owners</h2>' | Out-String
}
#endregion

#region RC4 Kerberoast

if((Get-ChildItem -Path "$Path" -Filter Ac_RC4Kerberoast*).length -gt '0')
{
    $RC4KFile = (Get-ChildItem -Path "$Path" -Filter Ac_RC4Kerberoast*).FullName
    $RC4KFrag = Import-Csv -Path $RC4KFile | select 'Name','Enabled','PasswordLastSet',@{l='EncryptionType';e={$_.EncryptionTypeAsString}},'HasRC4orIsBlank' | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Name','Enabled','PasswordLastSet','EncryptionType','HasRC4orIsBlank' `
                            -PostContent "These service accounts use RC4 encryption for Kerberos. This encyption type is weak and easily cracked.<br /><br />" `
                            -PreContent '<h2>RC4 Kerberoasting</h2>' | Out-String
}
else
{
    $RC4KFile = [pscustomobject]@{Name='';Enabled='';PasswordLastSet='';EncryptionType='';HasRc4orIsBlank=''}
    $RC4KFrag = $RC4KFile | select 'Name','Enabled','PasswordLastSet',@{l='EncryptionType';e={$_.EncryptionTypeAsString}},'HasRC4orIsBlank' | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Name','Enabled','PasswordLastSet','EncryptionType','HasRC4orIsBlank' `
                            -PostContent "These service accounts use RC4 encryption for Kerberos. This encyption type is weak and easily cracked.<br /><br />" `
                            -PreContent '<h2>RC4 Kerberoasting</h2>' | Out-String
}

#endregion

#region Orphaned Admin Accounts

if((Get-ChildItem -Path "$Path" -Filter orphanedaccounts*).length -gt '0')
{
    $Orphans = (Get-ChildItem -Path "$Path" -Filter orphanedaccounts*).FullName
    $OrphanedAdmins = Import-Csv -Path $Orphans | select Name,UserName,Enabled,LastLogonDate | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Name','UserName','Enabled','LastLogonDate' `
                            -PostContent 'These accounts once were a member of a privileged group. Chnages made to members of AD privileged groups are not undone when group membership is removed. Manual cleanup of these changes should be performed.<br /><br />' `
                            -PreContent '<h2>Orphaned Admin Accounts</h2>' | Out-String
}
else
{
    $Orphans = [pscustomobject]@{Name='';UserName='';Enabled='';LastLogonDate=''}
    $OrphanedAdmins = $Orphans | select Name,UserName,Enabled,LastLogonDate | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Name','UserName','Enabled','LastLogonDate' `
                            -PostContent 'These accounts once were a member of a privileged group. Chnages made to members of AD privileged groups are not undone when group membership is removed. Manual cleanup of these changes should be performed.<br /><br />' `
                            -PreContent '<h2>Orphaned Admin Accounts</h2>' | Out-String
}
#endregion

#region Admin Account Separation

if((Get-ChildItem -Path "$Path\findings" -Filter Priv_AcctSep*).length -gt '0')
{
    $Sep = (Get-ChildItem -Path "$Path\findings" -Filter Priv_AcctSep*).FullName
    $SingleAccountAdmins = Import-Csv -Path $Sep | select "Name","SamAccountName","Enabled","Description" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SamAccountName","Enabled","Description" `
                            -PostContent 'Maintaining separate administrative credentials is crucial to prevent credential theft. When privileged accounts are used to for user productivity tasks such as checking email, browsing the internet, and downloading content, they expose the entire forest to compromise.<br /><br />' `
                            -PreContent '<h2>Admin and User Account Separation</h2>' | Out-String
}
else
{
    $Sep = [pscustomobject]@{Name='';SamAccountName='';Enabled='';Description=''}
    $SingleAccountAdmins = $Sep | select "Name","SamAccountName","Enabled","Description" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SamAccountName","Enabled","Description" `
                            -PostContent 'Maintaining separate administrative credentials is crucial to prevent credential theft. When privileged accounts are used to for user productivity tasks such as checking email, browsing the internet, and downloading content, they expose the entire forest to compromise.<br /><br />' `
                            -PreContent '<h2>Admin and User Account Separation</h2>' | Out-String
}
#endregion

#region Passwords Common Properties
if((Get-ChildItem -Path "$Path\findings" -Filter Ac_PwCommonProp*).length -gt '0')
{
    $PwCommonPropFile = (Get-ChildItem -Path "$Path\findings" -Filter Ac_PwCommonProp*).FullName
    $PwCommonProp = Import-Csv -Path $PwCommonPropFile | select "Name","SamAccountName","PossiblePassword" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SamAccountName","PossiblePassword" `
                            -PostContent 'These accounts are suspected to have their password listed in common account Properties.<br /><br />' `
                            -PreContent '<h2>Passwords in Common User Properties</h2>' | Out-String
}
else
{
    $PwCommonPropFile = [pscustomobject]@{Name='';SamAccountName='';PossiblePassword=''}
    $PwCommonProp = $PwCommonPropFile | select "Name","SamAccountName","PossiblePassword" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SamAccountName","PossiblePassword" `
                            -PostContent 'These accounts are suspected to have their password listed in common account Properties.<br /><br />' `
                            -PreContent '<h2>Passwords in Common User Properties</h2>' | Out-String
}
#endregion

#region Short Lived Admin Accounts

if((Get-ChildItem -Path "$Path" -Filter Priv_Short*).length -gt '0')
{
    #$Added = (Get-ChildItem -Path "$Path" -Filter RecentlyAdded*).FullName
    $ShortAdmins = Import-Csv -Path (Get-ChildItem -Path "$Path" -Filter Priv_Short*).FullName | Where-Object Comment -eq 'Warning! Potential malicious activity.' | select "Account","Group","TimeAdded","TimeRemoved","TimeSpan","Comment" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Account","Group","TimeAdded","TimeRemoved","TimeSpan","Comment" `
                            -PostContent 'Accounts that had membership in a privileged group for a short period of time. This could be indication of malicious activity.<br /><br />' `
                            -PreContent '<h2>Short-Lived Admin Accounts</h2>' | Out-String
}
else
{
    $Short = [pscustomobject]@{Account='';Group='';TimeAddes='';TimeRemoved='';TimeSpan='';Comment=''}
    $ShortAdmins = $Short | select "Account","Group","TimeAdded","TimeRemoved","TimeSpan","Comment" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Account","Group","TimeAdded","TimeRemoved","TimeSpan","Comment" `
                            -PostContent 'Accounts that had membership in a privileged group for a short period of time. This could be indication of malicious activity.<br /><br />' `
                            -PreContent '<h2>Short-Lived Admin Accounts</h2>' | Out-String
}
#endregion

#region Recently Added Admin Accounts
            
if((Get-ChildItem -Path "$Path" -Filter RecentlyAdded*).length -gt '0')
{
    $Added = (Get-ChildItem -Path "$Path" -Filter RecentlyAdded*).FullName
    $AddedAdmins = Import-Csv -Path $Added | select GroupName,TimeAdded,Account | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'GroupName','TimeAdded','Account' `
                            -PostContent 'Accounts that have been added to a privileged group in the past 180 days.<br /><br />' `
                            -PreContent '<h2>Recently Added Admin Accounts</h2>' | Out-String
}
else
{
    $Added = [pscustomobject]@{GroupName='';TimeAdded='';Account=''}
    $AddedAdmins = $Added | select GroupName,TimeAdded,Account | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'GroupName','TimeAdded','Account' `
                            -PostContent 'Accounts that have been added to a privileged group in the past 180 days.<br /><br />' `
                            -PreContent '<h2>Recently Added Admin Accounts</h2>' | Out-String
}
#endregion

#region Recently Removed Admin Accounts
            
if((Get-ChildItem -Path "$Path" -Filter RecentlyRemoved*).length -gt '0')
{
    $Removed = (Get-ChildItem -Path "$Path" -Filter RecentlyRemoved*).FullName
    $RemovedAdmins = Import-Csv -Path $Removed | select GroupName,TimeDeleted,Account | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'GroupName','TimeDeleted','Account' `
                            -PostContent 'Accounts that have been removed from a privileged group in the past 180 days.<br /><br />' `
                            -PreContent '<h2>Recently Removed Admin Accounts</h2>' | Out-String
}
else
{
    $Removed = [pscustomobject]@{GroupName='';TimeDeleted='';Account=''}
    $RemovedAdmins = $Removed | select GroupName,TimeDeleted,Account | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'GroupName','TimeDeleted','Account' `
                            -PostContent 'Accounts that have been removed from a privileged group in the past 180 days.<br /><br />' `
                            -PreContent '<h2>Recently Removed Admin Accounts</h2>' | Out-String
}
#endregion

#region Kerberos Delegation
if((Get-ChildItem -Path "$Path\findings" -Filter C_FullDelegation*).length -gt '0' )
{
    $FullDelegation = (Get-ChildItem -Path "$Path\findings" -Filter C_FullDelegation*).FullName
    $FullDelegation_frag = Import-Csv -Path $FullDelegation | select "samaccountname","objectClass","fullDelegation","constrainedDelegation","resourceDelegation","AllowedProtocols" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "samaccountname","objectClass","fullDelegation","constrainedDelegation","resourceDelegation","AllowedProtocols" `
                            -PostContent 'When unconstrained delegation is configured, the Kerberos ticket TGT can be captured. This TGT grants access to any service the user has access to.<br /><br />' `
                            -PreContent '<h2>Kerberos Delegation</h2>' | Out-String
}
else
{
    $FullDelegation = [pscustomobject]@{SamAccountName='';ObjectClass='';FullDelegation='';ConstrainedDelegation='';ResourceDelegation='';AllowedProtocols=''}
    $FullDelegation_frag = $FullDelegation | select "samaccountname","objectClass","fullDelegation","constrainedDelegation","resourceDelegation","AllowedProtocols" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "samaccountname","objectClass","fullDelegation","constrainedDelegation","resourceDelegation","AllowedProtocols" `
                            -PostContent 'When unconstrained delegation is configured, the Kerberos ticket TGT can be captured. This TGT grants access to any service the user has access to.<br /><br />' `
                            -PreContent '<h2>Kerberos Delegation</h2>' | Out-String
}
            
#endregion

#region Hidden Users

if((Get-ChildItem -Path "$Path" -Filter ADHiddenUser*).length -gt '0' )
{
    $hidden = (Get-ChildItem -Path "$Path" -Filter ADHiddenUser*).FullName
    $hidden_frag = Import-Csv -Path $hidden | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "UserObject","Message" `
                            -PostContent 'A hidden account has been detected. This could be an indication of malicious activity.<br /><br />' `
                            -PreContent '<h2>Hidden User Accounts</h2>' | Out-String
}
else
{
    $hidden = [pscustomobject]@{UserObject='';Message=''}
    $hidden_frag = $hidden | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "UserObject","Message" `
                            -PostContent 'A hidden account has been detected. This could be an indication of malicious activity.<br /><br />' `
                            -PreContent '<h2>Hidden User Accounts</h2>' | Out-String
}
#endregion

#region Primary Group ID
if((Get-ChildItem -Path "$Path\findings" -Filter Ac_PrimaryGroupId*).length -gt '0' )
{
    $PrimaryGroupId_File = (Get-ChildItem -Path "$Path\findings" -Filter Ac_PrimaryGroupId*).FullName
    $PrimaryGroupId_frag = Import-Csv -Path $PrimaryGroupId_File | select "Name","SAMAccountname","Enabled","PrimaryGroupID" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PrimaryGroupID" `
                            -PostContent 'By default, all Active Directory users have a Primary Group ID of 513, which is associated with the Domain Users group. Some attacks, such as DCShadow can alter the Primary Group ID attribute for a user to a privileged group even thoguh they are not in that group. This attack does not create event logs and is steathly, persistent, and difficult to detect.<br /><br />' `
                            -PreContent '<h2>Primary Group ID</h2>' | Out-String
}
else
{
    $PrimaryGroupId_File = [pscustomobject]@{Name='';SamAccountName='';Enabled='';PrimaryGroupID=''}
    $PrimaryGroupId_frag = $PrimaryGroupId_File | select "Name","SAMAccountname","Enabled","PrimaryGroupID" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PrimaryGroupID" `
                            -PostContent 'By default, all Active Directory users have a Primary Group ID of 513, which is associated with the Domain Users group. Some attacks, such as DCShadow can alter the Primary Group ID attribute for a user to a privileged group even thoguh they are not in that group. This attack does not create event logs and is steathly, persistent, and difficult to detect.<br /><br />' `
                            -PreContent '<h2>Primary Group ID</h2>' | Out-String
    
}


#endregion

#region Blank Passwords

if(Get-ChildItem -Path $path -Filter ADBlank*)
{
    $BlankPw = (Get-ChildItem -Path $path -Filter ADBlank*).FullName

    $BlankPw_frag = ipcsv $BlankPw | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "UserName","HasBlankPassword" `
                            -PostContent 'The following accounts have the Password Not Required flag set. This configuration allows a blank password to be set.<br /><br />' `
                            -PreContent '<h2>Accounts With Blank Passwords</h2>' | Out-String
}
else
{
    $BlankPw = [pscustomobject]@{UserName='';HasBlankPassword=''}

    $BlankPw_frag = ipcsv $BlankPw | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "UserName","HasBlankPassword" `
                            -PostContent 'The following accounts have the Password Not Required flag set. This configuration allows a blank password to be set.<br /><br />' `
                            -PreContent '<h2>Accounts With Blank Passwords</h2>' | Out-String

}
#endregion

$t2 = @"
<div class="tab content2">

<h1>Privileged Account Report - $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString())</p> 
<br>Active Directory administrtion is typically performed by a small number of people. The number of privileged accounts typically exeeds the number of actual AD admins. Domain Admins members have FULL administrative rights to all workstations, servers, domain controllers, Active Directory, Group Policy, etc. by default. This is too much power for any one account in today's modern enterprise.
<br /><br />
<br>
$GroupCount
<br><br>
$PrivMembers
<br><br>
$Administrators
<br><br>
$DAMembers
<br><br>
$EnterpriseAdmins
<br><br>
$SchemaAdmins
<br><br>
$Operators
<br><br>
$DnsAdmins_frag
<br>
$PreWin2k_frag
<br>
$PrivPwdNotReq_frag
<br>
$Members
<br>
$GPCO
<br>
$IFTB
<br><br>
$PrivAcctSPN
<br><br>
$PrivOwner_frag
<br><br>
$RC4KFrag
<br>
$OrphanedAdmins
<br><br>
$SingleAccountAdmins
<br><br>
$ShortAdmins
<br><br>
$AddedAdmins
<br><br>
$RemovedAdmins
<br><br>
$FullDelegation_frag
<br><br>
<h1>User Accounts</h1>
<br>
$BlankPw_frag
<br><br>
$PrimaryGroupId_frag
<br>
$PwCommonProp
<br>
$PwdNotReq_frag
<br>

<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 3 Service Accounts

#region Privileged Service Accounts

if((Get-ChildItem -Path "$Path\findings" -Filter Priv_ServiceAccounts*).length -gt '0')
{
    $PSvc = (Get-ChildItem -Path "$Path\findings" -Filter Priv_ServiceAccounts* ).FullName
    $PSvcAccounts_frag = Import-Csv -Path $PSvc | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","AdminCount","PasswordNeverExpires","SPN" `
                            -PostContent "It is critical to ensure that every Service Account is delegated only the rights required and nothing more. The additional privileges provided to these service accounts can be used maliciously to escalate rights on a network. An attempt was made to discover which accounts are service accounts, as a result this list may not be complete.<br /><br />" `
                            -PreContent '<h2>Over-Privileged Service Accounts</h2>' | Out-String
}
else
{
    $PSvc = [pscustomobject]@{Name='';SamAccountName='';Enabled='';AdminCount='';PasswordNeverExpires='';SPN=''}
    $PSvcAccounts_frag = $PSvc | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","AdminCount","PasswordNeverExpires","SPN" `
                            -PostContent "It is critical to ensure that every Service Account is delegated only the rights required and nothing more. The additional privileges provided to these service accounts can be used maliciously to escalate rights on a network. An attempt was made to discover which accounts are service accounts, as a result this list may not be complete.<br /><br />" `
                            -PreContent '<h2>Over-Privileged Service Accounts</h2>' | Out-String
}
            
#endregion

#region Enabled Non-Privileged Service Accounts

if((Get-ChildItem -Path "$Path\findings" -Filter NonPriv_ServiceAccounts*).length -gt '0')
{
    $Svc = (Get-ChildItem -Path "$Path\findings" -Filter NonPriv_ServiceAccounts* ).FullName
    $ESvcAccounts_frag = Import-Csv -Path $Svc | Where Enabled -eq 'True' | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PasswordNeverExpires","SPN" `
                            -PostContent "It is critical to ensure that every Service Account is delegated only the rights required and nothing more. The additional privileges provided to these service accounts can be used maliciously to escalate rights on a network. An attempt was made to discover which accounts are service accounts, as a result this list may not be complete.<br /><br />" `
                            -PreContent '<h2>Enabled Non-Privileged Service Accounts</h2>' | Out-String
}
else
{
    $Svc = [pscustomobject]@{Name='';SamAccountName='';Enabled='';PasswordNeverExpires='';PasswordNotRequired='';ServicePrincipalName=''}
    $ESvcAccounts_frag = $Svc | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PasswordNeverExpires","SPN" `
                            -PostContent "It is critical to ensure that every Service Account is delegated only the rights required and nothing more. The additional privileges provided to these service accounts can be used maliciously to escalate rights on a network. An attempt was made to discover which accounts are service accounts, as a result this list may not be complete.<br /><br />" `
                            -PreContent '<h2>Enabled Non-Privileged Service Accounts</h2>' | Out-String
}
            
#endregion

#region Disabled Non-Privileged Service Accounts

if((Get-ChildItem -Path "$Path\findings" -Filter NonPriv_ServiceAccounts*).length -gt '0')
{
    $Svc = (Get-ChildItem -Path "$Path\findings" -Filter NonPriv_ServiceAccounts* ).FullName
    $DSvcAccounts_frag = Import-Csv -Path $Svc | Where Enabled -eq 'False' | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PasswordNeverExpires","SPN" `
                            -PostContent "It is critical to ensure that every Service Account is delegated only the rights required and nothing more. The additional privileges provided to these service accounts can be used maliciously to escalate rights on a network. An attempt was made to discover which accounts are service accounts, as a result this list may not be complete.<br /><br />" `
                            -PreContent '<h2>Disabled Non-Privileged Service Accounts</h2>' | Out-String
}
else
{
    $Svc = [pscustomobject]@{Name='';SamAccountName='';Enabled='';PasswordNeverExpires='';PasswordNotRequired='';ServicePrincipalName=''}
    $DSvcAccounts_frag = $Svc | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","SAMAccountname","Enabled","PasswordNeverExpires","SPN" `
                            -PostContent "It is critical to ensure that every Service Account is delegated only the rights required and nothing more. The additional privileges provided to these service accounts can be used maliciously to escalate rights on a network. An attempt was made to discover which accounts are service accounts, as a result this list may not be complete.<br /><br />" `
                            -PreContent '<h2>Disabled Non-Privileged Service Accounts</h2>' | Out-String
}
            
#endregion

#region Service Account Password Info

if((Get-ChildItem -Path "$Path" -Filter ServiceAccountPasswordInfo*).length -gt '0')
{
    $SvcPwd = (Get-ChildItem -Path $Path -Filter ServiceAccountPasswordInfo*).FullName
    $SvcPwd_frag = Import-Csv -Path $SvcPwd | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "SamAccountName","LastLogonDate","PasswordAgeYears","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired","PasswordExpired","AdminCount" `
                            -PostContent "Passwords for accounts with an SPN are vulnerable to discovery through Kerberoasting. Since service account passwords rarely change, it is important to know the password age. What was the password policy at the time it was set? What OS version were the domain controllers at that time? Could these accounts have a weak password? Are they stored with LMHash encryption?<br /><br />" `
                            -PreContent '<h2>Service Account Passwords</h2>' | Out-String
}
else
{
    $SvcPwd = [pscustomobject]@{SamAccountName='';LastLogonDate='';PasswordAgeYears='';PasswordLastSet='';PasswordNeverExpires='';PasswordNotRequired='';PasswordExpired='';AdminCount=''}
    $SvcPwd_frag = $SvcPwd | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "SamAccountName","LastLogonDate","PasswordAgeYears","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired","PasswordExpired","AdminCount" `
                            -PostContent "Passwords for accounts with an SPN are vulnerable to discovery through Kerberoasting. Since service account passwords rarely change, it is important to know the password age. What was the password policy at the time it was set? What OS version were the domain controllers at that time? Could these accounts have a weak password? Are they stored with LMHash encryption?<br /><br />" `
                            -PreContent '<h2>Service Account Passwords</h2>' | Out-String
}

#endregion

#region MSOL Account Info

if((Get-ChildItem -Path "$path" -Filter MsolAccountInfo*).Length -gt '0')
{
    $msol = Import-Csv (Get-ChildItem "$path" -Filter MsolAccountInfo*).FullName

    if($msol.account -notlike "*not found")
    {
        $msol_frag = $msol | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "AccountName","Created","Computer","Tenant" `
                                            -PostContent 'Azure AD Connect installs an on-premises service which orchestrates synchronization between Active Directory and Azure Active Directory.<br /><br />'`
                                            -PreContent '<h2>Azure AD Connect Service Account</h2>' | Out-String
    }
}

#endregion


$t3 = @"
<div class="tab content3">

<h1>Service Account Report - $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString())</p> 
<br>Active Directory administrtion is typically performed by a small number of people. The number of privileged accounts typically exeeds the number of actual AD admins. Domain Admins members have FULL administrative rights to all workstations, servers, domain controllers, Active Directory, Group Policy, etc. by default. This is too much power for any one account in today's modern enterprise.
<br /><br />
<br>
$PSvcAccounts_frag
<br><br>
$ESvcAccounts_frag
<br><br>
$DSvcAccounts_frag
<br><br>
$SvcPwd_frag
<br><br>
$msol_frag

<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 4 Content: Active Directory

#region AD Summary

$Summary = ipcsv -Path (Get-ChildItem -Path "$path" -Filter ADDomainReport*).FullName
$Summary_frag = $Summary | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass GRMEMTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As List `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "NetBIOSName","DNSRoot","WhenCreated","DCCount","GlobalCatalogCount","ForestMode","DomainMode","MachineAccountQuota","RIDsIssued","RIDsRemaining","PercentRIDsIssued","SiteCount","IsEmptySite","EmptySiteCount","ADRecycleBin","TombstoneLifetime","ADBackupDate","ADBackupAge" `
                            -PreContent '<h2>Domain Summary</h2>' | Out-String
#endregion

#region Sites and Stats Report

if(Test-Path -Path $Path\AD_SitesNStats-$Domain.csv)
{
    $SitesNStats = ipcsv -Path (Get-ChildItem -Path $path -Filter AD_SitesNStats*).FullName -ErrorAction SilentlyContinue

    $SitesNStats_frag = $SitesNStats | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass DCTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "SiteName","LinkCount","SubnetCount","DCCount","IsEmpty","WhenCreated","Description" `
                                -PostContent ''`
                                -PreContent '<h2>AD Sites and Stats</h2>' | Out-String
}
else
{
    $SitesNStats = [pscustomobject]@{SiteName='';LinkCount='';SubnetCount='';DCCount='';IsEmpty='';WhenCreated='';Description=''}

    $SitesNStats_frag = $SitesNStats | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass DCTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "SiteName","LinkCount","SubnetCount","DCCount","IsEmpty","WhenCreated","Description" `
                                -PostContent ''`
                                -PreContent '<h2>AD Sites and Stats</h2>' | Out-String
}

#endregion

#region Site Links

if(Test-Path -Path $path\ADSiteLinks-$Domain.csv)
{
    $SiteLinks = ipcsv -Path (Get-ChildItem -Path $path\ADSiteLinks-$Domain.csv).FullName -ErrorAction SilentlyContinue

    $SiteLinks_frag = $SiteLinks | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass DCTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","SiteCount","Cost","ReplInterval","Schedule","Options","SitesIncluded" `
                                -PostContent ''`
                                -PreContent '<h2>AD Site Links</h2>' | Out-String
}
else
{
    $SiteLinks = [pscustomobject]@{Name='';SiteCount='';Cost='';ReplInterval='';Schedule='';Options='';SitesIncluded=''}

    $SiteLinks_frag = $SiteLinks | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass DCTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","SiteCount","Cost","ReplInterval","Schedule","Options","SitesIncluded" `
                                -PostContent ''`
                                -PreContent '<h2>AD Site Links</h2>' | Out-String

}

#endregion
            
#region Password Policy

$PwPol = ipcsv -Path (Get-ChildItem -Path "$path" -Filter PasswordPolicy*).FullName 

$PwPol_frag = $PwPol | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass GRMEMTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As List `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "PolicyType","DistinguishedName","MinPasswordAge","MaxPasswordAge","MinPasswordLength","PasswordHistoryCount","PassworddProperties","LockoutDuration","LockoutObservationWindow","LockoutThreshold" `
                            -PostContent ''`
                            -PreContent '<h2>Default Domain Password Policy</h2>' | Out-String
#endregion

#region Fine-Grained Password Policy

if((Get-ChildItem -Path "$path" -Filter ADFineGrainedPass*).length -gt 0)
{
    $FGPP = ipcsv -Path (Get-ChildItem -Path "$path" -Filter ADFineGrainedPass*).FullName 

    $FGPP_frag = $FGPP | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As List `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","Precedence","AppliesTo","MinPasswordAge","MaxPasswordAge","MinPasswordLength","PasswordHistoryCount","ReversibleEncryptionEnabled","ComplexityEnabled","LockoutDuration","LockoutObservation","LocoutThreshold" `
                                -PostContent ''`
                                -PreContent '<h2>Fine-Grained Password Policies</h2>' | Out-String
}
else
{
    $FGPP = [pscustomobject]@{Name='';Precedence='';AppliedTo='';MinPasswordAge='';MaxPasswordAge='';MinPasswordLength='';PasswordHistoryCount='';ReversibleEncryption='';ComplexityEnabled='';LockoutDuration='';LockoutObservation='';LockoutThreshold=''}

    $FGPP_frag = $FGPP | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As List `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","Precedence","AppliesTo","MinPasswordAge","MaxPasswordAge","MinPasswordLength","PasswordHistoryCount","ReversibleEncryptionEnabled","ComplexityEnabled","LockoutDuration","LockoutObservation","LocoutThreshold" `
                                -PostContent ''`
                                -PreContent '<h2>Fine-Grained Password Policies</h2>' | Out-String
}
#endregion

#region GPOs with Password Policy
    
if((Get-ChildItem -Path "$path" -Filter GP_GPOWithPwdPolicy*).length -gt '0')
{
    $GPOPwdPol_frag = ipcsv -Path (Get-ChildItem -Path $Path -Filter GP_GPOWithPwdPolicy*).FullName | `
    ConvertTo-EnhancedHTMLFragment -TableCssID GPOPERMTABLE `
                            -TableCssClass GPOPERMTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "GPO","ContainsPasswordPolicy","LinkCount","LinksTo" `
                            -PostContent 'The policy with the highest link in the domain sets the password policy. If multiple password policies are needed, fine-grained password polices should be used.<br /><br />'`
                            -PreContent '<h2>GPO with Password Policy</h2>' | Out-String
                            
}
else
{
    $GPOPwdpol = [pscustomobject]@{GPO='';ContainsPasswordPolicy='';LinkCount='';LinksTo=''}
    $GPOPwdPol_frag = $GPOPwdpol | `
    ConvertTo-EnhancedHTMLFragment -TableCssID GPOPERMTABLE `
                            -TableCssClass GPOPERMTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "PolicyName","Trustee","PermissionType","ACLs" `
                            -PostContent 'The policy with the highest link in the domain sets the password policy. If multiple password policies are needed, fine-grained password polices should be used.<br /><br />'`
                            -PreContent '<h2>GPO with Password Policy</h2>' | Out-String
}
    
#endregion

#region Dns Zone Security

if(Get-ChildItem -Path "$path\Findings" -Filter Dns_ZoneSec*)
{
    $DnsZone = ipcsv -Path (Get-ChildItem -Path "$path\Findings" -Filter Dns_ZoneSec*).FullName 

    $DnsZone_frag = $DnsZone | select "ZoneName","Type","IsDsIntegrated","IsReverseLookup","DynamicUpdate" | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass DCTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "ZoneName","Type","IsDsIntegrated","IsReverseLookup","DynamicUpdate" `
                                -PostContent ''`
                                -PreContent '<h2>Dns Zone Security</h2>' | Out-String
}
else
{
    $DnsZone = [pscustomobject]@{ZoneName='';Type='';IsDsIntegrated='';IsReverseLookup='';DynamicUpdate=''}

    $DnsZone_frag = $DnsZone | select "ZoneName","Type","IsDsIntegrated","IsReverseLookup","DynamicUpdate" | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass DCTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "ZoneName","Type","IsDsIntegrated","IsReverseLookup","DynamicUpdate" `
                                -PostContent ''`
                                -PreContent '<h2>Dns Zone Security</h2>' | Out-String
}

#endregion

#region Dns Aging and Scavenging

$DnsScav = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DnsAgingScav*).FullName 

$DnsScav_Frag = $DnsScav | select "Name","ScavengingInterval" | ConvertTo-EnhancedHTMLFragment -TableCssID SCAVTABLE `
                            -TableCssClass SCAVTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","ScavengingInterval" `
                            -PostContent 'Dns Scavenging is the process of cleaning up stale Dns records. This is used in conjunction with Dns Aging to determine when records are stale and no longer needed.<br /><br /> '`
                            -PreContent '<h2>Dns Aging and Scavenging</h2>' | Out-String

#endregion

#region Domain Computer Report

$CompReport = ipcsv -Path (Get-ChildItem -Path "$path" -Filter ADComputerReport*).FullName

$CompReport_Frag = $CompReport | select "OperatingSystem","TotalCount","Enabled","Stale" | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass COMPREPFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "OperatingSystem","TotalCount","Enabled","Stale" `
                            -PostContent 'By default, computers reset their password every 30 days. Computers that have not reset their password in 90 days are considered stale.<br /><br /> '`
                            -PreContent '<h2>Domain Computer Report</h2>' | Out-String
#endregion

#region Duplicate SPNs

$DupSPN = (Get-ChildItem -Path "$path\findings" -Filter AD_DupSpn*).FullName 
if($DupSPN -ne $null)
{
    $DupSPN_frag = ipcsv -Path $DupSPN | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Account","SPN" `
                                -PostContent 'The Kerberos Service Principal Name (SPN) connects a service on a server supporting Kerberos authentication with the service account. When there are duplicate SPNs, Kerberos authentication breaks since a domain controller cannot identify a single account associated with the SPN. Authentication will need to fallback to NTLM authentication.<br /><br />'`
                                -PreContent '<h2>Duplicate SPNs</h2>' | Out-String
}
else
{
    $DupSPN = [pscustomobject]@{Account='';SPN=''}
    $DupSPN_frag = $DupSPN | select "SPN","Accounts" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Account","SPN" `
                            -PostContent "The Kerberos Service Principal Name (SPN) connects a service on a server supporting Kerberos authentication with the service account. When there are duplicate SPNs, Kerberos authentication breaks since a domain controller cannot identify a single account associated with the SPN. Authentication will need to fallback to NTLM authentication.<br /><br />" `
                            -PreContent '<h2>Duplicate SPNs</h2>' | Out-String
}
#endregion

#region AdminSDHolder Acls

if((Get-ChildItem -Path "$path\findings" -Filter AD_AdminSDHolderAclsAdditional*).Length -gt '0')
{
    $AdminSDHolderFile = Import-Csv (Get-ChildItem -Path "$path\findings" -Filter AD_AdminSDHolderAclsAdditional*).FullName

    $AdminSDHolderFrag = $AdminSDHolderFile | sort Identity | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "Identity","Access","Rights" `
                                            -PostContent ''`
                                            -PreContent '<h2>AdminSDHolder Permissions</h2>' | Out-String

}

#endregion

#region MAQ Computers

if((Get-ChildItem -Path "$path" -Filter MAQComputers*).Length -gt '0')
{
    $MAQFile = Import-Csv (Get-ChildItem -Path "$path" -Filter MAQComputers*).FullName

    $MAQFrag = $MAQFile | sort User | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "Name","Created","User" `
                                            -PostContent 'By default users are granted the right to create up to ten computers in the domain. Creating computers accounts should be handled by administrators or accounts delegated this right.<br /><br />'`
                                            -PreContent '<h2>Machine Account Quota Joined Computers</h2>' | Out-String

}
else
{
    $MAQFile = [pscustomobject]@{Name='';Created='';User=''}

    $MAQFrag = $MAQFile | sort User | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "Name","Created","User" `
                                            -PostContent 'By default users are granted the right to create up to ten computers in the domain. Creating computers accounts should be handled by administrators or accounts delegated this right.<br /><br />'`
                                            -PreContent '<h2>Machine Account Quota Joined Computers</h2>' | Out-String

}


#endregion

#region Manual Replication Connection

if((Get-ChildItem -Path "$path\findings" -Filter R_ManualRepConnection*).Length -gt '0')
{
    $ManualRep = Import-Csv (Get-ChildItem -Path "$path\findings" -Filter R_ManualRepConnection*).FullName

    $ManualRep_Frag = $ManualRep | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "DN","Name","Options" `
                                            -PostContent 'Manually configured replication connection objects can be problematic because they can result in replication failures and inconsistencies in Active Directory. When a connection object is manually configured it bypasses the KCC (Knowledge Consistency Checker) which his responsible for creating and maintaining a topology of domain controllers that ensures that replication occurs efficiently and reliably.<br /><br />'`
                                            -PreContent '<h2>Manual Replication Connection Objects</h2>' | Out-String
}
else
{
    $ManualRep = [pscustomobject]@{DN='';Name='';Options=''}

    $ManualRep_Frag = $ManualRep | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "DN","Name","Options" `
                                            -PostContent 'Manually configured replication connection objects can be problematic because they can result in replication failures and inconsistencies in Active Directory. When a connection object is manually configured it bypasses the KCC (Knowledge Consistency Checker) which his responsible for creating and maintaining a topology of domain controllers that ensures that replication occurs efficiently and reliably.<br /><br />'`
                                            -PreContent '<h2>Manual Replication Connection Objects</h2>' | Out-String
}

#endregion

$t4 = @"
<div class="tab content4">

<h1>Active Directory Forest and Domain - $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString())</p> 
<br>Active Directory is the security center of Microsoft's information system. It is a critical element for the centralized management of accounts, resources, and permissions. Obtaining high-level privileges in this directory can result in an instantaneous and complete takeover of the forest.
<br><br>Analysis of recent attacks reveals an increase in Active Directory targeting, given its role as the cornerstone of most information systems. An attacker who has obtained privileged rights in the directory can then deploy malicious software to the entire information system, especially by GPO or by using direct connections(WinRM, psexec, wmiexec). The lack of directory security endangers information systems as a whole and places a systemic risk on organizations.
<br /><br />

$Summary_frag
<br>
$SitesNStats_frag
<br>
$SiteLinks_frag
<br>
$PwPol_frag
<br>
$FGPP_frag
<br>
$GPOPwdPol_frag
<br>
$CompReport_Frag
<br>
$DupSPN_frag
<br>
$AdminSDHolderFrag
<br /><br />
$MAQFrag
<br>
$ManualRep_Frag
<br>
<h1>DNS</h1>
<br>
$DnsZone_frag
<br>
$DnsScav_Frag

<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 5 Content: Domain Controllers
            
#region Domain Controllers

$DCs = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainControllerReport*).FullName 

$DCs_frag = $DCs | select "Name","Domain","Site","Ipv4Address","OS","Enabled","GC","RODC",@{l='PDC';e={$_.PDCEmulator}},@{l='RID';e={$_.RIDMaster}},@{l='Inf';e={$_.InfrastructureMaster}},@{l='DNMaster';e={$_.DomainNamingMaster}},@{l='Schema';e={$_.SchemaMaster}} | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass DCTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Name","Domain","Site","Ipv4Address","OS","Enabled","GC","RODC","PDC","RID","Inf","DNMaster","Schema" `
                            -PostContent ''`
                            -PreContent '<h2>Domain Controllers</h2>' | Out-String
#endregion

#region Domain Controller Time Source

$DCTime = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainControllerTimeSource*).FullName 

$DCTime_Frag = $DCTime | select "DomainController","TimeSource" | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass DCTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "DomainController","TimeSource" `
                            -PostContent ''`
                            -PreContent '<h2>Domain Controller Time Source</h2>' | Out-String
#endregion

#region Domain Controller Installed Applications

$DCs = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainController_InstalledAp*).FullName | Group PSComputerName

foreach($dc in $DCs)
{
    $DCApps_Frag += ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainController_InstalledAp*).FullName | Where PSComputername -eq $dc.name | sort Publisher | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass DCTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "PSComputerName","Name","Publisher" `
                            -PostContent ''`
                            -PreContent "<h2>$($dc.name) - Installed Applications</h2>" | Out-String
    $DCApps_Frag += '</br></br>'
}
#endregion

#region Domain Computer Report

$CompReport = ipcsv -Path (Get-ChildItem -Path "$path" -Filter ADComputerReport*).FullName

$CompReport_Frag = $CompReport | select "OperatingSystem","TotalCount","Enabled","Stale" | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass COMPREPFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "OperatingSystem","TotalCount","Enabled","Stale" `
                            -PostContent 'By default, computers reset their password every 30 days. Computers that have not reset their password in 90 days are considered stale.<br /><br /> '`
                            -PreContent '<h2>Domain Computer Report</h2>' | Out-String
#endregion

#region Print Nightmare

$pn = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainController_PrintNightmare*).FullName 

$pn_frag = $pn | select "PSComputerName","Spooler","PatchInstalled",@{l='RestrictDriverInstall';e={$_.RestrictDriverInstallationToAdministrators}},@{l='NoWarningNoElevation';e={$_.NoWarningNoElevationOnInstall}},"UpdatePromptSettings","Expoitable","Explanation" | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass GRMEMTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "PSComputerName","Spooler","PatchInstalled","RestrictDriverInstall","NoWarningNoElevation","UpdatePromptSettings","Expoitable","Explanation" `
                            -PostContent ''`
                            -PreContent '<h2>Print Nightmare</h2>' | Out-String
#endregion

#region Audit Policy

if((Get-ChildItem -Path "$path" -Filter DomainController_AuditPol*).Length -gt '0')
{
    $auditpol = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainController_AuditPol*).FullName 

    $auditpol_frag = $auditpol | select "Policy","AuditEvents","Valid" | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass AUDITTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Policy","AuditEvents","Valid" `
                                -PostContent "To detect and mitigate an attack, the right set of events needs to be colledted. The audit policy is a compromise between too much and too few events to collect.<br /><br />"`
                                -PreContent '<h2>Audit Policy</h2>' | Out-String
    
    $auditpol_frag2 = $auditpol_frag -replace "<td>False</td>", "<td style=background-color:#ffba08>False</td>"    
}
#endregion

#region Duplicate SPNs

$DupSPN = (Get-ChildItem -Path "$path\findings" -Filter AD_DupSpn*).FullName 
if($DupSPN -ne $null)
{
    $DupSPN_frag = ipcsv -Path $DupSPN | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Account","SPN" `
                                -PostContent ''`
                                -PreContent '<h2>Duplicate SPNs</h2>' | Out-String
}
#endregion

#region DC Non-Essential Roles

if((Get-ChildItem -Path "$path\findings" -Filter DC_NonEss*).Length -gt '0')
{
    $NonEss = ipcsv -Path (Get-ChildItem -Path "$path\findings" -Filter DC_NonEss*).FullName 

    $NonEss_frag = $NonEss | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Server","Roles" `
                                -PostContent "Domain controllers should have limited software and agents installed including roles and services. Non-essential code running on domain controllers is a risk to the enterprise Active Directory environment. A domain controller should only run required software, services, and roles critical to essential operations, like DNS.<br /><br />"`
                                -PreContent '<h2>DC Non-Essential Roles</h2>' | Out-String
}
#endregion

#region DC Installed AV

if((Get-ChildItem -Path "$path" -Filter DomainController_InstalledAV*).Length -gt '0')
{
    $DCAV = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainController_InstalledAV*).FullName 

    $DCAV_frag = $DCAV | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "ComputerName","Name","Version","InstallDate" `
                                -PostContent "...<br /><br />"`
                                -PreContent '<h2>DC Installed AV/EDR</h2>' | Out-String
}
#endregion

#region NetBIOS over TCP

if((Get-ChildItem -Path "$path" -Filter DomainController_TcpNetBios*).Length -gt '0')
{
    $NetBios = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainController_TcpNetBios*).FullName 

    $NetBios_frag = $NetBios | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "ComputerName","Nic","Description","IPAddress","DhcpEnabled","NetBIOS" `
                                -PostContent "...<br /><br />"`
                                -PreContent '<h2>NetBIOS over TCP</h2>' | Out-String
}
#endregion

#region DC SMB1

$SMB1 = (Get-ChildItem -Path "$path\findings" -Filter DC_SMB*).FullName 
if($SMB1 -ne $null)
{
    $SMB1_frag = ipcsv -Path $SMB1 | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","SMB1" `
                                -PostContent ''`
                                -PreContent '<h2>SMB v1</h2>' | Out-String
}
#endregion

#region LDAP Channel Binding

if((Get-ChildItem -Path "$path" -Filter DomainController_LDAPChBinding*).Length -gt '0')
{
   $LDAPCHBN = ipcsv -Path (Get-ChildItem -Path $path -Filter DomainController_LDAPChBinding*).FullName | select "ldapenforcechannelbinding","PSComputerName"

   $LDAPCHBN_frag = $LDAPCHBN | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "PSComputerName","ldapenforcechannelbinding" `
                                -PostContent "LDAP Channel Binding helps prevent man-in-the-middle attacks by ensuring that LDAP traffic is transmitted securely over an SSL/TLS channel.<br />0 = Disabled<br />1 = Enabled when supported<br />2 = Enabled<br /><br />"`
                                -PreContent '<h2>LDAP Channel Binding</h2>' | Out-String
    
}

#endregion

#region DC User Rights Assignment

$URA = ipcsv -Path (Get-ChildItem -Path "$path" -Filter DomainController_UserRightsAssign*).FullName 

$URA_frag = $URA | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                            -TableCssClass GRMEMTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties "Policy","LinksTo","Name","Member" `
                            -PostContent "Acive Directory security effectively begins with ensuring domain controllers are configured securely. The best way to do this is to limit domain level administrative privileges. This includes limiting access to domain controllers, specifically logon administrative rights. User Rights Assignments, configred in Group Policy, define elevated rights and permissions on domain controllers.<br /><br />"`
                            -PreContent '<h2>User Rights Assignment</h2>' | Out-String
#endregion

#region Dangerous DC User Rights Assignment

if(Get-ChildItem -Path "$path\findings" -Filter DC_UserRights*)
{
    $DgUR = ipcsv -Path (Get-ChildItem -Path "$path\findings" -Filter DC_UserRights*).FullName 

    $DgUR_Frag = $DgUR | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Policy","LinksTo","Right","Member" `
                                -PostContent "Potentiall dangerous user rights assignment. Please review these findings.<br /><br />"`
                                -PreContent '<h2>Dangerous User Rights Assignment</h2>' | Out-String
}
else
{
    $DgUR = [pscustomobject]@{Policy='';LinksTo='';Right='';Member=''}

    $DgUR_Frag = $DgUR | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Policy","LinksTo","Right","Member" `
                                -PostContent "Potentiall dangerous user rights assignment. Please review these findings.<br /><br />"`
                                -PreContent '<h2>Dangerous User Rights Assignment</h2>' | Out-String

}
#endregion

#region DC Shares

if((Get-ChildItem -Path "$path\findings" -Filter DC_Shares*).Length -gt '0')
{
    $DCShares = ipcsv -Path (Get-ChildItem -Path "$path\findings" -Filter DC_Shares*).FullName 

    $DCShares_frag = $DCShares | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "PSComputerName","ShareState","Description","Name","Path" `
                                -PostContent ''`
                                -PreContent '<h2>Domain Controller Shares</h2>' | Out-String
}
#endregion

#region RDP Connections

if((Get-ChildItem -Path "$path\findings" -Filter DC_RDPCon*).Length -gt '0')
{
    $RDPCon = ipcsv -Path (Get-ChildItem -Path "$path\findings" -Filter DC_RDPCon*).FullName 

    $RDPCon_frag = $RDPCon | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "User","SourceHost","Os","IsDc" `
                                -PostContent ''`
                                -PreContent '<h2>RDP Connections</h2>' | Out-String
}
#endregion

#region AdminSDHolder Acls

if((Get-ChildItem -Path "$path\findings" -Filter AD_AdminSDHolderAclsAdditional*).Length -gt '0')
{
    $AdminSDHolderFile = Import-Csv (Get-ChildItem -Path "$path\findings" -Filter AD_AdminSDHolderAclsAdditional*).FullName

    $AdminSDHolderFrag = $AdminSDHolderFile | sort Identity | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "Identity","Access","Rights" `
                                            -PostContent ''`
                                            -PreContent '<h2>AdminSDHolder Permissions</h2>' | Out-String

}

#endregion

#region MAQ Computers

if((Get-ChildItem -Path "$path" -Filter MAQComputers*).Length -gt '0')
{
    $MAQFile = Import-Csv (Get-ChildItem -Path "$path" -Filter MAQComputers*).FullName

    $MAQFrag = $MAQFile | sort User | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "Name","Created","User" `
                                            -PostContent 'By default users are granted the right to create up to ten computers in the domain. Creating computers accounts should be handled by administrators or accounts delegated this right.<br /><br />'`
                                            -PreContent '<h2>Machine Account Quota Joined Computers</h2>' | Out-String

}


#endregion

#region Manual Replication Connection

if((Get-ChildItem -Path "$path\findings" -Filter R_ManualRepConnection*).Length -gt '0')
{
    $ManualRep = Import-Csv (Get-ChildItem -Path "$path\findings" -Filter R_ManualRepConnection*).FullName

    $ManualRep_Frag = $ManualRep | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                            -TableCssClass GRMEMTABLEFRAG `
                                            -DivCssID DIV `
                                            -DivCssClass DIV `
                                            -As Table `
                                            -MakeTableDynamic `
                                            -EvenRowCssClass 'even' `
                                            -OddRowCssClass 'odd' `
                                            -Properties "DN","Name","Options" `
                                            -PostContent 'Manually configured replication connection objects can be problematic because they can result in replication failures and inconsistencies in Active Directory. When a connection object is manually configured it bypasses the KCC (Knowledge Consistency Checker) which his responsible for creating and maintaining a topology of domain controllers that ensures that replication occurs efficiently and reliably.<br /><br />'`
                                            -PreContent '<h2>Manual Replication Connection Objects</h2>' | Out-String
}

#endregion

$t5 = @"
<div class="tab content5">

<h1>Domain Controller Configuration - $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString())</p> 
<br>Active Directory is the security center of Microsoft's information system. It is a critical element for the centralized management of accounts, resources, and permissions. Obtaining high-level privileges in this directory can result in an instantaneous and complete takeover of the forest.
<br><br>Analysis of recent attacks reveals an increase in Active Directory targeting, given its role as the cornerstone of most information systems. An attacker who has obtained privileged rights in the directory can then deploy malicious software to the entire information system, especially by GPO or by using direct connections(WinRM, psexec, wmiexec). The lack of directory security endangers information systems as a whole and places a systemic risk on organizations.
<br /><br />

$DCs_frag
<br><br>
$DCTime_Frag
<br><br>
$DCApps_Frag
<br><br>
$pn_frag
<br><br>
$auditpol_frag2
<br><br>
$NonEss_frag
<br><br>
$DCAV_frag
<br><br>
$NetBios_frag
<br><br>
$SMB1_frag
<br><br>
$LDAPCHBN_frag
<br><br>
$URA_frag
<br><br>
$DgUR_Frag
<br><br>
$DCShares_frag
<br><br>
$RDPCon_frag

<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 6 Content: ACL Report

    #region Change Password
    if((Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_Change*').length -gt '0')
    {
        $ChangePwFile = (Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_Change*').FullName
        $ChangePw = Import-Csv $ChangePwFile | select "OU","IdentityReference","ActiveDirectoryRights","InheritedObjectTypeName","ObjectTypeName","InheritanceType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "OU","IdentityReference","InheritedObjectTypeName","ObjectTypeName","InheritanceType","AccessControlType","IsInherited" `
                                -PostContent 'Rights to change account passwords.<br /><br />'`
                                -PreContent '<h2>Change Password Details</h2>' | Out-String
        
        
        $ChangePwSum = Import-Csv $ChangePwFile | Group IdentityReference | Select Name,Count | `
        ConvertTo-EnhancedHTMLFragment -TableCssID PSUMTABLE `
                                -TableCssClass PSUMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","Count" `
                                -PostContent 'Rights to change account passwords.<br /><br />'`
                                -PreContent '<h2>Change Password Summary</h2>' | Out-String

    }
    #endregion

    #region DCSync
    if((Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_DCSync*').length -gt '0')
    {
        $DCSyncFile = (Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_DCSync*').FullName
        $DCSync = Import-Csv $DCSyncFile | select "OU","IdentityReference","ActiveDirectoryRights","InheritedObjectTypeName","ObjectTypeName","InheritanceType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "OU","IdentityReference","InheritedObjectTypeName","ObjectTypeName","InheritanceType","AccessControlType","IsInherited" `
                                -PostContent 'Add description for this right.<br /><br />'`
                                -PreContent '<h2>DC Sync</h2>' | Out-String  
                                

        $DCSyncSum = Import-Csv $DCSyncFile | Group IdentityReference | Select Name,Count | `
        ConvertTo-EnhancedHTMLFragment -TableCssID PSUMTABLE `
                                -TableCssClass PSUMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","Count" `
                                -PostContent 'Add description for this right.<br /><br />'`
                                -PreContent '<h2>DC Sync Summary</h2>' | Out-String
                                                              
    }
    #endregion

    #region Generic All
    if((Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_GenericAll*').length -gt '0')
    {
        $GenericAllFile = (Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_GenericAll*').FullName
        $GenericAll = Import-Csv $GenericAllFile | select "OU","IdentityReference","ActiveDirectoryRights","InheritedObjectTypeName","ObjectTypeName","InheritanceType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "OU","IdentityReference","InheritedObjectTypeName","ObjectTypeName","InheritanceType","AccessControlType","IsInherited" `
                                -PostContent 'GenericAll is equivalent to full control. The account with GenericAll has full control permission on the object.<br /><br />'`
                                -PreContent '<h2>Generic All</h2>' | Out-String                                    
        
        $GenericAllSum = Import-Csv $GenericAllFile | Group IdentityReference | Select Name,Count | `
        ConvertTo-EnhancedHTMLFragment -TableCssID PSUMTABLE `
                                -TableCssClass PSUMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","Count" `
                                -PostContent 'GenericAll is equivalent to full control. The account with GenericAll has full control permission on the object.<br /><br />'`
                                -PreContent '<h2>Generic All Summary</h2>' | Out-String        
    }
    #endregion

    #region Generic Write
    if((Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_GenericWrite*').length -gt '0')
    {
        $GenericWriteFile = (Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_GenericWrite*').FullName
        $GenericWrite = Import-Csv $GenericWriteFile | select "OU","IdentityReference","ActiveDirectoryRights","InheritedObjectTypeName","ObjectTypeName","InheritanceType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "OU","IdentityReference","InheritedObjectTypeName","ObjectTypeName","InheritanceType","AccessControlType","IsInherited" `
                                -PostContent 'Add description for this right.<br /><br />'`
                                -PreContent '<h2>Generic Write</h2>' | Out-String                        
    
        $GenericWriteSum = Import-Csv $GenericWriteFile | Group IdentityReference | Select Name,Count | `
        ConvertTo-EnhancedHTMLFragment -TableCssID PSUMTABLE `
                                -TableCssClass PSUMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","Count" `
                                -PostContent 'Add description for this right.<br /><br />'`
                                -PreContent '<h2>Generic Write Summary</h2>' | Out-String        
    
    
    }
    #endregion

    #region Write DACL
    if((Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_WriteDacl*').length -gt '0')
    {
        $WriteDACLFile = (Get-ChildItem -Path "$path\findings" -Filter 'AD_DomainPermission_WriteDacl*').FullName
        $WriteDACL = Import-Csv $WriteDACLFile | select "OU","IdentityReference","ActiveDirectoryRights","InheritedObjectTypeName","ObjectTypeName","InheritanceType","ObjectFlags","AccessControlType","IsInherited","InheritanceFlags","PropagationFlags" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "OU","IdentityReference","InheritedObjectTypeName","ObjectTypeName","InheritanceType","AccessControlType","IsInherited" `
                                -PostContent 'Add description for this right.<br /><br />'`
                                -PreContent '<h2>Write DACL</h2>' | Out-String
    
        $WriteDACLSum = Import-Csv $WriteDACLFile | Group IdentityReference | Select Name,Count | `
        ConvertTo-EnhancedHTMLFragment -TableCssID PSUMTABLE `
                                -TableCssClass PSUMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "Name","Count" `
                                -PostContent 'Add description for this right.<br /><br />'`
                                -PreContent '<h2>Write DACL Summary</h2>' | Out-String        
    
    
    }

    #endregion

    #region Exchange ACE
    
    if((Get-ChildItem -Path "$path" -Filter 'ExchangeACE*').length -gt '0')
    {
        $ExchangeACEFile = (Get-ChildItem -Path "$path" -Filter 'ExchangeACE*').FullName
        $ExchangeACE_Frag = Import-Csv $ExchangeACEFile | select "PrimaryDN","ExchangeACE","Message" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                -TableCssClass GRMEMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "PrimaryDN","ExchangeACE","Message" `
                                -PostContent 'Add description for this right.<br /><br />'`
                                -PreContent '<h2>Exchange Domain Object DACL</h2>' | Out-String        
    }

    
    #endregion

$t6 = @"
<div class="tab content6">
<h1>Active Directory ACE Report - $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString())</p> 
<br>Active Directory is the security center of Microsoft's information system. It is a critical element for the centralized management of accounts, resources, and permissions. Obtaining high-level privileges in this directory can result in an instantaneous and complete takeover of the forest.
<br><br>Analysis of recent attacks reveals an increase in Active Directory targeting, given its role as the cornerstone of most information systems. An attacker who has obtained privileged rights in the directory can then deploy malicious software to the entire information system, especially by GPO or by using direct connections(WinRM, psexec, wmiexec). The lack of directory security endangers information systems as a whole and places a systemic risk on organizations.
<br /><br />
$ChangePwSum
<br>
$DCSyncSum
<br>
$GenericAllSum
<br>
$GenericWriteSum
<br>
$WriteDACLSum
<br><br>
$ExchangeACE_Frag
<br><br><br>
$ChangePw
<br>
$DCSync
<br>
$GenericAll
<br>
$GenericWrite
<br>
$WriteDACL

<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 7 Content: GPO Details

    #region Group Policy Settings
                                                                      
    if((Get-ChildItem -Path $path -Filter GP_Password*).Length -gt '0')
    {
        $Passwords = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_Password*).FullName 
    }

    #region NTLMv1

    if((Get-ChildItem -Path $path -Filter GPSecurity_NTLM*).Length -gt '0')
    {
        $NTLM1 = ipcsv -Path (Get-ChildItem -Path $path -Filter GPSecurity_NTLM*).FullName 

        $ntlm_frag = $NTLM1 | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'NTLM1 protocol.<br /><br />'`
                                    -PreContent '<h2>NTLM1</h2>' | Out-String
     
    }
    else
    {
        $NTLM1 = [pscustomobject]@{PolicyName = ''; LinksTo = ''; SecurityOption = ''; Value = ''; Enabled = ''}
        $ntlm_frag = $NTLM1 | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'NTLM1 protocol.<br /><br />'`
                                    -PreContent '<h2>NTLM1</h2>' | Out-String
    }

    #endregion

    #region Null session enum

    if((Get-ChildItem -Path $path -Filter GPSecurity_NullSess*).Length -gt '0')
    {
        $NullSess = ipcsv -Path (Get-ChildItem -Path $path -Filter GPSecurity_NullSess*).FullName 

        $NullSess_frag = $NullSess | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'A null session occurs when you logon to a system with no user or password. NETBIOS null sessions are a vulnerability found in the Server Message Block (SMB) protocol. Once a NETBIOS connection is made using a null session to a system, network information such as usernames, groups, shares, permissions, and more can be extracted.<br /><br />'`
                                    -PreContent '<h2>Null Session Enumeration</h2>' | Out-String
        $NullSess_frag += '<br>'
    }
    else
    {
        $NullSess = [pscustomobject]@{PolicyName = '';LinksTo = ''; SecurityOption = ''; SecurityOptionValue = ''; Value = ''; Enabled = ''}

        $NullSess_frag = $NullSess | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'A null session occurs when you logon to a system with no user or password. NETBIOS null sessions are a vulnerability found in the Server Message Block (SMB) protocol. Once a NETBIOS connection is made using a null session to a system, network information such as usernames, groups, shares, permissions, and more can be extracted.<br /><br />'`
                                    -PreContent '<h2>Null Session Enumeration</h2>' | Out-String
        $NullSess_frag += '<br>'
    }
    #endregion

    #region LLMNR

    if((Get-ChildItem -Path $path -Filter GP_LLMNR*).Length -gt '0')
    {
        $LLMNR = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_LLMNR*).FullName 

        $LLMNR_frag = $LLMNR | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","State","LinksTo","Enabled" `
                                    -PostContent 'Local Link Multicast Resolution.<br /><br />'`
                                    -PreContent '<h2>LLMNR</h2>' | Out-String
        $LLMNR_frag += '<br>'
    }
    else
    {
        $LLMNR = [pscustomobject]@{Policy='';Value='';State='';LinksTo='';Enabled=''}

        $LLMNR_frag = $LLMNR | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","State","LinksTo","Enabled" `
                                    -PostContent 'Local Link Multicast Resolution.<br /><br />'`
                                    -PreContent '<h2>LLMNR</h2>' | Out-String
        $LLMNR_frag += '<br>'
    }
    #endregion

    #region LMHash

    if((Get-ChildItem -Path $path -Filter GP_LMHash*).Length -gt '0')
    {
        $LMHash = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_LMHash*).FullName 

        $LMHash_frag = $LMHash | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'LM hash, or LAN Manager hash is a hash algorithm developed by Microsoft in Windows 3.1. Due to design flaws, hashes retrieved from the network can be reverted to clear text passwords in a matter of seconds.<br /><br />'`
                                    -PreContent '<h2>LMHash</h2>' | Out-String
        $LMHash_frag += '<br>'
    }
    else
    {
        $LMHash = [pscustomobject]@{Policy='';LinksTo='';Enabled='';Value='';Data=''}

        $LMHash_frag = $LMHash | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'LM hash, or LAN Manager hash is a hash algorithm developed by Microsoft in Windows 3.1. Due to design flaws, hashes retrieved from the network can be reverted to clear text passwords in a matter of seconds.<br /><br />'`
                                    -PreContent '<h2>LMHash</h2>' | Out-String
        $LMHash_frag += '<br>'
    }
    #endregion

    #region netcease

    if((Get-ChildItem -Path $path -Filter GP_NetCease*).Length -gt '0')
    {
        $NetCease = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_NetCease*).FullName 

        $NetCease_frag = $NetCease | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'By default, Winodws computers allow any auhtenticated resource to enumerate network sessions to it. This means that an attacker could enumerate network sessions to a file server or domain controller to see who is connected to it and determine which workstations each user and admin account is logged on to.<br /><br />Net Cease works by changing the default permissions of NetSessionEnum method to limit the number of domain users who are allowed to execute the method remotely.<br /><br />'`
                                    -PreContent '<h2>NetCease</h2>' | Out-String
        $NetCease_frag += '<br>'
    }
    else
    {
        $NetCease = [pscustomobject]@{Policy='';LinksTo='';Enabled='';Value='';Data=''}

        $NetCease_frag = $NetCease | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'By default, Winodws computers allow any auhtenticated resource to enumerate network sessions to it. This means that an attacker could enumerate network sessions to a file server or domain controller to see who is connected to it and determine which workstations each user and admin account is logged on to.<br /><br />Net Cease works by changing the default permissions of NetSessionEnum method to limit the number of domain users who are allowed to execute the method remotely.<br /><br />'`
                                    -PreContent '<h2>NetCease</h2>' | Out-String
        $NetCease_frag += '<br>'
    }
    #endregion

    #region WPAD

    if((Get-ChildItem -Path $path -Filter GP_WPAD*).Length -gt '0')
    {
        $WPad = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_WPAD*).FullName 

        $Wpad_frag = $WPad | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'If a browser is configured to automatically detect proxy settings, then it will make use of the WPAD protocol to locate and download the wpad.dat, Proxy Auto-Config (PAC) file. to find this file a query is send to DNS to find the device distributing the WPAD configuration. If DNS is not able to resolve the name, the machine will as all hosts on the network. Any host can reply, and the information will be regarded as legitimate even if incorrect.<br /><br />'`
                                    -PreContent '<h2>Windows Proxy Autodiscover (WPAD)</h2>' | Out-String
        $Wpad_frag += '<br>'
    }
    else
    {        
        $WPad = [pscustomobject]@{Policy='';LinksTo='';Enabled='';Value='';Data=''}

        $Wpad_frag = $WPad | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'If a browser is configured to automatically detect proxy settings, then it will make use of the WPAD protocol to locate and download the wpad.dat, Proxy Auto-Config (PAC) file. to find this file a query is send to DNS to find the device distributing the WPAD configuration. If DNS is not able to resolve the name, the machine will as all hosts on the network. Any host can reply, and the information will be regarded as legitimate even if incorrect.<br /><br />'`
                                    -PreContent '<h2>Windows Proxy Autodiscover (WPAD)</h2>' | Out-String
        $Wpad_frag += '<br>'

    }
    #endregion

    #region WSH

    if((Get-ChildItem -Path $path -Filter GP_WSH*).Length -gt '0')
    {
        $WSH = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_WSH*).FullName 

        $WSH_frag = $WSH | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'A common method for attackers is to embed or atach a Windows Script Host (WSH) associated file in an email or attached document for a user.<br /><br />'`
                                    -PreContent '<h2>Windows Script Host (WSH)</h2>' | Out-String
        $WSH_frag += '<br>'
    }
    else
    {
        $WSH = [pscustomobject]@{Policy='';LinksTo='';Enabled='';Value='';Data=''} 

        $WSH_frag = $WSH | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","LinksTo","Enabled","Value","Data" `
                                    -PostContent 'A common method for attackers is to embed or atach a Windows Script Host (WSH) associated file in an email or attached document for a user.<br /><br />'`
                                    -PreContent '<h2>Windows Script Host (WSH)</h2>' | Out-String
        $WSH_frag += '<br>'
    }
    #endregion

    #region WDigest

    if((Get-ChildItem -Path $path -Filter GP_WDigest*).Length -gt '0')
    {
        $WDigest = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_WDigest*).FullName 
            
        $WDigest_frag = $WDigest | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Name","State","LinksTo","Enabled" `
                                    -PostContent 'WDigest should be disabled on all endpoints. WDigest allows credential caching in LSASS, resulting in a users plaintext password being stored in memory.<br /><br />'`
                                    -PreContent '<h2>WDigest</h2>' | Out-String
        $WDigest_frag += '<br>'
    }
    else
    {
        $WDigest = [pscustomobject]@{Policy='';Name='';State='';LinksTo='';Enabled=''}
            
        $WDigest_frag = $WDigest | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Name","State","LinksTo","Enabled" `
                                    -PostContent 'WDigest should be disabled on all endpoints. WDigest allows credential caching in LSASS, resulting in a users plaintext password being stored in memory.<br /><br />'`
                                    -PreContent '<h2>WDigest</h2>' | Out-String
        $WDigest_frag += '<br>'
    }
    #endregion            

    #region Reversible Pw Encryption

    if((Get-ChildItem -Path $path -Filter GP_Reversible*).Length -gt '0')
    {
        $Reversible = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_Reversible*).FullName             

        $RevPwdEnc_Frag = $Reversible | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","DefaultUserName","Password","LinksTo","Enabled" `
                                    -PostContent 'Store passwords using reversible encryption is a policy setting that determines whether passwords are stored in a way that uses reversible encryption.<br /><br />'`
                                    -PreContent '<h2>Reversible Password Encryption</h2>' | Out-String
        $RevPwdEnc_Frag += '<br>'
    }
    else
    {
        $Reversible = [pscustomobject]@{Policy='';Value='';DefaultUserName='';Password='';LinksTo='';Enabled=''}

        $RevPwdEnc_Frag = $Reversible | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","DefaultUserName","Password","LinksTo","Enabled" `
                                    -PostContent 'Store passwords using reversible encryption is a policy setting that determines whether passwords are stored in a way that uses reversible encryption.<br /><br />'`
                                    -PreContent '<h2>Reversible Password Encryption</h2>' | Out-String
        $RevPwdEnc_Frag += '<br>'
    }
    #endregion

    #region Autologon

    if((Get-ChildItem -Path $path\findings -Filter GP_Autologon*).Length -gt '0')
    {
        $Autologon = ipcsv -Path (Get-ChildItem -Path $path\findings -Filter GP_Autologon*).FullName 
            
        $AutoLogon_Frag = $Autologon | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","DefaultUserName","Password","LinksTo","Enabled" `
                                    -PostContent 'Manually configuring autologon via the registry leaves the credentials in clear-text. The HKEY_LOCAL_MACHINE registry hive can be read by standard users which makes these password vulnerable to compromise.<br /><br />'`
                                    -PreContent '<h2>Autologon Configuration</h2>' | Out-String
        $AutoLogon_Frag += '<br>'
    }
    else
    {
        $Autologon = [pscustomobject]@{Policy='';Value='';DefaultUserName='';Password='';LinksTo='';Enabled=''}
            
        $AutoLogon_Frag = $Autologon | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","DefaultUserName","Password","LinksTo","Enabled" `
                                    -PostContent 'Manually configuring autologon via the registry leaves the credentials in clear-text. The HKEY_LOCAL_MACHINE registry hive can be read by standard users which makes these password vulnerable to compromise.<br /><br />'`
                                    -PreContent '<h2>Autologon Configuration</h2>' | Out-String
        $AutoLogon_Frag += '<br>'
    }
    #endregion

    #region SYSVOL Passwords

    if((Get-ChildItem -Path $path -Filter GP_SYSVOLP*).length -gt 0)
    {
        $SYSVOLPwd = ipcsv -Path (Get-ChildItem -Path $Path -Filter GP_SYSVOLP*).FullName            

        $SYSVOLPwd_frag = $SYSVOLPwd | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","UserName","CPassword","DecryptedPassword" `
                                    -PostContent 'Password that are exposed in Group Policy Preferences.<br /><br />'`
                                    -PreContent '<h2>SYSVOL Password</h2>' | Out-String
        $SYSVOLPwd_frag += '<br>'
    }
    else
    {
        $SYSVOLPwd = [pscustomobject]@{Policy='';UserName='';CPassword='';DecryptedPassword=''}

        $SYSVOLPwd_frag = $SYSVOLPwd | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","UserName","CPassword","DecryptedPassword" `
                                    -PostContent 'Password that are exposed in Group Policy Preferences.<br /><br />'`
                                    -PreContent '<h2>SYSVOL Password</h2>' | Out-String
        $SYSVOLPwd_frag += '<br>'
    }
    #endregion

    #region Outbound Firewall

    if(Test-Path $path -Filter GP_OB*)
    {
        if((Get-ChildItem -Path "$path" -Filter GP_OB*).length -gt 0)
        {
            $Firewall = ipcsv -Path (Get-ChildItem -Path "$path" -Filter GP_OB*).FullName 
          
            $OutboundFw_Frag = $Firewall | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                        -TableCssClass GRMEMTABLEFRAG `
                                        -DivCssID DIV `
                                        -DivCssClass DIV `
                                        -As Table `
                                        -MakeTableDynamic `
                                        -EvenRowCssClass 'even' `
                                        -OddRowCssClass 'odd' `
                                        -Properties "Policy","RuleName","App","Action","Direction","Active","DomainProfile","PublicProfile","PrivateProfile" `
                                        -PostContent 'Outbound firewall policy rules.<br /><br />'`
                                        -PreContent '<h2>Outbound Firewall Configuration</h2>' | Out-String
            $OutboundFw_Frag += '<br>'
        }
    }
    else
    {
            $Firewall = [pscustomobject]@{Policy='';RuleName='';App='';Action='';Direction='';Active='';DomainProfile='';PublicProfile='';PrivateProfile=''}
          
            $OutboundFw_Frag = $Firewall | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                        -TableCssClass GRMEMTABLEFRAG `
                                        -DivCssID DIV `
                                        -DivCssClass DIV `
                                        -As Table `
                                        -MakeTableDynamic `
                                        -EvenRowCssClass 'even' `
                                        -OddRowCssClass 'odd' `
                                        -Properties "Policy","RuleName","App","Action","Direction","Active","DomainProfile","PublicProfile","PrivateProfile" `
                                        -PostContent 'Outbound firewall policy rules.<br /><br />'`
                                        -PreContent '<h2>Outbound Firewall Configuration</h2>' | Out-String
            $OutboundFw_Frag += '<br>'
    }
    #endregion

    #region Powershell Logging

    if((Get-ChildItem -Path $path -Filter GP_PowerShellLogging*).Length -gt '0')
    {
        $PSLogging = ipcsv -Path (Get-ChildItem -Path $path -Filter GP_PowerShellLogging*).FullName 
          
        $PSLogging_Frag = $PSLogging | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","State","LinksTo","Enabled" `
                                    -PostContent 'Detecting PowerShell attacks on your network begins with logging PowerShell activity. Logs should be fed into a central logging system with alerts configured for known attack methods.<br /><br />'`
                                    -PreContent '<h2>PowerShell Logging</h2>' | Out-String
        $PSLogging_Frag += '<br>'
    }
    else
    {
        $PSLogging = [pscustomobject]@{Policy='';Value='';State='';LinksTo='';Enabled=''}
          
        $PSLogging_Frag = $PSLogging | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","State","LinksTo","Enabled" `
                                    -PostContent 'Detecting PowerShell attacks on your network begins with logging PowerShell activity. Logs should be fed into a central logging system with alerts configured for known attack methods.<br /><br />'`
                                    -PreContent '<h2>PowerShell Logging</h2>' | Out-String
        $PSLogging_Frag += '<br>'
    }
    #endregion

    #region SMB Signing

    if((Get-ChildItem -Path "$path" -Filter GPSecurity_SMB*).length -gt 0)
    {         
        $SMB_Frag = Import-Csv (Get-ChildItem -Path "$path" -Filter GPSecurity_SMB*).FullName | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'Digitally signing SMB packets enables the recipient of the packets to confirm their point of origination and their authenticity. This security mechanism in the SMB protocol helps avoid issues like tampering of  packets and man-in-the-middle attacks.<br /><br />'`
                                    -PreContent '<h2>SMB Signing</h2>' | Out-String
        $SMB_Frag += '<br>'
    }
    else
    {
        $SMBSigning = [pscustomobject]@{PolicyName='';LinksTo='';SecurityOption='';SecurityOptionValue='';Value='';Enabled=''}

        $SMB_Frag = $SMBSigning | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'Digitally signing SMB packets enables the recipient of the packets to confirm their point of origination and their authenticity. This security mechanism in the SMB protocol helps avoid issues like tampering of  packets and man-in-the-middle attacks.<br /><br />'`
                                    -PreContent '<h2>SMB Signing</h2>' | Out-String
        $SMB_Frag += '<br>'
    }
    #endregion

    #region Powershell Constrained Language Mode

    if((Get-ChildItem -Path "$path" -Filter GP_PowerShellLang*).Length -gt '0')
    {
        $PSLanguage = ipcsv -Path (Get-ChildItem -Path "$path" -Filter GP_PowerShellLang*).FullName 
          
        $PSLanguage_Frag = $PSLanguage | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","State","LinksTo","Enabled" `
                                    -PostContent 'Limits the capability of PowerShell to base functionality removing advanced feature support such as .Net, Windows API calls and COMS access.<br /><br />This stops most PowerShell attack tools since they rely on these features. This should only be considered a minor mitigation on the roadmap to whitelisting because it can be disabled by an attacker once they have gained control of the system.<br /><br />'`
                                    -PreContent '<h2>PowerShell Constrained Language Mode</h2>' | Out-String
        $PSLanguage_Frag += '<br>'
    }
    else
    {
        $PSLanguage = [pscustomobject]@{PolicyName='';Value='';State='';LinksTo='';Enabled=''}
          
        $PSLanguage_Frag = $PSLanguage | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "Policy","Value","State","LinksTo","Enabled" `
                                    -PostContent 'Limits the capability of PowerShell to base functionality removing advanced feature support such as .Net, Windows API calls and COMS access.<br /><br />This stops most PowerShell attack tools since they rely on these features. This should only be considered a minor mitigation on the roadmap to whitelisting because it can be disabled by an attacker once they have gained control of the system.<br /><br />'`
                                    -PreContent '<h2>PowerShell Constrained Language Mode</h2>' | Out-String
        $PSLanguage_Frag += '<br>'
    }
    #endregion

    #region Logon Restrictions (Tiered Isolation)

    if((Get-ChildItem -Path "$path" -Filter GPSecurity_Tier*).length -gt 0)
    {         
        $Tiered_Frag = Import-Csv (Get-ChildItem -Path "$path" -Filter GPSecurity_Tier*).FullName | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'Policies that limit logon for certain users or groups.<br /><br />'`
                                    -PreContent '<h2>Logon Restrictions</h2>' | Out-String
        $Tiered_Frag += '<br>'
    }
    else
    {
        $Tiered = [pscustomobject]@{PolicyName='';LinksTo='';SecurityOption='';SecurityOptionValue='';Value='';Enabled=''}

        $Tiered_Frag = $Tiered | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'Policies that limit logon for certain users or groups.<br /><br />'`
                                    -PreContent '<h2>Logon Restrictions</h2>' | Out-String
        $Tiered_Frag += '<br>'
    
    }
    #endregion

    #region LAPS

    if((Get-ChildItem -Path "$path" -Filter GP_LapsPolicy*).length -gt 0)
    {         
        $LAPS_Frag = Import-Csv (Get-ChildItem -Path "$path" -Filter GP_LapsPolicy*).FullName | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","Enabled","Name","State" `
                                    -PostContent 'Policies that configure LAPS settings.<br /><br />'`
                                    -PreContent '<h2>LAPS</h2>' | Out-String
        $LAPS_Frag += '<br>'
    }
    else
    {
        $LAPS = [pscustomobject]@{PolicyName='';LinksTo='';Enabled='';Name='';State=''}

        $LAPS_Frag = $LAPS | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","Enabled","Name","State" `
                                    -PostContent 'Policies that configure LAPS settings.<br /><br />'`
                                    -PreContent '<h2>LAPS</h2>' | Out-String
        $LAPS_Frag += '<br>'
    }
    #endregion

    #region LDAP Signing

    if((Get-ChildItem -Path "$path" -Filter GPSecurity_LDAP*).length -gt 0)
    {         
        $LDAPS_frag = Import-Csv (Get-ChildItem -Path "$path" -Filter GPSecurity_LDAP*).FullName | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'Policies that configure LDAP signing.<br /><br />'`
                                    -PreContent '<h2>LDAP Signing</h2>' | Out-String
        $LDAPS_frag += '<br>'
    }
    else
    {
        $LDAPS = [pscustomobject]@{PolicyName='';LinksTo='';SecurityOption='';SecurityOptionValue='';Value='';Enabled=''}

        $LDAPS_frag = $LDAPS | ConvertTo-EnhancedHTMLFragment -TableCssID GRMEMTABLE `
                                    -TableCssClass GRMEMTABLEFRAG `
                                    -DivCssID DIV `
                                    -DivCssClass DIV `
                                    -As Table `
                                    -MakeTableDynamic `
                                    -EvenRowCssClass 'even' `
                                    -OddRowCssClass 'odd' `
                                    -Properties "PolicyName","LinksTo","SecurityOption","SecurityOptionValue","Value","Enabled" `
                                    -PostContent 'Policies that configure LDAP signing.<br /><br />'`
                                    -PreContent '<h2>LDAP Signing</h2>' | Out-String
        $LDAPS_frag += '<br>'
    }
    #endregion

    #region GPO Permissions

    if((Get-ChildItem -Path "$path" -Filter GP_Insecure*).length -gt '0')
    {
        $GPOPermissions = ipcsv -Path (Get-ChildItem -Path $Path -Filter GP_Insecure*).FullName | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GPOPERMTABLE `
                                -TableCssClass GPOPERMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "PolicyName","Trustee","PermissionType","ACLs" `
                                -PostContent 'By default Domain Admins and Enterprise Admins have full control permission on group policy objects (GPOs). When user or groups have permission to modify a GPO, i can be used to take control of the accounts where the GPO is applied. Potential compromise of the domain is possible.<br /><br />'`
                                -PreContent '<h2>GPO Permissions</h2>' | Out-String
        $GPOPermissions += '<br>'                        
    }
    else
    {
        $GPOPerm = [pscustomobject]@{GPO='';Trustee='';Permission=''}
        $GPOPermissions = $GPOPerm | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GPOPERMTABLE `
                                -TableCssClass GPOPERMTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "PolicyName","Trustee","PermissionType","ACLs" `
                                -PostContent 'By default Domain Admins and Enterprise Admins have full control permission on group policy objects (GPOs). When user or groups have permission to modify a GPO, i can be used to take control of the accounts where the GPO is applied. Potential compromise of the domain is possible.<br /><br />'`
                                -PreContent '<h2>GPO Permissions</h2>' | Out-String
        $GPOPermissions += '<br>'                        
    }
    #endregion

    #region Local Users and Groups
    
    #Get-GPOLocalUsersAndGroups -FilePath "$OutputDir\GPO" | Export-Csv $OutputDir\GP_LocalUsersAndGroup-$Domain.csv -NoTypeInformation

    if((Get-ChildItem -Path "$path" -Filter GP_LocalUsersAnd*).length -gt '0')
    {
        $GPOPermissions = ipcsv -Path (Get-ChildItem -Path $Path -Filter GP_LocalUsersAnd*).FullName | select "GPO","AppliesTo","GroupName","Member" | `
        ConvertTo-EnhancedHTMLFragment -TableCssID GPLGRPTABLE `
                                -TableCssClass GPLGRPTABLEFRAG `
                                -DivCssID DIV `
                                -DivCssClass DIV `
                                -As Table `
                                -MakeTableDynamic `
                                -EvenRowCssClass 'even' `
                                -OddRowCssClass 'odd' `
                                -Properties "GPO","AppliesTo","GroupName","Member" `
                                -PostContent 'Policies that configure computer local group membership.<br /><br />'`
                                -PreContent '<h2>GPO Local Users and Groups</h2>' | Out-String
        $GPOLocalUsersAndGroups                        
    }

    
    #endregion


#endregion

$t7 = @"
<div class="tab content7">

<h1>Group Policy Report - $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString())</p> 
<br>Active Directory is the security center of Microsoft's information system. It is a critical element for the centralized management of accounts, resources, and permissions. Obtaining high-level privileges in this directory can result in an instantaneous and complete takeover of the forest.
<br><br>Analysis of recent attacks reveals an increase in Active Directory targeting, given its role as the cornerstone of most information systems. An attacker who has obtained privileged rights in the directory can then deploy malicious software to the entire information system, especially by GPO or by using direct connections(WinRM, psexec, wmiexec). The lack of directory security endangers information systems as a whole and places a systemic risk on organizations.
<br /><br />

$ntlm_frag
<br><br>
$NullSess_frag
<br><br>
$LMHash_frag
<br><br>
$NetCease_frag
<br><br>
$Wpad_frag
<br><br>
$WSH_frag
<br><br>
$WDigest_frag
<br><br>
$RevPwdEnc_Frag
<br><br>
$AutoLogon_Frag
<br><br>
$SYSVOLPwd_frag
<br><br>
$OutboundFw_Frag
<br><br>
$PSLogging_Frag
<br><br>
$SMB_Frag
<br><br>
$PSLanguage_Frag
<br><br>
$Tiered_Frag
<br><br>
$LAPS_Frag
<br><br>
$LDAPS_frag
<br><br>
$GPOPermissions
<br><br>
$GPOLocalUsersAndGroups

<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 8 Content: GPO Permissions

$GPOXmlPath = $OutputDir + '\GPO'

function Get-GPOPermission($xmldata)
{
    if(($xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text').count -gt '1')
    {
        [int]$count = '-1'
        foreach($Trustee in $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text')
        {    
            $count++
            $PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType[$count]
            $ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard[$count].GPOGroupedAccessEnum)

            [pscustomobject]@{
                PolicyName = $xmldata.GPO.Name
                Trustee = $Trustee
                PermissionType = $PermissionType
                ACLs = $ACLs
            }
        }
    }
    else
    {
        [pscustomobject]@{
            PolicyName = $xmldata.GPO.Name                
            Trustee = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text'
            PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType
            ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard.GPOGroupedAccessEnum)
        }
    }
}

function Test-GPOAdministrativePermission($xmldata)
{
    [int]$fail = '0'
    function Get-GPOPermission($xmldata)
    {
        if(($xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text').count -gt '1')
        {
            [int]$count = '-1'
            foreach($Trustee in $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text')
            {    
                $count++
                $PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType[$count]
                $ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard[$count].GPOGroupedAccessEnum)

                [pscustomobject]@{
                    PolicyName = $xmldata.GPO.Name
                    Trustee = $Trustee
                    PermissionType = $PermissionType
                    ACLs = $ACLs
                }
            }
        }
        else
        {
            [pscustomobject]@{
                PolicyName = $xmldata.GPO.Name                
                Trustee = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text'
                PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType
                ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard.GPOGroupedAccessEnum)
            }
        }
    }

    $Permissions = Get-GPOPermission([xml]$xmldata)

    if($Permissions | ? Trustee -Match 'Domain Admins')
    {
        if(($Permissions | ? Trustee -Match 'Domain Admins').PermissionType -eq 'allow')
        {
            if(($Permissions | ? Trustee -Match 'Domain Admins').ACLs -ne 'Edit, delete, modify security')
            {
                [int]$fail = '1'
            }
        }
        else
        {
            [int]$fail = '1'
        }
    }
    else
    {
        [int]$fail = '1'
    }

    if($Permissions | ? Trustee -Match 'Enterprise Admins')
    {
        if(($Permissions | ? Trustee -Match 'Enterprise Admins').PermissionType -eq 'allow')
        {
            if(($Permissions | ? Trustee -Match 'Enterprise Admins').ACLs -ne 'Edit, delete, modify security')
            {
                [int]$fail = '1'
            }
        }
        else
        {
            [int]$fail = '1'
        }
    }
    else
    {
        [int]$fail = '1'
    }
    
    if([int]$fail -eq '1')
    {
        Write-Output 'Fail'
    }
}

function Test-GPOAuthenticatedUserPermission($xmldata)
{
    [int]$fail = 0
    function Get-GPOPermission($xmldata)
    {
        if(($xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text').count -gt '1')
        {
            [int]$count = '-1'
            foreach($Trustee in $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text')
            {    
                $count++
                $PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType[$count]
                $ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard[$count].GPOGroupedAccessEnum)

                [pscustomobject]@{
                    PolicyName = $xmldata.GPO.Name
                    Trustee = $Trustee
                    PermissionType = $PermissionType
                    ACLs = $ACLs
                }
            }
        }
        else
        {
            [pscustomobject]@{
                PolicyName = $xmldata.GPO.Name                
                Trustee = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text'
                PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType
                ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard.GPOGroupedAccessEnum)
            }
        }
    }

    $Permissions = Get-GPOPermission([xml]$xmldata)

    if($Permissions | ? Trustee -Match 'Authenticated Users')
    {
        if(($Permissions | ? Trustee -Match 'Authenticated Users').PermissionType -eq 'allow')
        {
            if(($Permissions | ? Trustee -Match 'Authenticated Users').ACLs -ne 'Apply Group Policy')
            {
                if(($Permissions | ? Trustee -Match 'Authenticated Users').ACLs -ne 'Read')
                {
                    [int]$fail = '1'
                }
            }
        }
        else
        {
            [int]$fail = '1'
        }
    }
    else
    {
        [int]$fail = '1'
    }

    if($fail -eq '1')
    {
        Write-Output 'Fail'
    }
}

function Test-GPOSYSTEMPermission($xmldata)
{
    [int]$fail = '0'
    function Get-GPOPermission($xmldata)
    {
        if(($xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text').count -gt '1')
        {
            [int]$count = '-1'
            foreach($Trustee in $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text')
            {    
                $count++
                $PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType[$count]
                $ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard[$count].GPOGroupedAccessEnum)

                [pscustomobject]@{
                    PolicyName = $xmldata.GPO.Name
                    Trustee = $Trustee
                    PermissionType = $PermissionType
                    ACLs = $ACLs
                }
            }
        }
        else
        {
            [pscustomobject]@{
                PolicyName = $xmldata.GPO.Name                
                Trustee = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.Name.'#text'
                PermissionType = $xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.ParentNode.Type.PermissionType
                ACLs = [string]::join(', ',$xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Standard.GPOGroupedAccessEnum)
            }
        }
    }

    $Permissions = Get-GPOPermission([xml]$xmldata)

    if($Permissions | ? Trustee -Match 'SYSTEM')
    {
        if(($Permissions | ? Trustee -Match 'SYSTEM').PermissionType -eq 'allow')
        {
            if(($Permissions | ? Trustee -Match 'SYSTEM').ACLs -ne 'Edit, delete, modify security')
            {
                [int]$fail = '1'
            }
        }
        else
        {
            [int]$fail = '1'
        }
    }
    else
    {
        [int]$fail = '1'
    }

    if($fail -eq '1')
    {
        Write-Output 'Fail'
    }
}

$GPOIncorrectPermissions = Import-Csv -Path $OutputDir\GP_IncorrectPermission-$Domain.csv | Group-Object GPO

[int]$AdministrativeFail = '0'
[int]$AuthenticatedUserFail = '0'
[int]$SystemFail = '0'
[System.Collections.ArrayList]$array = @()

foreach($item in $GPOIncorrectPermissions)
{
    $obj = "" | select 'Policy','Administrative','AuthenticatedUsers','System'

    $obj.Policy = $item.Name
    $obj.AuthenticatedUsers = 'Pass'
    $obj.Administrative = 'Pass'
    $obj.System = 'Pass'

    if($item.group.Trustee -eq 'Authenticated Users')
    {
        $AuthenticatedUserFail++ 
        $obj.AuthenticatedUsers = 'Fail'
    }

    if($item.group.Trustee -eq 'SYSTEM')
    {
        $SystemFail++
        $obj.System = 'Fail'
    }

    if($item.group.Trustee -eq 'Domain Admins' -or $item.Trustee -eq 'Enterprise Admins')
    {
        $AdministrativeFail++
        $obj.Administrative = 'Fail'
    }

    $array += $obj
    $obj = $Null
}

    $Count = ($array | measure).count
    $GPOPermissionFrag = $array | `
    ConvertTo-EnhancedHTMLFragment -TableCssID GPOPRTABLE `
                            -TableCssClass GPOPRTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Policy','Administrative','AuthenticatedUsers','System' `
                            -PreContent "<h2>GPOs Requiring Permission Fix ($($Count))</h2>" | Out-String

    $GPOPermissionFrag1 = $GPOPermissionFrag -replace "<td>Fail</td>", "<td class='cell-severe'>Fail</td>"   


    $InsecureGPO_Frag = ipcsv "$OutputDir\GP_InsecureGPOAcls-$Domain.csv" | `
    ConvertTo-EnhancedHTMLFragment -TableCssID GPOPRTABLE `
                            -TableCssClass GPOPRTABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'PolicyName','Trustee','PermissionType','ACLs' `
                            -PreContent "<h2>Insecure GPO Permissions</h2>" | Out-String    

$t8 = @"
<div class="tab content8">
<h1>Group Policy Permission Analysis- $($ClientName)</h1><p>Assessment Date: $($lwt.LastWriteTime.ToShortDateString()) </p>
<br>When a GPO is created a handfull of permissions are granted to it by default. Over time permissions on GPO change, while most chnages make sense and are required to be able to target proper groups of accounts, some changes are not recommended or even bad. 
<br>
<br><strong>Administrative</strong>
<br>Policies that are missing Edit/Delete/Modify permissions for the Domain Admins and/or Enterprise Admins groups.
<br>
<br><strong>Authenticated Users</strong>
<br>Policies that are missing Read or Apply Group Policy permission for NT AUTHORITY\Authenticated Users.
<br>
<br><strong>System</strong>
<br>Policies that are missing Edit/Delete/Modify permissions for the SYSTEM account.
<br> 
<br>GPOs requiring Administrative permission fix: $AdministrativeFail
<br>GPOs requiring Authenticated Users permission fix: $AuthenticatedUserFail
<br>GPOs requiring SYSTEM permission fix: $SystemFail
<br><br><br><br>
$GPOPermissionFrag1
<br><br>
$InsecureGPO_Frag
<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 9 Content: Inactive GPOs

    function Get-GPOReport
    {
        [cmdletBinding()]
        Param
        (
            [parameter(Mandatory=$true)]
            $GPOPath 
        )

        function IsGPOEmpty($xmldata)
        { 
            If($xmldata.GPO.Computer.ExtensionData -eq $null) 
	        { 
                If($xmldata.GPO.User.ExtensionData -eq $null) 
                {
                    Return $true
                }
                #Return $false
            } 
            Return $false 
        } 

        function IsGPOAllSettingsDisabled($xmldata)
        { 
            If($xmldata.GPO.Computer.Enabled -eq $false) 
	        { 
                If($xmldata.GPO.User.Enabled -eq $false) 
                {
                    Return $true
                }
            } 
            Return $false 
        } 

        function IsGPOLinkDisabled($xmldata)
        { 
            if($xmldata.GPO.LinksTo.Enabled -eq $null)
            {
                Return $true
            }

            else
            {
                $Result = $true

                foreach($Link in $xmldata.GPO.LinksTo.Enabled)
                {
                    if($Link -eq $true)
                    {
                        $Result = $false
                    }                                                 
                }
                $Result
            }
        } 

        function GPOLinksToCount($xmldata)
        {
            ($xmldata.GPO.LinksTo | Measure-Object).count
        }

        function GPOMissingApplyPermissions($xmldata)
        {
            if(($xmldata.GPO.SecurityDescriptor.Permissions.TrusteePermissions.Trustee.name.'#text' | Where-Object {$_ -notlike "*DOmain Admins" -and $_ -notlike "*Enterprise Admins" -and $_ -notlike "*SYSTEM" -and $_ -notlike "*ENTERPRISE DOMAIN CONTROLLERS"}) -eq $null)
            {
                Return $true
            }
            Return $false
        }

        function CreatedTime($xmldata)
        {
            ([datetime]$xmldata.GPO.CreatedTime).ToString('MM/dd/yyyy')
        }

        $GPOxmlFiles = Get-ChildItem -Path $GPOPath -Filter *.xml

        foreach($file in $GPOxmlFiles)
        {
            [xml]$xml = Get-Content $file.FullName

            [pscustomobject]@{
                Name = $xml.GPO.Name
                Created = CreatedTime([xml]$xml)
                GPOEmpty = IsGPOEmpty([xml]$xml)
                SettingsDisabled = IsGPOAllSettingsDisabled([xml]$xml)
                LinkDisabled = IsGPOLinkDisabled([xml]$xml)
                LinksCount = GPOLinksToCount([xml]$xml)
                MissingPermissions = GPOMissingApplyPermissions([xml]$xml)
            }
        }
    }


    $Report = Get-GPOReport -GPOPath $GPOXmlPath

    $Count = ($Report | ? {$_.GPOEmpty -eq 'True' -or $_.SettingsDisabled -eq 'True' -or $_.LinkDisabled -eq 'True' -or $_.LinksCount -eq '0' -or $_.MissingPermissions -eq 'true'} | measure).count
    $HTMLFrag = $Report | ? {$_.GPOEmpty -eq 'True' -or $_.SettingsDisabled -eq 'True' -or $_.LinkDisabled -eq 'True' -or $_.LinksCount -eq '0' -or $_.MissingPermissions -eq 'true'} | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Name','Created','GPOEmpty','SettingsDisabled','LinkDisabled','LinksCount','MissingPermissions' `
                            -PreContent "<h2>Policies With No Effect ($($Count))</h2>" | Out-String

    $HTMLFrag1 = $HTMLFrag -replace "<td>True</td>", "<td class='cell-severe'>True</td>"
    $HTMLFrag2 = $HTMLFrag1 -replace "<td>0</td>", "<td class='cell-severe'>0</td>"    
    $HTMLFrag2 += '<br /><br />'


    $count = ($Report | ? {$_.GPOEmpty -like 'f*' -and $_.SettingsDisabled -like 'f*' -and $_.LinkDisabled -like 'f*' -and $_.LinksCount -gt 0 -and $_.MissingPermissions -like 'f*'}).count
    $GoodPolicyFrag = $Report | ? {$_.GPOEmpty -like 'f*' -and $_.SettingsDisabled -like 'f*' -and $_.LinkDisabled -like 'f*' -and $_.LinksCount -gt 0 -and $_.MissingPermissions -like 'f*'} | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Name','Created','GPOEmpty','SettingsDisabled','LinkDisabled','LinksCount','MissingPermissions' `
                            -PreContent "<h2>Policies In Effect ($($Count))</h2>" | Out-String

    $GoodPolicyFrag += '<br />'



$t9 = @"
<div class="tab content9">

<h1>Inactive Policy Summary- $($ClientName)</h1><p>Report Generated On: $($lwt.LastWriteTime.ToShortDateString()) </p> 
<br><strong>GPOEmpty</strong> = The GPO has no content
<br><strong>SettingsDisabled</strong> = Both Computer and User sections are disabled, and therefore the GPO has no effect.
<br><strong>LinkDisabled</strong> = The GPO has it's links disabled.
<br><strong>LinksCount</strong> =  The number of links the GPO has.
<br><strong>MissingPermissions</strong> = The GPO is not being applied to any group, users, or computers.
<br><br><br>                                
$HTMLFrag2

$GoodPolicyFrag

<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


#region Tab 10 Content: GPO Firewall Rules

    function Get-GPOFirewallRules($xmldata)
    {
        [System.Collections.ArrayList]$arraylist = @()

        $FirewallRules = $xmldata.GPO.Computer.ExtensionData.Extension.OutboundFirewallRules
        $FirewallRules += $xmldata.GPO.Computer.ExtensionData.Extension.InboundFirewallRules

        foreach($rule in $FirewallRules)
        {
            if($rule.name -ne $null)
            {
                $obj = "" | select 'Policy','Enabled','RuleName','App','RemoteAddress','Port','Action','Direction','Active','Description'

                if(($rule.ra4 | measure).count -gt '1')
                {
                    $obj.RemoteAddress = [string]::join(', ',$rule.ra4)                
                }
                else
                {
                    $obj.RemoteAddress = $rule.ra4
                }

                if(($rule.lport | measure).count -gt '1')
                {
                    $obj.port = [string]::join(', ',$rule.lport)                
                }
                else
                {
                    $obj.port = $rule.lport
                }

                if(($xml.GPO.LinksTo.Enabled | measure).count -gt '1')
                {
                    $obj.Enabled = [string]::join(', ',$xml.GPO.LinksTo.Enabled)                
                }
                else
                {
                    $obj.Enabled = $xml.GPO.LinksTo.Enabled
                }

                $obj.Policy =  $xml.GPO.Name
                $obj.RuleName = $rule.name
                $obj.App = $rule.app
                $obj.Action = $rule.action
                $obj.Direction = $rule.dir
                $obj.Active = $rule.active
                $obj.Description = $rule.desc        

                $arraylist += $obj
                $obj = $Null
            }    
        }
        $arraylist
    }


    # GPO Inbound and Outbound Rule Count
    function Get-FwRuleCount
    {
        [cmdletBinding()]
        Param
        (
            [parameter(Mandatory=$true)]
            $Path
        )

        $GPOXmlFiles = Get-ChildItem -Path $Path -Filter *.xml

        foreach($file in $GPOXmlFiles)
        {
            [xml]$xml = cat $file.FullName

            $FwRules = Get-GPOFirewallRules([xml]$xml)
            $InCount = $FwRules | ? Direction -eq 'in' | measure
            $OutCount = $FwRules | ? Direction -eq 'out' | measure

            if($InCount.count -ne '0' -or $OutCount.Count -ne '0')
            {
                [pscustomobject]@{
                    Name = $xml.gpo.Name
                    Inbound = $InCount.Count
                    Outbound = $OutCount.Count
                }
            }
        }    
    }
    $RuleCount = Get-FwRuleCount -Path $GPOXmlPath | sort Name



    # List all GPO Firewall Rules
    function Get-FwRule
    {
        [cmdletBinding()]
        Param
        (
            [parameter(Mandatory=$true)]
            $Path
        )

        $GPOXmlFiles = Get-ChildItem -Path $Path -Filter *.xml

        foreach($file in $GPOXmlFiles)
        {
            [xml]$xml = cat $file.FullName

            $FwRules = Get-GPOFirewallRules([xml]$xml)
            $FwRules
        }    
    }
     $alltherules = Get-FwRule -Path $GPOXmlPath


    $PolicyFrag = $RuleCount  | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Name','Inbound','Outbound' `
                            -PreContent "<h2>Inbound / Outbound Rule Count</h2>" | Out-String    
    $PolicyFrag += '<br /><br />'

    $PolicyFrag2 = $alltherules  | `
    ConvertTo-EnhancedHTMLFragment -TableCssID TABLE `
                            -TableCssClass TABLEFRAG `
                            -DivCssID DIV `
                            -DivCssClass DIV `
                            -As Table `
                            -MakeTableDynamic `
                            -EvenRowCssClass 'even' `
                            -OddRowCssClass 'odd' `
                            -Properties 'Policy','Enabled','RuleName','App','RemoteAddress','Port','Action','Direction','Active','Description' `
                            -PreContent "<h2>Firewall Rules</h2>" | Out-String    
    $PolicyFrag2 += '<br />'


$t10 = @"
<div class="tab content10">

<h1>GPO Firewall Rules- $($ClientName)</h1><p>Report Generated On: $($lwt.LastWriteTime.ToShortDateString()) </p>
<br><br>
$PolicyFrag
$PolicyFrag2
<br><br><hr />copyright RSM 2022<br><br>
</div>
"@

#endregion


    New-TabsHTMLDocument -Title 'AD Security Assessment Report' `
                         -Tabs $Tabs `
                         -StyleSheet $css `
                         -Tab1Content $t1 `
                         -Tab2Content $t2 `
                         -Tab3Content $t3 `
                         -Tab4Content $t4 `
                         -Tab5Content $t5 `
                         -Tab6Content $t6 `
                         -Tab7Content $t7 `
                         -Tab8Content $t8 `
                         -Tab9Content $t9 `
                         -Tab10Content $t10 | Out-File $OutputDir\ADAssessmentReport_$ClientName.html
    if($ShowReport)
    {
        Start-Process $OutputDir\ADAssessmentReport_$ClientName.html
    }

}


function Show-Menu 
{ 
    [cmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        $Color
    )
       
    Write-Host ""
    Write-Host " 1 = Connect to Services" -ForegroundColor $Color
    Write-Host " 2 = Collect Data" -ForegroundColor $Color
    Write-Host " 3 = Disconnect Services Report" -ForegroundColor $Color
    Write-Host " 4 = Analyze" -ForegroundColor $Color
    Write-Host " 5 = Generate Report" -ForegroundColor $Color
    Write-Host " Q = Press 'Q' to quit" -ForegroundColor $Color
}

Clear-Host
Write-Host $Banner -ForegroundColor $DataColor 

do
{
    Show-Menu -Color yellow
    Write-Host ""
    $selection = Read-Host "Please make a selection"
    Write-Host "" 
    switch ($selection)
    {
        {$selection -eq '1'} { Connectto-Services }
        {$selection -eq '2'} 
        { 
            $Domain = Read-Host -Prompt 'Enter client domain name'
            Invoke-365DataCollection -OutputDir $OutputDir -Domain $Domain -Verbose 
        }
        {$selection -eq '3'} { Invoke-365Analyzer -Path $OutputDir -Domain $Domain -ClientName $Domain -ShowReport }
        {$selection -eq '4'} { Write-365HTMLReport -Path $OutputDir -Domain $Domain -ClientName $Domain -ShowReport }
        {$selection -eq 'q'} {''}
    }
}
until($selection -eq 'q')




ipcsv $OutputDir\WarningList-$Domain.csv | ? Rating -eq 'Fail' | ft -Wrap


break



# 4.14
Get-MalwareFilterPolicy | fl Identity,EnableInternalSenderAdminNotifications, InternalSenderAdminAddress

# 4.15
Get-OrganizationConfig |fl MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled,MailTipsLargeAudienceThreshold


Get-OwaMailboxPolicy | epcsv $OutputDir\OWAMailboxPolicy.csv

# 4.16 verify false
Get-OwaMailboxPolicy | select LinkedInEnabled


# 4.17 verify false
Get-OwaMailboxPolicy | select FacebookEnabled


# 4.9 (L1) Ensure that an anti-phishing policy has been created (Scored)
# This does not return the desired information.
Get-AntiPhishPolicy | ft Name

Get-MalwareFilterPolicy -Identity Default | Select-Object EnableFileFilter


# 4.13 (L1) Ensure notifications for internal users sending malware is Enabled (Scored)

function Get-MalwareNotificationsForInternalUsers
{
    Write-Output "4.13 (L1) Ensure notifications for internal users sending malware is Enabled (Scored)"

    Get-MalwareFilterPolicy | fl EnableInternalSenderAdminNotifications, InternalSenderAdminAddress
}


# 5.6 (L1) Ensure user role group changes are reviewed at least weekly (Not Scored)

$startDate = ((Get-Date).AddDays(-7)).ToShortDateString() 
$endDate = (Get-date).ToShortDateString() 
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate | ? { $_.Operations -eq "Add member to role." }

# 5.7 (L1) Ensure mail forwarding rules are reviewed at least weekly (Not Scored)

$allUsers = @() 
$AllUsers = Get-MsolUser -All -EnabledFilter EnabledOnly | select ObjectID, UserPrincipalName, FirstName, LastName, StrongAuthenticationRequirements, StsRefreshTokensValidFrom, StrongPasswordRequired, LastPasswordChangeTimestamp | Where-Object {($_.UserPrincipalName -notlike "*#EXT#*")} 
$UserInboxRules = @() 
$UserDelegates = @() 
foreach ($User in $allUsers) 
{ 
    Write-Host "Checking inbox rules and delegates for user: " $User.UserPrincipalName 
    $UserInboxRules += Get-InboxRule -Mailbox $User.UserPrincipalname | Select MailboxOwnerId, Name, Description, Enabled, Priority, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage | Where-Object {($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectsTo -ne $null)} 
    $UserDelegates += Get-MailboxPermission -Identity $User.UserPrincipalName | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")} } 
    $SMTPForwarding = Get-Mailbox -ResultSize Unlimited | select DisplayName,ForwardingAddress,ForwardingSMTPAddress,DeliverToMailboxandForward | where {$_.ForwardingSMTPAddress -ne $null
} 
    
# Export list of inboxRules, Delegates and SMTP Forwards 
$UserInboxRules | Export-Csv MailForwardingRulesToExternalDomains.csv 
$UserDelegates | ft -a # | Export-Csv MailboxDelegatePermissions.csv 
$SMTPForwarding | Export-Csv Mailboxsmtpforwarding.csv


Get-Mailbox | % {Get-InboxRule -Mailbox $_.PrimarySmtpAddress | ? {($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectsTo -ne $null)} |Select MailboxOwnerId,Name,Description,Enabled,ForwardTo,ForwardAsAttachmentTo,RedirectTo }


# 5.10 (L1) Ensure the Account Provisioning Activity report is reviewed at least weekly (Not Scored)

$startDate = ((Get-Date).AddDays(-7)).ToShortDateString() 
$endDate = (Get-date).ToShortDateString()
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate | Where-Object { $_.Operations -eq "add user." }


# 5.12 (L1) Ensure the spoofed domains report is review weekly (Not Scored)

Get-PhishFilterPolicy -Detailed -SpoofAllowBlockList -SpoofType Internal 


# 5.14 (L1) Ensure the report of users who have had their email privileges restricted due to spamming is reviewed (Not Scored)



# 6.2 (L1) Ensure expiration time for external sharing links is set (Scored)

Get-SPOTenant | fl RequireAnonymousLinksExpireInDays


#2.3 Verify the value for AllowClickThrough is set to False and the rest are set for True.
Get-AtpPolicyForO365 | fl Name,AllowClickThrough,EnableSafeLinksForClients,EnableSafeLinksForWebAccessCompanion,EnableSafeLinksForO365Clients


