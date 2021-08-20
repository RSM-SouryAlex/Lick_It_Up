# List MFA status for all accounts in Office 365

$Result=@() 
$users = Get-MsolUser -All

ForEach($user in $users)
{
    #$user = $_
    $mfaStatus = $user.StrongAuthenticationRequirements.State 
    $methodTypes = $user.StrongAuthenticationMethods 
 
    if ($mfaStatus -ne $null -or $methodTypes -ne $null)
    {
        if($mfaStatus -eq $null)
        { 
            $mfaStatus='Enabled (Conditional Access)'
        }

        $authMethods = $methodTypes.MethodType
        $defaultAuthMethod = ($methodTypes | Where{$_.IsDefault -eq "True"}).MethodType 
        $verifyEmail = $user.StrongAuthenticationUserDetails.Email 
        $phoneNumber = $user.StrongAuthenticationUserDetails.PhoneNumber
        $alternativePhoneNumber = $user.StrongAuthenticationUserDetails.AlternativePhoneNumber
    }

    Else
    {
        $mfaStatus = "Disabled"
        $defaultAuthMethod = $null
        $verifyEmail = $null
        $phoneNumber = $null
        $alternativePhoneNumber = $null
    }
    
    $Result += New-Object PSObject -property @{ 
        UserName = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        MFAStatus = $mfaStatus
        AuthenticationMethods = $authMethods
        DefaultAuthMethod = $defaultAuthMethod
        MFAEmail = $verifyEmail
        PhoneNumber = $phoneNumber
        AlternativePhoneNumber = $alternativePhoneNumber
        IsLicensed = $user.islicensed
        BlockCredential = $user.blockcredential
        Licenses = $user.licenses
    }
}
$Result | Select UserName,MFAStatus,MFAEmail,IsLicensed,BlockCredential,PhoneNumber,AlternativePhoneNumber,licenses | ft