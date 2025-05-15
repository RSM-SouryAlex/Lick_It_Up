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

