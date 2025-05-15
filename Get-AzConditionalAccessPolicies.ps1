#Connect-AzureAD

Function Get-AzConditionalAccessPolicies
{
    $ConditionalAccessPolicies = Get-AzureADMSConditionalAccessPolicy

    [System.Collections.ArrayList]$Array = @()
    [System.Collections.ArrayList]$AR = @()

    foreach($policy in $ConditionalAccessPolicies)
    {
        $obj = "" | select "DisplayName","State","IncludeApplications","ExcludeApplications","IncludeUserActions","IncludeProtectionLevels","IncludeUsers","ExcludeUsers","IncludeGroups","IncludeRoles","ExcludeRoles","Operator","BuiltInControls"

        [string]$IncludeApplications = $policy.Conditions.Applications.IncludeApplications
        [string]$ExcludeApplications = $policy.Conditions.Applications.ExcludeApplications
        [string]$IncludeUserActions = $policy.Conditions.Applications.IncludeUserActions
        [string]$IncludeProtectionLevels = $policy.Conditions.Applications.IncludeProtectionLevels
        [string]$IncludeUsers = $policy.Conditions.Users.IncludeUsers
        [string]$ExcludeUsers = $policy.Conditions.Users.ExcludeUsers
        [string]$IncludeRoles = $policy.Conditions.Users.IncludeRoles
        [string]$ExcludeRoles = $policy.Conditions.Users.ExcludeRoles
        [string]$Operator = $policy.GrantControls._Operator
        [string]$BuiltInControls = $policy.GrantControls.BuiltInControls


        [System.Collections.ArrayList]$IncludedUsersArray = @()
        if($IncludeUsers -ne 'All' -and $IncludeUsers -ne 'None' -and $IncludeUsers -ne '')
        {
            foreach($id in $IncludeUsers.Split(' '))
            {
                $IncUserObj = "" | select Name
                try
                {
                    $UserObj = Get-AzureADUser -ObjectId $id -ErrorAction Stop
                }
                catch{}
                $IncUserName = $($UserObj.DisplayName)

                $IncUserObj.Name = $IncUserName
                $IncludedUsersArray += $IncUserObj
                $IncUserObj = $null
            }
            $IncludedUsersName = $IncludedUsersArray.name -join ', '
        }
        else
        {
            $IncludedUsersName = $IncludeUsers
        }

        [System.Collections.ArrayList]$IncludedGroupsName = @()        
        $IncludeGroups = $policy.Conditions.Users.IncludeGroups
        if($IncludeGroups -ne $null)
        {
            foreach($id in $IncludeGroups.Split(' '))
            {
                $obj2 = "" | select Name
                $GroupObj = Get-AzureADGroup -ObjectId $id -ErrorAction Stop
                $GroupName = $($GroupObj.DisplayName)

                $obj2.name = $GroupName
                $AR += $obj2
                $obj2 = $null
            }

            $IncludeGroupsName = $AR.name -join ', '
        }

        [System.Collections.ArrayList]$ExcludedUsersArray = @()
        if($ExcludeUsers -ne '')
        {
            foreach($id in $ExcludeUsers.Split(' '))
            {                
                $ExUserObj = "" | select Name
                $UserObj = Get-AzureADUser -ObjectId $id -ErrorAction Stop
                $ExUserName = $($UserObj.UserPrincipalName)

                $ExUserObj.Name = $ExUserName
                $ExcludedUsersArray += $ExUserObj
                $ExUserObj = $null
            }
            $ExcludedUsersName = $ExcludedUsersArray.name -join ', '
        }
        else
        {
            $ExcludedUsersName = $ExcludeUsers
        }

        [System.Collections.ArrayList]$IncludeRoleArray = @()
        if($IncludeRoles -ne '')
        {
            foreach($id in $IncludeRoles.Split(''))
            {                
                $IncRoleObj = "" | select Name                
                $RoleObj = Get-AzureADMSRoleDefinition -Id $id -ErrorAction stop
                $IncRoleName = $($RoleObj.DisplayName)

                $IncRoleObj.Name = $IncRoleName
                $IncludeRoleArray += $IncRoleObj
                $IncRoleObj = $null
            }
            $IncludedRolesName = $IncludeRoleArray.name -join ', '
        }
        else
        {
            $IncludedRolesName = $IncludeRoles
        }

        [System.Collections.ArrayList]$ExcludeRoleArray = @()
        if($ExcludeRoles -ne '')
        {
            foreach($id in $ExcludeRoles.Split(''))
            {                
                $ExRoleObj = "" | select Name                
                $RoleObj = Get-AzureADMSRoleDefinition -Id $id -ErrorAction stop
                $ExRoleName = $($RoleObj.DisplayName)

                $ExRoleObj.Name = $ExRoleName
                $ExcludeRoleArray += $ExRoleObj
                $ExRoleObj = $null
            }
            $ExcludeRolesName = $ExcludeRoleArray.name -join ', '
        }
        else
        {
            $ExcludeRolesName = $ExcludeRoles
        }


        $obj.DisplayName = $policy.DisplayName
        $obj.State = $policy.State
        $obj.IncludeApplications = $IncludeApplications
        $obj.ExcludeApplications = $ExcludeApplications
        $obj.IncludeUserActions = $IncludeUserActions
        $obj.IncludeProtectionLevels = $IncludeProtectionLevels
        $obj.IncludeUsers = $IncludedUsersName
        $obj.ExcludeUsers = $ExcludedUsersName
        $obj.IncludeGroups = $IncludeGroupsName
        $obj.IncludeRoles = $IncludedRolesName
        $obj.ExcludeRoles = $ExcludeRolesName
        $obj.Operator = $Operator
        $obj.BuiltInControls = $BuiltInControls

        $Array += $obj
        $obj = $null
        $obj2 = $null
        $IncludeGroupsName = $null
        $AR = @()
    }

    $Array 
}

Get-AzConditionalAccessPolicies | ogv


