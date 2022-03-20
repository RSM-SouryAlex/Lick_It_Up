#Connect-AzureAD

Function Get-AzConditionalAccessPolicies
{
    $ConditionalAccessPolicies = Get-AzureADMSConditionalAccessPolicy

    [System.Collections.ArrayList]$Array = @()
    [System.Collections.ArrayList]$AR = @()
    [System.Collections.ArrayList]$ExcludedUsersArray = @()

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

        $ExcludeUsers = $policy.Conditions.Users.ExcludeUsers

        if($ExcludeUsers -ne $null)
        {
            foreach($id in $ExcludeUsers.Split(''))
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

        $obj.DisplayName = $policy.DisplayName
        $obj.State = $policy.State
        $obj.IncludeApplications = $IncludeApplications
        $obj.ExcludeApplications = $ExcludeApplications
        $obj.IncludeUserActions = $IncludeUserActions
        $obj.IncludeProtectionLevels = $IncludeProtectionLevels
        $obj.IncludeUsers = $IncludeUsers
        $obj.ExcludeUsers = $ExcludedUsersName
        $obj.IncludeGroups = $IncludeGroupsName
        $obj.IncludeRoles = $IncludeRoles
        $obj.ExcludeRoles = $ExcludeRoles
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

Get-AzConditionalAccessPolicies 


