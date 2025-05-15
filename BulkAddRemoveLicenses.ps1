Connect-MsolService
Connect-MgGraph -Scopes User.ReadWrite.All, Organization.Read.All
Get-MgUser


$r1 = Get-MgSubscribedSku -All | ? SkuPartNumber -like "*E1_(no*" 
$r1.SkuId | clip
$r2 = Get-MgSubscribedSku -All | ? SkuPartNumber -like "*Enterprise_New*" 


$E1 = ipcsv 'C:\Users\e060080\OneDrive - RSM\Client_Folders\ProducersMidstream\E1NoTeams.csv'
$e1Sku = Get-MgSubscribedSku -All | ? SkuPartNumber -like "*STANDARDPACK*" 
foreach($user in $E1)
{
    #add new
    #Set-MgUserLicense -UserId $user.UserPrincipalName -AddLicenses @{SkuId = $e1Sku.SkuId} -RemoveLicenses @()

    #remove licenses
    Set-MgUserLicense -UserId $user.UserPrincipalName -RemoveLicenses @("f8ced641-8e17-4dc5-b014-f5a2d53f6ac8") -AddLicenses @{}
    Set-MgUserLicense -UserId $user.UserPrincipalName -RemoveLicenses @("7e31c0d9-9551-471d-836f-32ee72be4a01") -AddLicenses @{}
}


$E3 = ipcsv 'C:\Users\e060080\OneDrive - RSM\Client_Folders\ProducersMidstream\E3NoTeams.csv'
$e3Sku = Get-MgSubscribedSku -All | ? SkuPartNumber -like "*SPE_E3*" 
foreach($user in $E3)
{
    #Set-MgUserLicense -UserId $user.UserPrincipalName -AddLicenses @{SkuId = $e3Sku.SkuId} -RemoveLicenses @()
    Set-MgUserLicense -UserId $user.UserPrincipalName -RemoveLicenses @("dcf0408c-aaec-446c-afd4-43e3683943ea") -AddLicenses @{}
    Set-MgUserLicense -UserId $user.UserPrincipalName -RemoveLicenses @("7e31c0d9-9551-471d-836f-32ee72be4a01") -AddLicenses @{}

}


$E5 = ipcsv 'C:\Users\e060080\OneDrive - RSM\Client_Folders\ProducersMidstream\E5NoTeams.csv'
$e5Sku = Get-MgSubscribedSku -All | ? SkuPartNumber -like "*SPE_E5*" 
foreach($user in $E5)
{
    #Set-MgUserLicense -UserId $user.UserPrincipalName -AddLicenses @{SkuId = $e5Sku.SkuId} -RemoveLicenses @()

    Set-MgUserLicense -UserId $user.UserPrincipalName -RemoveLicenses @("18a4bd3f-0b5b-4887-b04f-61dd0ee15f5e") -AddLicenses @{}
    Set-MgUserLicense -UserId $user.UserPrincipalName -RemoveLicenses @("7e31c0d9-9551-471d-836f-32ee72be4a01") -AddLicenses @{}

}