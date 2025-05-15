$Domain = Read-Host -Prompt 'Enter Hostname'
#$Domain = 'fnbgiddings.com'


$dkim1 = Resolve-DnsName -Type CNAME -Name selector1._domainkey.$Domain | select -ExpandProperty NameHost
$dkim2 = Resolve-DnsName -Type CNAME -Name selector2._domainkey.$Domain | select -ExpandProperty NameHost
$dmarc = Resolve-DnsName -Type TXT -Name _dmarc.$Domain | select -ExpandProperty strings
$spf = Resolve-DnsName -Type TXT -Name $Domain | Where-Object Strings -like "*spf*" | Select -ExpandProperty Strings


[System.Collections.ArrayList]$ArrayList = @() 

$obj = "" | select DnsRecord,Value
$obj.DnsRecord = 'DKIM'
$obj.Value = $dkim1
$ArrayList += $obj
$obj = $null

$obj = "" | select DnsRecord,Value
$obj.DnsRecord = 'DKIM'
$obj.Value = $dkim2
$ArrayList += $obj
$obj = $null

$obj = "" | select DnsRecord,Value
$obj.DnsRecord = 'DMARC'
$obj.Value = $dmarc
$ArrayList += $obj
$obj = $null

$obj = "" | select DnsRecord,Value
$obj.DnsRecord = 'SPF'
$obj.Value = $spf
$ArrayList += $obj
$obj = $null


$ArrayList



