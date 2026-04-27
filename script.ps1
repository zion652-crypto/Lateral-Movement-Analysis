# Filter for Successful Logons (4624) and extract Service Logons (Type 5)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | foreach {
    $xml = [xml]$_.ToXml()
    $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "LogonType"}
    $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"}
    
    if ($logonType.'#text' -eq "5") {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = $user.'#text'
            Type = $logonType.'#text'
        }
    }
} | Select-Object -Unique User, Time
