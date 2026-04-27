
---

# Forensic Investigation: Lateral Movement & Service Persistence

## 1. Objective
The goal of this investigation was to detect **Lateral Movement** within a Windows Domain environment (`soprano.local`). Specifically, I targeted unauthorized **Service Account** activity on the Domain Controller (**DC.soprano.local**) to identify how an attacker was maintaining persistence.

## 2. Technical Context
In a Windows environment, attackers often "pivot" to a Domain Controller and install a malicious service to run their code with high privileges.
* **Target System:** DC.soprano.local
* **Primary Indicator:** Windows Event ID **4624** (Successful Logon)
* **Sub-Indicator:** **Logon Type 5** (Service Logon)

### Why Logon Type 5?
Most users log in via Type 2 (Keyboard) or Type 3 (Network shares). Type 5 occurs when the **Service Control Manager (SCM)** starts a service. If a human user account (e.g., `tony.soprano`) is found with a Type 5 logon, it indicates they have installed a service to run as themselves—a classic "persistence" red flag.

## 3. The Script: PowerShell Log Parser
Because the standard Event Viewer GUI was laggier than the network and frequently threw XML query errors, I developed a PowerShell script to bypass the UI and extract the "Signal from the Noise."

### How it works:
The script targets the `Security` log, filters for successful logins (4624), and converts the raw data into an XML object to access the nested `LogonType` and `TargetUserName` fields.

```powershell
# PowerShell script to find unique Service Logons (Type 5)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | foreach {
    $xml = [xml]$_.ToXml()
    $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "LogonType"}
    $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"}
    
    # Filter for Type 5 (Service) only
    if ($logonType.'#text' -eq "5") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser  = $user.'#text'
            LogonType   = $logonType.'#text'
            Computer    = $_.MachineName
        }
    }
} | Select-Object -Unique TargetUser, TimeCreated
```

## 4. Example Output & Analysis
| TimeCreated | TargetUser | Computer | Interpretation |
| :--- | :--- | :--- | :--- |
| 5:21 PM | SYSTEM | SOPRANOS-DC | **Normal:** System process heartbeat. |
| 5:23 PM | NETWORK SERVICE | SOPRANOS-DC | **Normal:** Standard network service. |
| **5:35 PM** | **tony.soprano** | **SOPRANOS-DC** | **CRITICAL:** Human user running a service. |

## 5. Summary of Findings
By bypassing the corrupted Event Viewer filters, I successfully identified the **TargetUserName** responsible for the lateral movement. The investigation proved that while machine accounts like `SOPRANOS-DC$` log in as `SYSTEM` regularly, any deviation—such as a standard user account appearing as a Service Logon—is an immediate indicator of a hijacked account or a malicious service installation.

---

