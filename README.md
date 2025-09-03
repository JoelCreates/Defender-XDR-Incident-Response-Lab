# Microsoft Defender XDR Incident Response Lab

## 📌 Overview
This repository documents my hands-on **incident response** exercise using Microsoft Defender XDR.  
The lab simulated a phishing attack that resulted in malicious **PowerShell execution**, **process injection**, and **command-and-control (C2) communication**.  

I approached the lab as if it were a **SOC analyst case study**, documenting the **attack lifecycle, defensive configurations, KQL hunting, forensic collection, and containment measures**.  

**Credential Verification:**  
[Microsoft Applied Skills – Defend against cyberthreats with Microsoft Defender XDR](<https://learn.microsoft.com/en-gb/users/joelamoaniokanta-1857/credentials/5f48991d010976ca?ref=https%3A%2F%2Fwww.linkedin.com%2F>)

---

## Contents
- [Scenario](#scenario)  
- [Objectives](#objectives)  
- [Lab Architecture](#lab-architecture)  
- [Tools Used](#tools-used)  
- [Configurations](#configurations)  
- [Incident Timeline](#incident-timeline)  
- [Hunting Queries](#hunting-queries)  
- [Forensics Collection](#forensics-collection)  
- [Response & Containment](#response--containment)  
- [Findings](#findings)  
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)  
- [Lessons Learned](#lessons-learned)  
- [Reflection](#reflection)  
- [Limitations](#limitations)

---

## Scenario
The simulated incident began with a **phishing campaign** delivering a malicious attachment. When executed, it spawned **PowerShell** commands to download additional payloads.  
The attacker attempted to **inject PowerShell into `notepad.exe`** using `CreateRemoteThread`, followed by an outbound connection to a known **malicious IP** (`2.100.20.102`) acting as a command-and-control server.  

The lab required me to:
1. Detect and validate the malicious activity in **Microsoft Defender XDR**.  
2. Hunt for additional indicators with **KQL queries**.  
3. Collect **forensic evidence** from the compromised endpoint.  
4. Apply **remediation actions** to prevent reoccurrence.  
5. **Isolate** the endpoint to stop further spread.  

---

## Objectives
- Configure Microsoft 365 Defender policies: **Safe Links, Safe Attachments, anti-phishing**.  
- Create and prioritise **device groups** with automation settings.  
- Define **indicators of compromise (IoCs)** for malicious IPs.  
- Use **Advanced Hunting with KQL** to expand detection scope.  
- Collect **forensic investigation packages** for offline review.  
- Apply **containment actions** (device isolation, user compromise marking).  
- Map attacker behaviours to the **MITRE ATT&CK framework**.  

---

## Lab Architecture
- **Client1 (Analyst Workstation)** → Used to access Defender XDR portal and perform hunting.  
- **Client2 (Victim Endpoint)** → Windows machine simulating compromise.  
- **Microsoft Defender XDR Portal** → Central investigation, hunting, and response platform.  

---

## Tools Used
- **Microsoft Defender XDR (Microsoft 365 Defender)**  
- **Advanced Hunting (KQL queries)**  
- **Device groups with automation levels**  
- **Custom Indicators of Compromise (IP, domains, file hashes)**  
- **Detection rules** (scheduled queries triggering responses)  
- **Live Response / Investigation packages**  
- **Device isolation features**  

---

## Configurations
### Device Group
- `Group1` (Windows 10/11 endpoints)  
- Automation level: **Full remediation**  
- Priority: **Highest**  

### Security Policies
- **Safe Links** – Prevented users from opening malicious URLs.  
- **Safe Attachments** – Sandboxed attachments before delivery.  
- **Anti-Phishing** – Applied advanced impersonation and spoof detection.  

### Custom Indicator
- Name: `Indicator1`  
- Type: **IP address**  
- Value: `2.100.20.102`  
- Action: **Block execution**  
- Severity: **High**  
- Category: **Execution**  
- Scope: **Group1**  

### Detection Rule
- Name: `SuspiciousPowershell`  
- Source: **Advanced Hunting query saved as scheduled rule (hourly)**  
- Scope: **All devices**  
- Actions:  
  - Collect **investigation package**  
  - Mark associated user as **compromised**  

---

## Incident Timeline
**Chronological flow of the attack and response (Client2):**

- **09:42** — Malicious attachment executed.  
- **09:45** — `powershell.exe` launched with obfuscated arguments.  
- **09:47** — PowerShell injected into `notepad.exe` via `CreateRemoteThread`.  
- **09:49** — Outbound network traffic observed to `2.100.20.102`.  
- **09:52** — Defender triggered alert for suspicious PowerShell behaviour.  
- **09:55** — Analyst (me) confirmed malicious execution via KQL.  
- **10:00** — Custom indicator added for IP address.  
- **10:02** — Detection rule created to hunt similar patterns.  
- **10:05** — Forensic package collection triggered.  
- **10:07** — Device isolated from network.  

---

## Hunting Queries
To validate and expand detection scope, I ran the following **KQL queries**:

```kusto
// Detect suspicious PowerShell executions
DeviceProcessEvents
| where FileName == "powershell.exe"

// Identify outbound connections to known malicious IP
DeviceNetworkEvents
| where RemoteIP == "2.100.20.102"
```
