# Microsoft Defender XDR Incident Response Lab

## 📌 Overview
Hands-on **incident response** in Microsoft Defender XDR: detect a simulated attack, investigate with KQL hunting, collect forensics, and contain by isolating the endpoint. Written as a SOC case-study so reviewers can see real workflows, not just a badge.

**Credential:** [Microsoft Applied Skills – Defend against cyberthreats with Microsoft Defender XDR](<https://learn.microsoft.com/en-gb/users/joelamoaniokanta-1857/credentials/5f48991d010976ca?ref=https%3A%2F%2Fwww.linkedin.com%2F>)

---

## Contents
- [Objectives](#objectives)  
- [Lab Architecture](#lab-architecture)  
- [Tools Used](#tools-used)  
- [What I Configured](#what-i-configured)  
- [Investigation & Hunting](#investigation--hunting)  
- [Forensics & Containment](#forensics--containment)  
- [Findings](#findings)  
- [Lessons Learned](#lessons-learned)  
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Objectives
- Configure M365 Defender controls (Safe Links, Safe Attachments, anti-phishing).
- Onboard an endpoint and group it for targeted protection.
- Hunt with **KQL** to identify suspicious PowerShell activity and malicious IPs.
- Collect a **forensic investigation package**.
- **Isolate** the compromised device to stop lateral movement.

---

## Lab Architecture
- **Client1** — analyst workstation (portal access).  
- **Client2** — simulated compromised Windows endpoint.  
- **Defender XDR portal** — investigation, hunting, and response.

---

## Tools Used
- Microsoft Defender XDR (Microsoft 365 Defender)
- Advanced Hunting (KQL)
- Device groups (automation levels)
- Indicators (IP)
- Live Response / Investigation package
- Device isolation

---

## What I Configured
- **Device group**: `Group1` (Windows 10/11), **Full** automatic remediation, highest priority.  
- **Security policies**: Safe Links, Safe Attachments, anti-phishing (standard hardening for mail/endpoint).  
- **Custom indicator**: `Indicator1`  
  - Type: **IP address** → `2.100.20.102` (malicious)  
  - Action: **Block execution** | Severity: **High** | Category: **Execution**  
  - Scope: **Group1**
- **Detection rule**: `SuspiciousPowershell` (Advanced Hunting → Saved as scheduled rule, hourly)  
  - **Scope:** All devices  
  - **Actions:**  
    - Collect investigation package  
    - Mark user as compromised → **InitiatingProcessAccountObjectId**

---

## Investigation & Hunting
**Timeline highlights (Client2):**
- *Suspicious process injection*: `powershell.exe` injecting into `notepad.exe` (CreateRemoteThread).
- Outbound connection to **malicious IP** `2.100.20.102`.

**KQL queries used**
```kusto
// Suspicious PowerShell usage (download behaviour)
DeviceProcessEvents
| where FileName == "powershell.exe"

// PowerShell initiating external connections
DeviceNetworkEvents
| where RemoteIP == "2.100.20.102"

// Variant focused on process injection target
DeviceProcessEvents
| where FileName == "notepad.exe"
```
