# Microsoft Defender XDR Incident Response Lab

## 📌 Overview
This project demonstrates hands-on experience in **incident response and threat detection** using Microsoft Defender XDR.  
The lab simulated a multi-stage attack across email and endpoint environments, requiring investigation, hunting, forensic collection, and device isolation.  
The goal was to build practical SOC workflows that mirror real-world security operations centre (SOC) processes.

Credential: [Microsoft Applied Skills – Defend against cyberthreats with Microsoft Defender XDR](<insert-your-credential-link-here>)

---

## 🎯 Objectives
- Configure security controls in Microsoft 365 Defender (Safe Links, Safe Attachments, anti-phishing).  
- Investigate simulated malicious activity across endpoints and email.  
- Use **advanced hunting queries (KQL)** to identify suspicious events.  
- Collect forensic evidence from a compromised endpoint.  
- Contain the incident by isolating the affected device.  

---

## 🏗️ Lab Architecture
- **Client1** – Management workstation for analysis.  
- **Client2** – Simulated compromised endpoint.  
- **Microsoft Defender XDR portal** – Central platform for investigation, detection, and response.  


---

## 🛠️ Tools Used
- Microsoft Defender XDR (formerly Microsoft 365 Defender)  
- Advanced Hunting (KQL)  
- Device groups and policy assignment  
- Forensic package collection  
- Device isolation  

---

## 🔍 Steps Taken
1. **Configured security policies**  
   - Set up anti-phishing, Safe Links, and Safe Attachments policies.  
   - Assigned policies to the `Group1` device group.  

2. **Investigated alerts**  
   - Analysed incidents involving suspicious email attachments and endpoint behaviour.  
   - Correlated alerts across different entities (users, endpoints).  

3. **Advanced hunting with KQL**  
   - Queried suspicious PowerShell usage:  
     ```kql
     DeviceProcessEvents
     | where FileName == "powershell.exe"
     | where ProcessCommandLine contains "Invoke-WebRequest"
     ```  
   - Queried potentially malicious IP connections:  
     ```kql
     DeviceNetworkEvents
     | where RemoteIPCountry != "United Kingdom"
     | where InitiatingProcessFileName == "powershell.exe"
     ```  

4. **Collected forensic evidence**  
   - Triggered **Investigation Package Collection** from Client2.  
   - Downloaded and analysed `Forensics Collection Summary.csv` to review processes and persistence.  

5. **Isolated compromised endpoint**  
   - Applied **full isolation** on Client2 to prevent lateral movement while maintaining Defender cloud communication.  

---

## 📊 Findings
- Successful detection of suspicious PowerShell execution used for downloading payloads.  
- Identified connections to malicious external IP addresses.  
- Forensic package confirmed suspicious persistence mechanisms on Client2.  
- Device isolation prevented further spread, demonstrating containment procedures.  

---

## 🧠 Lessons Learned
- Device groups and policy assignment are essential for targeted protection.  
- KQL hunting enables proactive detection of activity not covered by default alerts.  
- Forensic package collection is invaluable for validating compromise beyond alerts.  
- Incident response requires both **automated alerts** and **manual analyst hunting**.  

---

## 🚀 Outcomes
- Built practical experience in Microsoft Defender XDR’s **investigate → hunt → collect → contain** workflow.  
- Mapped lab detections to the **MITRE ATT&CK** framework:  
  - **T1059** – Command-Line and Scripting (PowerShell)  
  - **T1071** – Application Layer Protocol (malicious HTTP requests)  
  - **T1078** – Valid Accounts (login attempts)  

---

## 🔗 Credential
- [Microsoft Applied Skills – Defend against cyberthreats with Microsoft Defender XDR](<insert-your-credential-link-here>)  

---
