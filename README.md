# Azure Detection Lab – Full Documentation

This lab simulates an enterprise Windows environment inside Azure to practice Active Directory management, SIEM monitoring with Splunk, offensive security techniques using Kali Linux, and adversary simulation with Atomic Red Team. The project focuses on generating security telemetry, analyzing malicious activity, and developing SOC-style remediation strategies.

---

# 1. Environment Setup

## Resource Group
- **AD-Lab**

## Virtual Networks

| VNET           | Address Space        | Purpose                                   |
|----------------|----------------------|-------------------------------------------|
| **AD-Lab-VNET** | `192.168.100.0/24`   | Domain Controller, Client, Splunk         |
| **Attack-VNET** | `10.0.10.0/24`       | Kali attack machine                       |

**VNET Peering:** Enabled between both networks to allow controlled attack simulation.

---

# 2. Virtual Machines

## AD-Lab-VNET
- **ADDC-1** – Windows Server 2022 (Domain Controller)  
- **Client-1** – Windows 11 Pro (Domain-joined endpoint)  
- **Splunk** – Ubuntu 24.04 LTS (Splunk Enterprise server)

## Attack-VNET
- **Kali** – Kali Linux 2025.3 (Attack platform)
![imagealt](https://github.com/pwrod/Azure-Detection-Lab/blob/main/images/VMs.png?raw=true)

---

# 3. Active Directory Configuration

- Promoted **ADDC-1** to a Domain Controller.  
- Created a new **Organizational Unit (OU)**.  
- Added **two new AD user accounts**.  
- Joined **Client-1** to the domain.

---

# 4. Logging & Monitoring Setup

## Client-1 (Windows Target)
- Installed and configured **Sysmon** for enhanced endpoint telemetry.  
- Enabled RDP access for test users.  
- Disabled Windows Defender (for lab visibility purposes).

## Splunk Server
- Installed **Splunk Enterprise** on Ubuntu.  
- Created a dedicated **index** for Client-1 logs.  
- Installed **Splunk Universal Forwarder** on Client-1.  
- Configured forwarding for:
  - Windows Security Logs  
  - Sysmon Logs  
  - System Logs  

---

# 5. Attack Simulation – Hydra RDP Brute Force

Performed an RDP brute-force attack from the **Kali machine**:

- Created a password list containing **10 incorrect** passwords + **1 correct** password.  
- Used **Hydra** to attempt RDP authentication on Client-1.

### Splunk Observed Events
- **4625** – Failed logon attempts  
- **4624** – Successful logon
![imagealt](https://github.com/pwrod/Azure-Detection-Lab/blob/main/images/Hydra%20splunk%20logs.png?raw=true)

---

# 6. Atomic Red Team – Adversary Emulation

Installed **Atomic Red Team** on Client-1 and executed tests mapped to MITRE ATT&CK.

---

## Test 1: T1078.001 – Valid Accounts (Local Account Abuse)

Simulates enabling/modifying the Guest account and granting RDP & admin privileges.

**Expected Logs:**  
`4798, 4722, 4738, 4724, 4732`
![imagealt](https://github.com/pwrod/Azure-Detection-Lab/blob/main/images/Atomic%20T1078%20logs.png?raw=true)
---

## Test 2: T1059.001 – PowerShell Execution

Simulates malicious PowerShell scripting activity.

**Expected Logs:**  
`4648` (plus Sysmon process creation logs)
![altimage](https://github.com/pwrod/Azure-Detection-Lab/blob/main/images/Atomic%20logs%20T1059.png?raw=true)
---

## Test 3: T1562.002 – Disable Windows Event Logging

Simulates tampering with the Windows Event Logging service.

**Expected Logs:**  
`1100`
![imagealt]()
---

# 7. Skills Learned

### Active Directory & Infrastructure
- Designed and deployed a multi-VM Active Directory environment in Azure.  
- Configured Organizational Units, domain users, and domain-joined machines.  
- Implemented VNET peering for segmented but accessible network zones.

### Endpoint Logging & Monitoring
- Installed Sysmon for enhanced process and network telemetry.  
- Configured Splunk Universal Forwarder and customized log ingestion paths.  
- Analyzed high-value Windows Event IDs related to authentication, PowerShell, and account abuse.

### Offensive Security & Adversary Simulation
- Executed RDP brute-force attacks using Hydra.  
- Performed MITRE ATT&CK Atomic Red Team tests to simulate real-world attacker behavior.  
- Generated, collected, and analyzed malicious security telemetry.

### Security Operations & Detection Engineering
- Investigated SIEM logs to correlate attacker movement and activity.  
- Identified critical event codes for brute force, privilege escalation, and logging evasion.  
- Developed mitigation strategies and improved detection capability.

---

# 8. Remediation Strategies

Below is a professional breakdown of recommended remediations for each attack technique executed in this lab.

---

## RDP Brute-Force Attack (Hydra)

### Risks
Allows attackers to guess valid credentials and gain interactive access.

### Remediation
- Enable **Account Lockout Policies** (e.g., 5 failed attempts = lock for 15 minutes).  
- Enforce **MFA for RDP** to eliminate password-only logins.  
- Implement **Network Level Authentication (NLA)**.  
- Restrict RDP to **VPN-only** or **allowlist IPs**.  
- Disable RDP for unnecessary accounts.  
- Enforce strong password complexity and length requirements.

---

## T1078.001 – Valid Accounts Abuse

### Risks
Adversaries may enable dormant accounts or elevate privileges.

### Remediation
- Keep Guest and unused accounts **disabled** by policy.  
- Use **least privilege** and restrict local administrator group modification.  
- Set SIEM alerts for events: `4722, 4738, 4724, 4732, 4798`.  
- Implement **Privileged Access Management (PAM)** and Just-In-Time access.  
- Apply GPO settings to prevent unauthorized privilege changes.

---

## T1059.001 – PowerShell Execution

### Risks
PowerShell is a powerful native tool often abused for malware execution, credential theft, and lateral movement.

### Remediation
- Enable **PowerShell Logging** (Module, Script Block, and Transcription).  
- Enforce **Constrained Language Mode** for non-admin users.  
- Implement **AppLocker or WDAC** to restrict PowerShell execution paths.  
- Monitor for suspicious patterns (encoded commands, remote downloads, startup folder execution).  

---

## T1562.002 – Disable Windows Event Logging

### Risks
Attackers may attempt to blind defenders by stopping logs or clearing them.

### Remediation
- Alert on `1100` (Event Log Service Shutdown) and `1102` (Log Cleared).  
- Forward logs to Splunk/EDR in real time to retain off-host logs.  
- Restrict Event Log service permissions to **SYSTEM only**.  
- Use Sysmon as a secondary log source for redundancy.  
- Implement endpoint detection & response (EDR) tools capable of detecting log tampering.

---

# 9. Conclusion

This lab demonstrates how a SOC analyst can detect, analyze, and respond to a variety of real-world attack scenarios. The combination of AD, Sysmon, Splunk, Hydra, and Atomic Red Team provides hands-on experience in:

- Detection engineering  
- Log correlation  
- Threat emulation  
- Incident investigation  
- Preventative hardening  

---

