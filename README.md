
## Executive Summary
In modern enterprise environments, Security Operations Centers face an overwhelming volume of endpoint telemetry and false-positive security alerts. Analysts routinely spend 70% of their operational cycles manually decoding base64 commands, correlating parent-child process relationships, and cross-referencing benign system binaries. This operational fatigue increases Mean Time to Detect (MTTD), inflates dwell time, and diverts senior talent from proactive threat hunting.

This project delivers an end-to-end detection engineering and autonomous triage system. Integrating kernel-level **Windows Sysmon** telemetry, **Wazuh SIEM/EDR** log correlation, and an asynchronous **FastAPI** reasoning engine, the pipeline automates the initial triage phase of incident response while maintaining a resilient human-in-the-loop validation interface.

---

## Core Objectives
* **Sub-Second Automated Triage:** Ingest process execution telemetry, extract key forensic artifacts, and evaluate threat indicators instantly upon alert triggering.
* **Eliminate Repetitive False Positives:** Implement continuous few-shot environment memory so human-validated benign activity automatically tunes future scoring without vulnerable blanket rule exclusions.
* **Bridge Detection to Action:** Map raw execution anomalies directly to MITRE ATT&CK techniques with clear contextual narratives that accelerate Tier-1 decisions.
* **Zero-Disruption Deployment:** Integrate with open-source SIEM infrastructure without heavy proprietary agent overhead.

---

## Scope & Operational Boundary

### In Scope
* **Endpoint Telemetry Capture:** Windows Sysmon (EID 1: Process Creation) collecting execution trees, command lines, hashes, and token authentications.
* **Custom Detection Engineering:** Wazuh Manager rules mapped to MITRE ATT&CK (e.g., T1059.001 - Command and Scripting Interpreter: PowerShell).
* **Automated Forensic Extraction:** Dynamic extraction of process IDs, parent lineage, base64 payloads, execution paths, and hashes.
* **Adaptive Learning Console:** A responsive analyst command console equipped with granular forensic drawer expansion and one-click feedback mechanisms ("Allowlist" / "Confirm Malicious").

### Out of Scope
* Direct automated host network isolation or process termination (focused on intelligent triage rather than destructive SOAR response).
* Non-Windows endpoint telemetry ingestion.

---

## Strategic Impact & Potential
* **Operational ROI:** Reduces manual triage time per alert from minutes to under 5 seconds, reclaiming significant analyst hours across shifts.
* **Defensible Context:** Equips entry-level analysts with contextual explanations and MITRE mappings, standardizing triage quality across all experience levels.
* **Adaptive Tuning Without Blind Spots:** Traditional SIEM allowlists often rely on static exclusions that attackers can bypass. This pipeline evaluates behavioral patterns against historical analyst decisions, preserving alert integrity while eliminating analyst fatigue.
* **Foundation for Enterprise Scaling:** The lightweight asynchronous microservice architecture can plug into enterprise orchestration platforms (Slack, Jira, Splunk, TheHive) or interface directly with frontier LLM APIs for deeper payload deobfuscation.

---
---

## System Architecture

```text
[Windows 11 Endpoint]
       │
       │ (Sysmon EventChannel: Process Create / EID 1)
       ▼
[Wazuh Manager (v4.x)]
       │
       │ (local_rules.xml: Rule 100100 Level 10 / MITRE T1059.001)
       ▼
[Wazuh Integratord Daemon]
       │
       │ (integrations/custom-ai-triage -> HTTP POST)
       ▼
[FastAPI AI Triage Backend (:5000)]
       ├── Context & IOC Extraction (CommandLine, PID, Parent Process, Hashes)
       ├── SQLite Environment Memory (Few-Shot Pattern Store)
       └── Triage Heuristic / LLM Synthesis Engine
       │
       ▼
[SOC Triage Console (Tailwind CSS)]
       ├── Collapsible Incident Drawers (MITRE Mapping, Verdict, Recommendations)
       └── Continuous Learning Loop ("Allowlist" / "Confirm Malicious")


**Repository Structure**

├── app/
│   ├── server.py              # FastAPI webhook & adaptive memory engine
│   └── templates/
│       └── dashboard.html     # Tailwind SOC incident command console
├── integrations/
│   └── custom-ai-triage       # Wazuh integrator forwarding script
├── rules/
│   └── local_rules.xml        # Custom MITRE ATT&CK detection rules
├── .gitignore
├── requirements.txt
└── README.md

**Setup & Deployment Guide**

Windows Endpoint Configuration
Install Sysmon with SwiftOnSecurity baseline:


Invoke-WebRequest -Uri "[https://live.sysinternals.com/Sysmon64.exe](https://live.sysinternals.com/Sysmon64.exe)" -OutFile "$env:TEMP\Sysmon64.exe"
Invoke-WebRequest -Uri "[https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml)" -OutFile "$env:TEMP\sysmonconfig.xml"
& "$env:TEMP\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"


**Configure Wazuh Agent Ingestion:**

Append the Microsoft-Windows-Sysmon/Operational event channel into C:\Program Files (x86)\ossec-agent\ossec.conf:

<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

**Restart Agent Service:**

Restart-Service -Name WazuhSvc

**Wazuh Manager Configuration**

Deploy Detection Rules:
Copy rules/local_rules.xml to /var/ossec/etc/rules/local_rules.xml on the Wazuh server:

<rule id="100100" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image">powershell.exe$|pwsh.exe$</field>
  <field name="win.eventdata.commandLine">-enc|-encodedcommand|downloadstring|iex|invoke-expression</field>
  <description>Suspicious PowerShell execution detected (Obfuscation / Download Cradle)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>

**Deploy Integrator Dispatcher:**

Place integrations/custom-ai-triage in /var/ossec/integrations/custom-ai-triage:

chmod 750 /var/ossec/integrations/custom-ai-triage
chown root:wazuh /var/ossec/integrations/custom-ai-triage


**Configure Alert Forwarding:**

In /var/ossec/etc/ossec.conf, add inside <ossec_config>:

<integration>
  <name>custom-ai-triage</name>
  <hook_url>[http://127.0.0.1:5000/webhook/wazuh](http://127.0.0.1:5000/webhook/wazuh)</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>

**Restart Wazuh Manager:**

systemctl restart wazuh-manager

**AI Triage Console Deployment**

Set Up Python Environment:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

**Launch Console Server:**

uvicorn app.server:app --host 0.0.0.0 --port 5000 --reload

----------------------------------

Open http://<MANAGER_IP>:5000 to access the SOC command console.

**Verification & Testing**

**Verification & Testing**

Trigger High-Severity Alert on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression 'Write-Output Testing-SOC-Pipeline'"
------------------------------------------

**Incident Triage & Analysis:**

The event flows through Sysmon -> Wazuh Manager -> wazuh-integratord -> FastAPI Webhook.

Click anywhere on the incident row in the console to expand the drawer and inspect:

AI Triage Rationale & Confidence Score.

MITRE ATT&CK Tactics and Techniques.

Forensic Artifacts: User Account, PID, Parent Image, Parent Command Line, and SHA256 hashes.

**Continuous Learning Loop:**

Click Allowlist to train the environment memory store.

Subsequent executions of the pattern are automatically recognized as False Positive (Allowlisted) with 99% confidence.
'''

![SOC Dashboard Overview](https://github.com/user-attachments/assets/ce5ebc9f-fca8-4f94-a3f0-5d29ae896068)

![Incident Forensics & IOC Drawer](https://github.com/user-attachments/assets/cf48ab45-aa86-4e28-baae-10813d412065)
